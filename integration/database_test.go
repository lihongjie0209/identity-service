//go:build integration

package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lihongjie0209/identity-service/internal/config"
	appdb "github.com/lihongjie0209/identity-service/internal/database"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
	"github.com/lihongjie0209/identity-service/internal/migration"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestRepositoryAndMigrations(t *testing.T) {
	for _, databaseType := range []string{"postgres", "mysql"} {
		t.Run(databaseType, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			dsn, migrationURL := startDatabase(t, ctx, databaseType)
			migrationPath, err := filepath.Abs(filepath.Join("..", "migrations", databaseType))
			if err != nil {
				t.Fatal(err)
			}
			schema := ""
			if databaseType == "postgres" {
				schema = "integration_postgres"
			}
			migrationCfg := config.Migration{Path: migrationPath, DatabaseURL: migrationURL, Table: "integration_" + databaseType + "_schema_migrations", Schema: schema, CreateSchema: schema != ""}
			migrationErrors := make(chan error, 3)
			var migrations sync.WaitGroup
			for range 3 {
				migrations.Add(1)
				go func() {
					defer migrations.Done()
					migrationErrors <- migration.Run(migrationCfg, "up", 0)
				}()
			}
			migrations.Wait()
			close(migrationErrors)
			for err := range migrationErrors {
				if err != nil {
					t.Fatalf("concurrent migration up: %v", err)
				}
			}

			db, err := appdb.Open(ctx, config.Database{Type: databaseType, DSN: dsn, Schema: schema, MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute, PingTimeout: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			repository := identitydomain.NewRepository(db)
			transactor := appdb.NewTransactor(db)
			service, err := identitydomain.NewService(repository, transactor, config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "integration", Secret: "01234567890123456789012345678901", KeyID: "integration-key", TTL: time.Hour}})
			if err != nil {
				t.Fatal(err)
			}
			adminCtx := principal.WithContext(ctx, principal.Principal{ID: "admin-1", Type: principal.TypeUser})
			created, err := service.Register(adminCtx, "alice_"+databaseType, "Alice", "alice-"+databaseType+"@example.com", "", "correct horse battery staple")
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			tokens, err := service.Login(
				ctx,
				created.Username,
				"correct horse battery staple",
				identitydomain.SessionClient{IP: "127.0.0.1", UserAgent: "identity-integration-test"},
			)
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			rotated, err := service.Refresh(ctx, tokens.Tokens.RefreshToken)
			if err != nil || rotated.RefreshToken == tokens.Tokens.RefreshToken {
				t.Fatalf("refresh=%+v err=%v", rotated, err)
			}
			sessionPage, err := service.ListSessions(ctx, created.ID, "", "active", 1, 20)
			if err != nil || sessionPage.Total != 1 || len(sessionPage.Items) != 1 {
				t.Fatalf("session page=%+v err=%v", sessionPage, err)
			}
			revokedSession, err := service.RevokeSessionByID(
				adminCtx,
				sessionPage.Items[0].ID,
				"integration security test",
				sessionPage.Items[0].Version,
			)
			if err != nil || revokedSession.RevokedAt == nil || revokedSession.Version != sessionPage.Items[0].Version+1 {
				t.Fatalf("revoked session=%+v err=%v", revokedSession, err)
			}
			account, secret, err := service.CreateServiceAccount(adminCtx, "reporting", []string{"reporting-api"})
			if err != nil || secret == "" {
				t.Fatalf("service account=%+v err=%v", account, err)
			}
			accountPage, err := service.ListServiceAccounts(ctx, "report", identitydomain.StatusActive, 1, 20)
			if err != nil || accountPage.Total != 1 || len(accountPage.Items) != 1 || accountPage.Items[0].ID != account.ID {
				t.Fatalf("service account page=%+v err=%v", accountPage, err)
			}
			if len(accountPage.Items[0].Audiences) != 1 || accountPage.Items[0].Audiences[0] != "reporting-api" {
				t.Fatalf("service account audiences=%v", accountPage.Items[0].Audiences)
			}
			serviceToken, _, err := service.ServiceAccountToken(ctx, account.ClientID, secret)
			if err != nil || serviceToken == "" {
				t.Fatalf("service token error=%v", err)
			}
			var outboxCount int
			if err := db.GetContext(ctx, &outboxCount, "SELECT COUNT(*) FROM outbox_events"); err != nil || outboxCount != 3 {
				t.Fatalf("outbox count=%d err=%v", outboxCount, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			if err := migration.Run(migrationCfg, "down", 0); err != nil {
				t.Fatalf("migration down: %v", err)
			}
		})
	}
}

func startDatabase(t *testing.T, ctx context.Context, databaseType string) (string, string) {
	t.Helper()
	switch databaseType {
	case "postgres":
		container, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("app"), postgres.WithUsername("app"), postgres.WithPassword("app"), postgres.BasicWaitStrategies(), postgres.WithSQLDriver("pgx"))
		if err != nil {
			t.Fatal(err)
		}
		testcontainers.CleanupContainer(t, container)
		dsn, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		return dsn, dsn
	case "mysql":
		container, err := mysql.Run(ctx, "mysql:8.4", mysql.WithDatabase("app"), mysql.WithUsername("app"), mysql.WithPassword("app"))
		if err != nil {
			t.Fatal(err)
		}
		testcontainers.CleanupContainer(t, container)
		dsn, err := container.ConnectionString(ctx, "parseTime=true")
		if err != nil {
			t.Fatal(err)
		}
		migrationDSN, err := container.ConnectionString(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return dsn, "mysql://" + migrationDSN
	default:
		t.Fatal(fmt.Errorf("unsupported database %q", databaseType))
		return "", ""
	}
}
