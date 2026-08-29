package identity

import (
	"context"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

func TestServiceRegisterPersistsAuditActorInOneTransaction(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(NewRepository(sqlDB), database.NewTransactor(sqlDB), config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	service.hasher, _ = NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO users (id, username, name, email, phone, status, failed_login_count, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")).WithArgs(sqlmock.AnyArg(), "alice", "Alice", "alice@example.com", "", StatusActive, 0, int64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), "admin-1", "admin-1").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO credentials (id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "password", sqlmock.AnyArg(), StatusActive, int64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), "admin-1", "admin-1").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)")).WithArgs(sqlmock.AnyArg(), "platform.identity.user.created.v1", sqlmock.AnyArg(), sqlmock.AnyArg(), int64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), "admin-1", "admin-1").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	ctx := principal.WithContext(context.Background(), principal.Principal{ID: "admin-1", Type: principal.TypeUser})
	created, err := service.Register(ctx, "Alice", "Alice", "ALICE@example.com", "", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if created.Username != "alice" || created.CreatedBy != "admin-1" {
		t.Fatalf("created = %#v", created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceIssuesTokenForConfiguredServiceAudiences(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	audiences := []string{"identity-service", "tenant-service", "authorization-service"}
	service, err := NewService(NewRepository(sqlx.NewDb(db, "sqlmock")), &database.Transactor{}, config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "identity-service", Audiences: audiences, Secret: "01234567890123456789012345678901", TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := service.issuer.Issue("user-1", "user", "session-1", "tenant-1", "membership-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := service.issuer.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, audience := range audiences {
		if !slices.Contains(claims.Audience, audience) {
			t.Fatalf("token audiences %v do not contain %q", claims.Audience, audience)
		}
	}
}

func TestServiceLoginRecordsFailureBeforeRejectingCredentials(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(NewRepository(sqlDB), database.NewTransactor(sqlDB), config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	service.hasher, _ = NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	hash, err := service.hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT "+userColumns+" FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)")).WithArgs("alice", "alice").WillReturnRows(sqlmock.NewRows([]string{"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until", "version", "created_at", "updated_at", "created_by", "updated_by"}).AddRow("u1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 1, now, now, "admin", "admin"))
	mock.ExpectQuery("SELECT id, user_id, type, secret_hash").WithArgs("u1").WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "type", "secret_hash", "status", "version", "created_at", "updated_at", "created_by", "updated_by"}).AddRow("c1", "u1", "password", hash, StatusActive, 1, now, now, "admin", "admin"))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET failed_login_count = failed_login_count + 1, locked_until = CASE WHEN failed_login_count + 1 >= ? THEN ? ELSE locked_until END, version = version + 1, updated_at = ?, updated_by = 'identity:login' WHERE id = ?")).WithArgs(loginFailureThreshold, sqlmock.AnyArg(), sqlmock.AnyArg(), "u1").WillReturnResult(sqlmock.NewResult(0, 1))
	if _, err := service.Login(t.Context(), "alice", "wrong password value"); err == nil {
		t.Fatal("Login() error = nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
