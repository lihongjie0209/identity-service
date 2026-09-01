//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/lihongjie0209/identity-service/internal/app"
	"github.com/lihongjie0209/identity-service/internal/config"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	rediscontainer "github.com/testcontainers/testcontainers-go/modules/redis"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
)

func TestHTTPAndGRPCEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	postgresContainer, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("app"), postgres.WithUsername("app"), postgres.WithPassword("app"), postgres.BasicWaitStrategies(), postgres.WithSQLDriver("pgx"))
	if err != nil {
		t.Fatal(err)
	}
	testcontainers.CleanupContainer(t, postgresContainer)
	dsn, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	migrationPath, _ := filepath.Abs(filepath.Join("..", "migrations", "postgres"))

	redisContainer, err := rediscontainer.Run(ctx, "redis:7.4-alpine")
	if err != nil {
		t.Fatal(err)
	}
	testcontainers.CleanupContainer(t, redisContainer)
	redisURL, err := redisContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}
	redisOptions, err := goredis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}

	httpAddress := freeAddress(t)
	grpcAddress := freeAddress(t)
	const secret = "01234567890123456789012345678901"
	cfg := config.Config{
		Runtime:       config.Runtime{ActiveProfile: "integration"},
		App:           config.App{Name: "integration", Env: "integration", ShutdownTimeout: 10 * time.Second},
		HTTP:          config.HTTP{Address: httpAddress, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, RequestTimeout: 5 * time.Second, MaxBodyBytes: 1 << 20},
		GRPC:          config.GRPC{Enabled: true, Address: grpcAddress, MaxReceiveBytes: 4 << 20},
		Log:           config.Log{Level: "error", Format: "json", File: filepath.Join(t.TempDir(), "app.log"), MaxSizeMB: 1, MaxBackups: 1, MaxAgeDays: 1},
		Database:      config.Database{Enabled: true, Type: "postgres", DSN: dsn, MaxOpenConns: 5, MaxIdleConns: 2, ConnMaxLifetime: time.Minute, ConnMaxIdleTime: time.Minute, PingTimeout: 10 * time.Second},
		Migration:     config.Migration{AutoUp: true, Path: migrationPath, DatabaseURL: dsn, Table: "integration_e2e_schema_migrations"},
		Redis:         config.Redis{Enabled: true, Address: redisOptions.Addr, DB: redisOptions.DB, DialTimeout: 5 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second},
		Health:        config.Health{DatabaseTimeout: 2 * time.Second, RedisTimeout: 2 * time.Second},
		Observability: config.Observability{MetricsEnabled: true},
		JWT:           config.JWT{Issuer: "integration", Secret: secret, TTL: time.Hour},
		Auth:          config.Auth{SkipHTTPPaths: []string{"/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/version"}, SkipGRPCMethods: []string{"/grpc.health.v1.Health/*"}, PSK: config.PSK{Enabled: true, Key: secret, HTTPPaths: []string{"/api/v1/identities/register"}, GRPCMethods: []string{"/platform.identity.v1.IdentityService/GetServiceAccount"}}},
		Cron:          config.Cron{Enabled: false, Timezone: "UTC"},
		User:          config.User{CacheTTL: time.Minute, LockTTL: 10 * time.Second, LockRetryDelay: 20 * time.Millisecond},
		Idempotency:   config.Idempotency{Enabled: true, ProcessingTTL: 30 * time.Second, ResultTTL: time.Hour, FailureTTL: time.Minute},
	}
	application := app.New(cfg)
	if err := application.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = application.Stop(stopCtx)
	})
	baseURL := "http://" + httpAddress
	if status := postJSON(t, baseURL+"/api/v1/version", "", "", `{}`); status != http.StatusOK {
		t.Fatalf("public version status = %d", status)
	}
	registerBody, status := postJSONBody(t, baseURL+"/api/v1/identities/register", "PSK "+secret, "", `{"username":"alice","display_name":"Alice","email":"alice@example.com","password":"correct horse battery staple"}`)
	if status != http.StatusOK {
		t.Fatalf("register status=%d body=%s", status, registerBody)
	}
	userID := responseUserID(t, registerBody)
	loginBody, status := postJSONBody(t, baseURL+"/api/v1/auth/login", "", "", `{"login":"alice","password":"correct horse battery staple"}`)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%s", status, loginBody)
	}
	token, refresh := responseTokens(t, loginBody)
	meBody, status := postJSONBody(t, baseURL+"/api/v1/me", "Bearer "+token, "", `{}`)
	if status != http.StatusOK || !bytes.Contains(meBody, []byte(`"username":"alice"`)) {
		t.Fatalf("JWT profile status=%d body=%s", status, meBody)
	}
	otherLoginBody, status := postJSONBody(t, baseURL+"/api/v1/auth/login", "", "", `{"login":"alice","password":"correct horse battery staple"}`)
	if status != http.StatusOK {
		t.Fatalf("second login status=%d body=%s", status, otherLoginBody)
	}
	otherToken, _ := responseTokens(t, otherLoginBody)
	changePasswordBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/change-password",
		"Bearer "+token,
		"",
		`{"current_password":"correct horse battery staple","new_password":"different horse battery staple"}`,
	)
	if status != http.StatusOK || !bytes.Contains(changePasswordBody, []byte(`"revoked_sessions":1`)) {
		t.Fatalf("change password status=%d body=%s", status, changePasswordBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+otherToken, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("other session JWT status = %d, want %d", status, http.StatusUnauthorized)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+token, "", `{}`); status != http.StatusOK {
		t.Fatalf("current session JWT after password change status = %d", status)
	}
	oldPasswordBody, status := postJSONBody(t, baseURL+"/api/v1/auth/login", "", "", `{"login":"alice","password":"correct horse battery staple"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("old password login status=%d body=%s", status, oldPasswordBody)
	}
	serviceAccountBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/service-accounts/create",
		"Bearer "+token,
		"",
		`{"name":"reporting","audiences":["reporting-api"]}`,
	)
	if status != http.StatusOK {
		t.Fatalf("create service account status=%d body=%s", status, serviceAccountBody)
	}
	serviceAccountsBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/service-accounts/list",
		"Bearer "+token,
		"",
		`{"keyword":"report","status":"active","page":1,"page_size":20}`,
	)
	if status != http.StatusOK || !bytes.Contains(serviceAccountsBody, []byte(`"client_id":"svc_`)) {
		t.Fatalf("list service accounts status=%d body=%s", status, serviceAccountsBody)
	}
	refreshBody, status := postJSONBody(t, baseURL+"/api/v1/auth/refresh", "", "", `{"refresh_token":"`+refresh+`"}`)
	if status != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", status, refreshBody)
	}

	connection, err := grpc.NewClient(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	healthResponse, err := grpc_health_v1.NewHealthClient(connection).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil || healthResponse.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("health = %v, %v", healthResponse, err)
	}
	pskCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "PSK "+secret)
	if _, err := identityv1.NewIdentityServiceClient(connection).GetServiceAccount(pskCtx, &identityv1.GetServiceAccountRequest{ServiceAccountId: "missing"}); grpcstatus.Code(err) == codes.Unauthenticated {
		t.Fatalf("PSK GetServiceAccount was not authenticated: %v", err)
	}
	jwtCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	identityResponse, err := identityv1.NewIdentityServiceClient(connection).GetUser(jwtCtx, &identityv1.GetUserRequest{UserId: userID})
	if err != nil || identityResponse.GetUser().GetUsername() != "alice" {
		t.Fatalf("JWT GetUser: %v, %v", identityResponse, err)
	}
	sessionsBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/sessions/list",
		"Bearer "+token,
		"",
		`{"user_id":"`+userID+`","status":"active","page":1,"page_size":20}`,
	)
	if status != http.StatusOK {
		t.Fatalf("list sessions status=%d body=%s", status, sessionsBody)
	}
	sessionID, sessionVersion := responseSession(t, sessionsBody)
	revokeBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/sessions/revoke",
		"Bearer "+token,
		"",
		fmt.Sprintf(
			`{"session_id":%q,"reason":"integration security test","version":%d}`,
			sessionID,
			sessionVersion,
		),
	)
	if status != http.StatusOK || !bytes.Contains(revokeBody, []byte(`"status":"revoked"`)) {
		t.Fatalf("revoke session status=%d body=%s", status, revokeBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+token, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("revoked session JWT status = %d, want %d", status, http.StatusUnauthorized)
	}
	newPasswordBody, status := postJSONBody(t, baseURL+"/api/v1/auth/login", "", "", `{"login":"alice","password":"different horse battery staple"}`)
	if status != http.StatusOK {
		t.Fatalf("new password login status=%d body=%s", status, newPasswordBody)
	}
	newPasswordToken, _ := responseTokens(t, newPasswordBody)
	identitiesBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/list",
		"Bearer "+newPasswordToken,
		"",
		`{"keyword":"alice","status":"active","page":1,"page_size":20}`,
	)
	if status != http.StatusOK {
		t.Fatalf("list identities status=%d body=%s", status, identitiesBody)
	}
	identityVersion := responseIdentityVersion(t, identitiesBody, userID)
	updateStatusBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/update-status",
		"Bearer "+newPasswordToken,
		"",
		fmt.Sprintf(
			`{"id":%q,"status":"disabled","reason":"integration lifecycle test","version":%d}`,
			userID,
			identityVersion,
		),
	)
	if status != http.StatusOK {
		t.Fatalf("disable identity status=%d body=%s", status, updateStatusBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+newPasswordToken, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("disabled user session status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func responseUserID(t *testing.T, data []byte) string {
	t.Helper()
	var response struct {
		Body struct {
			ID string `json:"id"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	return response.Body.ID
}

func responseTokens(t *testing.T, data []byte) (string, string) {
	t.Helper()
	var response struct {
		Body struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Body.AccessToken == "" || response.Body.RefreshToken == "" {
		t.Fatalf("missing tokens: %s", data)
	}
	return response.Body.AccessToken, response.Body.RefreshToken
}

func responseSession(t *testing.T, data []byte) (string, int64) {
	t.Helper()
	var response struct {
		Body struct {
			Items []struct {
				SessionID string `json:"session_id"`
				Version   int64  `json:"version"`
			} `json:"items"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Body.Items) != 1 || response.Body.Items[0].SessionID == "" {
		t.Fatalf("missing session: %s", data)
	}
	return response.Body.Items[0].SessionID, response.Body.Items[0].Version
}

func responseIdentityVersion(t *testing.T, data []byte, userID string) int64 {
	t.Helper()
	var response struct {
		Body struct {
			Items []struct {
				ID      string `json:"id"`
				Version int64  `json:"version"`
			} `json:"items"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	for _, item := range response.Body.Items {
		if item.ID == userID && item.Version > 0 {
			return item.Version
		}
	}
	t.Fatalf("missing identity version for %q: %s", userID, data)
	return 0
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func postJSON(t *testing.T, target, authorization, key, body string) int {
	t.Helper()
	_, status := postJSONBody(t, target, authorization, key, body)
	return status
}
func postJSONBody(t *testing.T, target, authorization, key, body string) ([]byte, int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var validJSON any
	if err := json.Unmarshal(data, &validJSON); err != nil {
		t.Fatalf("invalid JSON response: %v (%s)", err, data)
	}
	return data, response.StatusCode
}

var _ = fmt.Sprintf
