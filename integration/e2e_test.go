//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Test interoperability with RFC 6238 HMAC-SHA1.
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
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
	mfaEncryptionKey := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	mfaRecoveryPepper := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyzABCDEF"))
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
		MFA:           config.MFA{Enabled: true, Issuer: "Platform Integration", EncryptionKey: mfaEncryptionKey, RecoveryPepper: mfaRecoveryPepper, ChallengeTTL: 5 * time.Minute},
		Auth:          config.Auth{SkipHTTPPaths: []string{"/api/v1/auth/login", "/api/v1/auth/mfa/verify", "/api/v1/auth/refresh", "/api/v1/auth/password-reset/confirm", "/api/v1/version"}, SkipGRPCMethods: []string{"/grpc.health.v1.Health/*"}, PSK: config.PSK{Enabled: true, Key: secret, HTTPPaths: []string{"/api/v1/identities/register"}, GRPCMethods: []string{"/platform.identity.v1.IdentityService/GetServiceAccount"}}},
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
	token, refresh, _ := responseTokens(t, loginBody)
	meBody, status := postJSONBody(t, baseURL+"/api/v1/me", "Bearer "+token, "", `{}`)
	if status != http.StatusOK || !bytes.Contains(meBody, []byte(`"username":"alice"`)) {
		t.Fatalf("JWT profile status=%d body=%s", status, meBody)
	}
	identityBody, status := postJSONBody(t, baseURL+"/api/v1/identities/get", "Bearer "+token, "", fmt.Sprintf(`{"id":%q}`, userID))
	if status != http.StatusOK || !bytes.Contains(identityBody, []byte(`"username":"alice"`)) {
		t.Fatalf("get identity status=%d body=%s", status, identityBody)
	}
	otherLoginBody, status := postJSONBody(t, baseURL+"/api/v1/auth/login", "", "", `{"login":"alice","password":"correct horse battery staple"}`)
	if status != http.StatusOK {
		t.Fatalf("second login status=%d body=%s", status, otherLoginBody)
	}
	otherToken, _, _ := responseTokens(t, otherLoginBody)
	selfRevokeLoginBody, status := postJSONBody(t, baseURL+"/api/v1/auth/login", "", "", `{"login":"alice","password":"correct horse battery staple"}`)
	if status != http.StatusOK {
		t.Fatalf("self-revoke login status=%d body=%s", status, selfRevokeLoginBody)
	}
	selfRevokeToken, _, selfRevokeSessionID := responseTokens(t, selfRevokeLoginBody)
	ownedSessionsBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/sessions/list",
		"Bearer "+token,
		"",
		`{"status":"active","page":1,"page_size":20}`,
	)
	if status != http.StatusOK {
		t.Fatalf("list own sessions status=%d body=%s", status, ownedSessionsBody)
	}
	if !bytes.Contains(ownedSessionsBody, []byte(`"client_ip":"127.0.0.1"`)) ||
		!bytes.Contains(ownedSessionsBody, []byte(`"user_agent":"Go-http-client/1.1"`)) {
		t.Fatalf("own sessions omit client metadata: %s", ownedSessionsBody)
	}
	selfRevokeVersion := responseSessionVersion(t, ownedSessionsBody, selfRevokeSessionID)
	selfRevokeBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/sessions/revoke",
		"Bearer "+token,
		"",
		fmt.Sprintf(`{"session_id":%q,"version":%d}`, selfRevokeSessionID, selfRevokeVersion),
	)
	if status != http.StatusOK || !bytes.Contains(selfRevokeBody, []byte(`"status":"revoked"`)) {
		t.Fatalf("self revoke session status=%d body=%s", status, selfRevokeBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+selfRevokeToken, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("self-revoked session JWT status = %d, want %d", status, http.StatusUnauthorized)
	}
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
	var createdServiceAccount struct {
		Body struct {
			Account struct {
				ID string `json:"id"`
			} `json:"account"`
		} `json:"body"`
	}
	if err := json.Unmarshal(serviceAccountBody, &createdServiceAccount); err != nil || createdServiceAccount.Body.Account.ID == "" {
		t.Fatalf("decode service account: %v body=%s", err, serviceAccountBody)
	}
	serviceAccountDetail, status := postJSONBody(t, baseURL+"/api/v1/service-accounts/get", "Bearer "+token, "", fmt.Sprintf(`{"id":%q}`, createdServiceAccount.Body.Account.ID))
	if status != http.StatusOK || !bytes.Contains(serviceAccountDetail, []byte(`"name":"reporting"`)) {
		t.Fatalf("get service account status=%d body=%s", status, serviceAccountDetail)
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
	if status != http.StatusOK || !bytes.Contains(sessionsBody, []byte(`"username":"alice"`)) || !bytes.Contains(sessionsBody, []byte(`"user_display_name":"Alice"`)) {
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
	logoutToken, _, logoutSessionID := responseTokens(t, newPasswordBody)
	logoutBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/logout",
		"Bearer "+logoutToken,
		"",
		fmt.Sprintf(`{"session_id":%q,"reason":"user logout"}`, logoutSessionID),
	)
	if status != http.StatusOK || !bytes.Contains(logoutBody, []byte(`"revoked":true`)) {
		t.Fatalf("logout status=%d body=%s", status, logoutBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+logoutToken, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("logged out session status = %d, want %d", status, http.StatusUnauthorized)
	}
	testMFAHTTPFlow(t, baseURL, secret)
	testPasswordResetHTTPFlow(t, baseURL, secret)
	lifecycleLoginBody, status := postJSONBody(t, baseURL+"/api/v1/auth/login", "", "", `{"login":"alice","password":"different horse battery staple"}`)
	if status != http.StatusOK {
		t.Fatalf("lifecycle login status=%d body=%s", status, lifecycleLoginBody)
	}
	newPasswordToken, _, _ := responseTokens(t, lifecycleLoginBody)
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
	batchIdentitiesBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/batch-get",
		"Bearer "+newPasswordToken,
		"",
		fmt.Sprintf(`{"user_ids":[%q]}`, userID),
	)
	if status != http.StatusOK || !bytes.Contains(batchIdentitiesBody, []byte(`"username":"alice"`)) {
		t.Fatalf("batch identities status=%d body=%s", status, batchIdentitiesBody)
	}
	identityVersion := responseIdentityVersion(t, identitiesBody, userID)
	updateProfileBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/update-profile",
		"Bearer "+newPasswordToken,
		"",
		fmt.Sprintf(
			`{"id":%q,"display_name":"Alice Zhang","email":"alice.zhang@example.com","phone":"13800000000","reason":"integration profile test","version":%d}`,
			userID,
			identityVersion,
		),
	)
	if status != http.StatusOK || !bytes.Contains(updateProfileBody, []byte(`"display_name":"Alice Zhang"`)) {
		t.Fatalf("update identity profile status=%d body=%s", status, updateProfileBody)
	}
	updatedIdentityVersion := responseBodyVersion(t, updateProfileBody)
	_, status = postJSONBody(
		t,
		baseURL+"/api/v1/identities/update-profile",
		"Bearer "+newPasswordToken,
		"",
		fmt.Sprintf(
			`{"id":%q,"display_name":"Stale Update","email":"stale@example.com","reason":"stale integration test","version":%d}`,
			userID,
			identityVersion,
		),
	)
	if status != http.StatusConflict {
		t.Fatalf("stale identity profile status=%d, want %d", status, http.StatusConflict)
	}
	updateStatusBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/update-status",
		"Bearer "+newPasswordToken,
		"",
		fmt.Sprintf(
			`{"id":%q,"status":"disabled","reason":"integration lifecycle test","version":%d}`,
			userID,
			updatedIdentityVersion,
		),
	)
	if status != http.StatusOK {
		t.Fatalf("disable identity status=%d body=%s", status, updateStatusBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+newPasswordToken, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("disabled user session status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func responseBodyVersion(t *testing.T, data []byte) int64 {
	t.Helper()
	var response struct {
		Body struct {
			Version int64 `json:"version"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Body.Version < 1 {
		t.Fatalf("response version is invalid: %s", data)
	}
	return response.Body.Version
}

func testPasswordResetHTTPFlow(t *testing.T, baseURL, psk string) {
	t.Helper()
	registerBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/register",
		"PSK "+psk,
		"",
		`{"username":"recovery-user","display_name":"Recovery User","email":"recovery@example.com","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("register password recovery user status=%d body=%s", status, registerBody)
	}
	userID := responseUserID(t, registerBody)
	loginBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"recovery-user","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("initial password recovery login status=%d body=%s", status, loginBody)
	}
	oldAccessToken, _, _ := responseTokens(t, loginBody)

	adminRegisterBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/register",
		"PSK "+psk,
		"",
		`{"username":"recovery-admin","display_name":"Recovery Admin","email":"recovery-admin@example.com","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("register password recovery admin status=%d body=%s", status, adminRegisterBody)
	}
	adminLoginBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"recovery-admin","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("password recovery admin login status=%d body=%s", status, adminLoginBody)
	}
	adminToken, _, _ := responseTokens(t, adminLoginBody)

	firstIssueBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/password-reset/issue",
		"Bearer "+adminToken,
		"",
		fmt.Sprintf(`{"user_id":%q,"reason":"verified account ownership"}`, userID),
	)
	if status != http.StatusOK {
		t.Fatalf("first password reset issue status=%d body=%s", status, firstIssueBody)
	}
	firstToken := responsePasswordResetToken(t, firstIssueBody)
	secondIssueBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/password-reset/issue",
		"Bearer "+adminToken,
		"",
		fmt.Sprintf(`{"user_id":%q,"reason":"reissued through verified channel"}`, userID),
	)
	if status != http.StatusOK {
		t.Fatalf("second password reset issue status=%d body=%s", status, secondIssueBody)
	}
	secondToken := responsePasswordResetToken(t, secondIssueBody)
	if status := postJSON(
		t,
		baseURL+"/api/v1/auth/password-reset/confirm",
		"",
		"",
		fmt.Sprintf(`{"reset_token":%q,"new_password":"different horse battery staple"}`, firstToken),
	); status != http.StatusUnauthorized {
		t.Fatalf("superseded password reset token status=%d, want %d", status, http.StatusUnauthorized)
	}
	confirmBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/password-reset/confirm",
		"",
		"",
		fmt.Sprintf(`{"reset_token":%q,"new_password":"different horse battery staple"}`, secondToken),
	)
	if status != http.StatusOK || !bytes.Contains(confirmBody, []byte(`"changed":true`)) {
		t.Fatalf("confirm password reset status=%d body=%s", status, confirmBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+oldAccessToken, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("pre-reset session status=%d, want %d", status, http.StatusUnauthorized)
	}
	if status := postJSON(
		t,
		baseURL+"/api/v1/auth/password-reset/confirm",
		"",
		"",
		fmt.Sprintf(`{"reset_token":%q,"new_password":"another horse battery staple"}`, secondToken),
	); status != http.StatusUnauthorized {
		t.Fatalf("replayed password reset token status=%d, want %d", status, http.StatusUnauthorized)
	}
	if status := postJSON(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"recovery-user","password":"correct horse battery staple"}`,
	); status != http.StatusUnauthorized {
		t.Fatalf("old password after reset status=%d, want %d", status, http.StatusUnauthorized)
	}
	newLoginBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"recovery-user","password":"different horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("new password after reset status=%d body=%s", status, newLoginBody)
	}
	_, _, _ = responseTokens(t, newLoginBody)
}

func testMFAHTTPFlow(t *testing.T, baseURL, psk string) {
	t.Helper()
	registerBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/register",
		"PSK "+psk,
		"",
		`{"username":"bob","display_name":"Bob","email":"bob@example.com","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("register mfa user status=%d body=%s", status, registerBody)
	}
	bobUserID := responseUserID(t, registerBody)
	loginBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"bob","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("initial mfa user login status=%d body=%s", status, loginBody)
	}
	token, _, _ := responseTokens(t, loginBody)
	setupBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/mfa/setup/start",
		"Bearer "+token,
		"",
		`{"current_password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("start mfa setup status=%d body=%s", status, setupBody)
	}
	secret, version := responseMFASetup(t, setupBody)
	confirmBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/mfa/setup/confirm",
		"Bearer "+token,
		"",
		fmt.Sprintf(`{"code":%q,"version":%d}`, totpCode(t, secret, time.Now()), version),
	)
	if status != http.StatusOK {
		t.Fatalf("confirm mfa setup status=%d body=%s", status, confirmBody)
	}
	recoveryCode := responseFirstRecoveryCode(t, confirmBody)
	challengeBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"bob","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("mfa password login status=%d body=%s", status, challengeBody)
	}
	challenge := responseMFAChallenge(t, challengeBody)
	verifyBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/mfa/verify",
		"",
		"",
		fmt.Sprintf(`{"challenge_token":%q,"recovery_code":%q}`, challenge, recoveryCode),
	)
	if status != http.StatusOK {
		t.Fatalf("verify mfa recovery code status=%d body=%s", status, verifyBody)
	}
	mfaToken, _, _ := responseTokens(t, verifyBody)
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+mfaToken, "", `{}`); status != http.StatusOK {
		t.Fatalf("mfa session status=%d", status)
	}
	if status := postJSON(
		t,
		baseURL+"/api/v1/auth/mfa/verify",
		"",
		"",
		fmt.Sprintf(`{"challenge_token":%q,"recovery_code":%q}`, challenge, recoveryCode),
	); status != http.StatusUnauthorized {
		t.Fatalf("replayed mfa challenge status=%d, want %d", status, http.StatusUnauthorized)
	}

	adminRegisterBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/register",
		"PSK "+psk,
		"",
		`{"username":"mfa-admin","display_name":"MFA Admin","email":"mfa-admin@example.com","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("register mfa admin status=%d body=%s", status, adminRegisterBody)
	}
	adminLoginBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"mfa-admin","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("mfa admin login status=%d body=%s", status, adminLoginBody)
	}
	adminToken, _, _ := responseTokens(t, adminLoginBody)
	statusBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/mfa/status",
		"Bearer "+adminToken,
		"",
		fmt.Sprintf(`{"user_id":%q}`, bobUserID),
	)
	if status != http.StatusOK {
		t.Fatalf("admin mfa status=%d body=%s", status, statusBody)
	}
	mfaVersion := responseMFAStatusVersion(t, statusBody)
	resetBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/identities/mfa/reset",
		"Bearer "+adminToken,
		"",
		fmt.Sprintf(`{"user_id":%q,"reason":"verified device loss","version":%d}`, bobUserID, mfaVersion),
	)
	if status != http.StatusOK {
		t.Fatalf("admin mfa reset=%d body=%s", status, resetBody)
	}
	if status := postJSON(t, baseURL+"/api/v1/me", "Bearer "+mfaToken, "", `{}`); status != http.StatusUnauthorized {
		t.Fatalf("mfa reset session status=%d, want %d", status, http.StatusUnauthorized)
	}
	postResetLoginBody, status := postJSONBody(
		t,
		baseURL+"/api/v1/auth/login",
		"",
		"",
		`{"login":"bob","password":"correct horse battery staple"}`,
	)
	if status != http.StatusOK {
		t.Fatalf("post-reset password login status=%d body=%s", status, postResetLoginBody)
	}
	_, _, _ = responseTokens(t, postResetLoginBody)
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

func responsePasswordResetToken(t *testing.T, data []byte) string {
	t.Helper()
	var response struct {
		Body struct {
			ResetToken string    `json:"reset_token"`
			ExpiresAt  time.Time `json:"expires_at"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Body.ResetToken == "" || !response.Body.ExpiresAt.After(time.Now()) {
		t.Fatalf("missing password reset issue: %s", data)
	}
	return response.Body.ResetToken
}

func responseTokens(t *testing.T, data []byte) (string, string, string) {
	t.Helper()
	var response struct {
		Body struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			SessionID    string `json:"session_id"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Body.AccessToken == "" || response.Body.RefreshToken == "" || response.Body.SessionID == "" {
		t.Fatalf("missing tokens: %s", data)
	}
	return response.Body.AccessToken, response.Body.RefreshToken, response.Body.SessionID
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

func responseSessionVersion(t *testing.T, data []byte, sessionID string) int64 {
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
	for _, item := range response.Body.Items {
		if item.SessionID == sessionID && item.Version > 0 {
			return item.Version
		}
	}
	t.Fatalf("missing session version for %q: %s", sessionID, data)
	return 0
}

func responseMFASetup(t *testing.T, data []byte) (string, int64) {
	t.Helper()
	var response struct {
		Body struct {
			Secret  string `json:"secret"`
			Version int64  `json:"version"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Body.Secret == "" || response.Body.Version < 1 {
		t.Fatalf("missing mfa setup: %s", data)
	}
	return response.Body.Secret, response.Body.Version
}

func responseFirstRecoveryCode(t *testing.T, data []byte) string {
	t.Helper()
	var response struct {
		Body struct {
			RecoveryCodes []string `json:"recovery_codes"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Body.RecoveryCodes) != 10 {
		t.Fatalf("missing recovery codes: %s", data)
	}
	return response.Body.RecoveryCodes[0]
}

func responseMFAChallenge(t *testing.T, data []byte) string {
	t.Helper()
	var response struct {
		Body struct {
			Required  bool   `json:"mfa_required"`
			Challenge string `json:"mfa_challenge_token"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Body.Required || response.Body.Challenge == "" {
		t.Fatalf("missing mfa challenge: %s", data)
	}
	return response.Body.Challenge
}

func responseMFAStatusVersion(t *testing.T, data []byte) int64 {
	t.Helper()
	var response struct {
		Body struct {
			Enabled bool  `json:"enabled"`
			Version int64 `json:"version"`
		} `json:"body"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Body.Enabled || response.Body.Version < 1 {
		t.Fatalf("missing enabled mfa status: %s", data)
	}
	return response.Body.Version
}

func totpCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, decoded)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
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
