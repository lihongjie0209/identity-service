package httptransport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/identity-service/internal/auth"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/idempotency"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

type fakeIdempotencyManager struct {
	decision  idempotency.Decision
	beginKey  string
	completed *Response
}

func (*fakeIdempotencyManager) Enabled() bool { return true }
func (m *fakeIdempotencyManager) Begin(_ context.Context, key, _ string) (idempotency.Decision, error) {
	m.beginKey = key
	return m.decision, nil
}
func (m *fakeIdempotencyManager) Complete(_ context.Context, _, _ string, response any) error {
	value, ok := response.(Response)
	if ok {
		m.completed = &value
	}
	return nil
}
func (*fakeIdempotencyManager) Fail(context.Context, string, string, idempotency.Failure) error {
	return nil
}

func TestIdempotencyExecutionCompletesAndReplaysAdministrativeMutation(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := &fakeIdempotencyManager{decision: idempotency.Decision{State: idempotency.StateAcquired, Owner: "owner-1"}}
	calls := 0
	router := gin.New()
	router.Use(RequestID(), func(c *gin.Context) {
		c.Set("subject", "administrator-1")
		c.Request = c.Request.WithContext(idempotency.WithContext(c.Request.Context(), "operation-1"))
		c.Next()
	}, IdempotencyExecution(manager, []string{"/api/v1/sessions/revoke"}, logger))
	router.POST("/api/v1/sessions/revoke", func(c *gin.Context) { calls++; OK(c, nil) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke", strings.NewReader(`{"session_id":"session-1"}`)))
	if calls != 1 || manager.beginKey != "operation-1" || manager.completed == nil || manager.completed.RequestID != "" {
		t.Fatalf("calls=%d key=%q completed=%+v", calls, manager.beginKey, manager.completed)
	}
	stored, err := json.Marshal(*manager.completed)
	if err != nil {
		t.Fatal(err)
	}
	manager.decision = idempotency.Decision{State: idempotency.StateCompleted, Response: stored}
	replay := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/revoke", strings.NewReader(`{"session_id":"session-1"}`))
	replay.Header.Set("X-Request-ID", "current-request")
	replayRecorder := httptest.NewRecorder()
	router.ServeHTTP(replayRecorder, replay)
	var response Response
	if err := json.Unmarshal(replayRecorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || response.RequestID != "current-request" {
		t.Fatalf("calls=%d response=%+v", calls, response)
	}
}

func TestIdempotencyExecutionDoesNotCacheSensitiveTokenRoute(t *testing.T) {
	t.Parallel()
	manager := &fakeIdempotencyManager{decision: idempotency.Decision{State: idempotency.StateConflict}}
	calls := 0
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(idempotency.WithContext(c.Request.Context(), "operation-1"))
		c.Next()
	}, IdempotencyExecution(manager, []string{"/api/v1/sessions/revoke"}, slog.New(slog.NewTextHandler(io.Discard, nil))))
	router.POST("/api/v1/auth/refresh", func(c *gin.Context) { calls++; OK(c, gin.H{"access_token": "secret"}) })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil))
	if calls != 1 || manager.beginKey != "" || recorder.Code != http.StatusOK {
		t.Fatalf("calls=%d key=%q status=%d", calls, manager.beginKey, recorder.Code)
	}
}

func TestIdempotencyExecutionDoesNotCacheOneTimeServiceAccountSecret(t *testing.T) {
	t.Parallel()
	manager := &fakeIdempotencyManager{decision: idempotency.Decision{State: idempotency.StateConflict}}
	calls := 0
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(idempotency.WithContext(c.Request.Context(), "operation-1"))
		c.Next()
	}, IdempotencyExecution(manager, []string{"/api/v1/service-accounts/update-status"}, slog.New(slog.NewTextHandler(io.Discard, nil))))
	router.POST("/api/v1/service-accounts/rotate-secret", func(c *gin.Context) {
		calls++
		OK(c, gin.H{"client_secret": "one-time-secret"})
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts/rotate-secret", nil))
	if calls != 1 || manager.beginKey != "" || recorder.Code != http.StatusOK {
		t.Fatalf("calls=%d key=%q status=%d", calls, manager.beginKey, recorder.Code)
	}
}

type authorizationStub struct{ err error }

func (a authorizationStub) Authorize(context.Context, principal.Principal, platformauthz.Requirement) error {
	return a.err
}

func TestIdentityHTTPRequirementCoversAdministrationOnly(t *testing.T) {
	t.Parallel()
	for _, route := range []string{"/api/v1/sessions/list", "/api/v1/sessions/get", "/api/v1/sessions/revoke", "/api/v1/identities/register", "/api/v1/identities/get", "/api/v1/identities/list", "/api/v1/identities/batch-get", "/api/v1/identities/update-profile", "/api/v1/identities/update-status", "/api/v1/identities/password-reset/issue", "/api/v1/identities/mfa/status", "/api/v1/identities/mfa/reset", "/api/v1/service-accounts/create", "/api/v1/service-accounts/get", "/api/v1/service-accounts/list", "/api/v1/service-accounts/batch-get", "/api/v1/service-accounts/update-status", "/api/v1/service-accounts/rotate-secret"} {
		requirement, ok := identityHTTPRequirement(route)
		if !ok || requirement.Resource == "" || requirement.Action == "" || requirement.Scope != platformauthz.ScopePlatform {
			t.Fatalf("route %q requirement = %+v, %v", route, requirement, ok)
		}
	}
	for _, route := range []string{"/api/v1/auth/login", "/api/v1/auth/mfa/verify", "/api/v1/auth/refresh", "/api/v1/auth/password-reset/confirm", "/api/v1/auth/logout", "/api/v1/auth/change-password", "/api/v1/auth/mfa/status", "/api/v1/auth/mfa/setup/start", "/api/v1/auth/mfa/setup/confirm", "/api/v1/auth/mfa/recovery-codes/regenerate", "/api/v1/auth/mfa/disable", "/api/v1/auth/sessions/list", "/api/v1/auth/sessions/revoke", "/api/v1/auth/service-token", "/api/v1/me", "/api/v1/version"} {
		if _, ok := identityHTTPRequirement(route); ok {
			t.Fatalf("authentication lifecycle route %q must not depend on authorization-service", route)
		}
	}
}

func TestAdministrativeMFARecoveryUsesOneDedicatedPermission(t *testing.T) {
	t.Parallel()
	statusRequirement, statusOK := identityHTTPRequirement("/api/v1/identities/mfa/status")
	resetRequirement, resetOK := identityHTTPRequirement("/api/v1/identities/mfa/reset")
	if !statusOK || !resetOK ||
		statusRequirement.Resource != resetRequirement.Resource ||
		statusRequirement.Action != resetRequirement.Action ||
		statusRequirement.Scope != resetRequirement.Scope {
		t.Fatalf("mfa recovery requirements = status %+v reset %+v", statusRequirement, resetRequirement)
	}
	if statusRequirement.Resource != "identity.user" || statusRequirement.Action != "mfa-reset" {
		t.Fatalf("mfa recovery requirement = %+v", statusRequirement)
	}
}

func TestAuthorizationFailsClosedAndClassifiesOutage(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{{name: "denied", err: platformauthz.ErrDenied, status: http.StatusForbidden}, {name: "unavailable", err: platformauthz.ErrDecisionUnavailable, status: http.StatusServiceUnavailable}} {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(RequestID(), func(c *gin.Context) {
				c.Request = c.Request.WithContext(principal.WithContext(c.Request.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser}))
				c.Next()
			}, Authorization(true, authorizationStub{err: test.err}, slog.New(slog.NewTextHandler(io.Discard, nil))))
			router.POST("/api/v1/identities/list", func(c *gin.Context) { OK(c, nil) })
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/identities/list", nil))
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

func TestRequestID(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestID())
	router.POST("/test", func(c *gin.Context) { OK(c, nil) })
	request := httptest.NewRequest(http.MethodPost, "/test", nil)
	request.Header.Set("X-Request-ID", "client-request-1")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("X-Request-ID"); got != "client-request-1" {
		t.Fatalf("X-Request-ID = %q", got)
	}
	var response Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.RequestID != "client-request-1" {
		t.Fatalf("request_id = %q", response.RequestID)
	}
}

func TestAuthentication_PSKPrecedesSkipAndJWT(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	const key = "01234567890123456789012345678901"
	service := auth.New(config.Config{JWT: config.JWT{Issuer: "test", Secret: key, TTL: time.Hour}})
	for _, test := range []struct {
		name   string
		header string
		status int
	}{
		{name: "valid PSK", header: "PSK " + key, status: http.StatusOK},
		{name: "PSK route does not become public", status: http.StatusUnauthorized},
		{name: "bearer cannot access PSK route", header: "Bearer invalid", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			router := gin.New()
			router.Use(RequestID(), Authentication(service, slog.New(slog.NewTextHandler(io.Discard, nil)), config.Auth{
				SkipHTTPPaths: []string{"/api/v1/external/*"},
				PSK:           config.PSK{Enabled: true, Key: key, HTTPPaths: []string{"/api/v1/external/*"}},
			}))
			router.POST("/api/v1/external/callback", func(c *gin.Context) { OK(c, nil) })
			request := httptest.NewRequest(http.MethodPost, "/api/v1/external/callback", nil)
			request.Header.Set("Authorization", test.header)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

func TestRequireJSON(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestID(), RequireJSON())
	router.POST("/test", func(c *gin.Context) { OK(c, nil) })
	request := httptest.NewRequest(http.MethodPost, "/test", io.NopCloser(&oneByteReader{}))
	request.ContentLength = 1
	request.Header.Set("Content-Type", "text/plain")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestTimeoutPropagatesCancellation(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := gin.New()
	router.Use(RequestID(), Timeout(time.Millisecond, logger))
	router.POST("/test", func(c *gin.Context) { <-c.Request.Context().Done() })
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/test", nil))
	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusGatewayTimeout)
	}
}

type oneByteReader struct{}

func (*oneByteReader) Read(buffer []byte) (int, error) { buffer[0] = 'x'; return 1, io.EOF }
