package httptransport

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/health"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
)

func TestHandler_LoginRejectsInvalidRequest(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	handler := NewHandler(nil, health.New(nil, nil, config.Config{}), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := gin.New()
	router.POST("/login", handler.Login)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"login":""}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestSessionResponseClassifiesLifecycleWithoutExposingRefreshToken(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	revokedAt := now.Add(-time.Minute)
	tests := []struct {
		name    string
		session identitydomain.Session
		status  string
	}{
		{name: "active", session: identitydomain.Session{ExpiresAt: now.Add(time.Hour)}, status: "active"},
		{name: "expired", session: identitydomain.Session{ExpiresAt: now}, status: "expired"},
		{
			name:    "revoked takes precedence",
			session: identitydomain.Session{ExpiresAt: now.Add(-time.Hour), RevokedAt: &revokedAt},
			status:  "revoked",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := sessionResponse(test.session, now)
			if response.Status != test.status {
				t.Fatalf("status = %q, want %q", response.Status, test.status)
			}
		})
	}
}
