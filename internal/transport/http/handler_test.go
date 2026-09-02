package httptransport

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/database"
	"github.com/lihongjie0209/identity-service/internal/health"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
	"github.com/lihongjie0209/microservice-platform-go/principal"
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

func TestHandlerRotateServiceAccountSecretRejectsMissingVersion(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	handler := NewHandler(nil, health.New(nil, nil, config.Config{}), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := gin.New()
	router.POST("/service-accounts/rotate-secret", handler.RotateServiceAccountSecret)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/service-accounts/rotate-secret", strings.NewReader(`{"id":"service-account-1"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestHandlerUpdateIdentityProfileRejectsMissingReason(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	handler := NewHandler(nil, health.New(nil, nil, config.Config{}), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := gin.New()
	router.POST("/identities/update-profile", handler.UpdateIdentityProfile)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/identities/update-profile", strings.NewReader(`{"id":"user-1","display_name":"Alice","email":"alice@example.com","version":1}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestHandlerBatchGetIdentitiesRejectsMissingIDs(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	handler := NewHandler(nil, health.New(nil, nil, config.Config{}), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	router := gin.New()
	router.POST("/identities/batch-get", handler.BatchGetIdentities)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/identities/batch-get", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestHandlerMeBindsProfileToAuthenticatedUser(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	identities, err := identitydomain.NewService(
		identitydomain.NewRepository(sqlDB),
		database.NewTransactor(sqlDB),
		config.Config{
			App: config.App{Name: "identity-service"},
			JWT: config.JWT{
				Issuer: "test",
				Secret: "01234567890123456789012345678901",
				TTL:    time.Hour,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, username, name, email, phone, status").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow(
			"user-1", "alice", "Alice", "alice@example.com", "13800000000", identitydomain.StatusActive,
			0, nil, 1, now, now, "admin", "admin",
		))
	handler := NewHandler(
		nil,
		health.New(nil, nil, config.Config{}),
		identities,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		actor := principal.Principal{
			ID:           "user-1",
			Type:         principal.TypeUser,
			SessionID:    "session-1",
			TenantID:     "tenant-1",
			MembershipID: "membership-1",
		}
		c.Request = c.Request.WithContext(principal.WithContext(c.Request.Context(), actor))
		c.Next()
	})
	router.POST("/me", handler.Me)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/me", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	for _, expected := range []string{
		`"subject":"user-1"`,
		`"username":"alice"`,
		`"tenant_id":"tenant-1"`,
		`"membership_id":"membership-1"`,
		`"roles":[]`,
	} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("body %s does not contain %s", recorder.Body.String(), expected)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerMeDoesNotTreatServiceAccountAsUser(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)
	handler := NewHandler(
		nil,
		health.New(nil, nil, config.Config{}),
		nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		actor := principal.Principal{ID: "service-1", Type: principal.TypeServiceAccount}
		c.Request = c.Request.WithContext(principal.WithContext(c.Request.Context(), actor))
		c.Next()
	})
	router.POST("/me", handler.Me)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/me", nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"subject_type":"service_account"`) {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"username":""`) {
		t.Fatalf("service account response does not have a stable profile shape: %s", recorder.Body.String())
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
