package httptransport

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/health"
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
