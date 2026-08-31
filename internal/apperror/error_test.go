package apperror

import (
	"net/http"
	"testing"
)

func TestForbiddenUsesGlobalCodeAndHTTPStatus(t *testing.T) {
	t.Parallel()
	err := Forbidden("permission denied")
	if err.Code != CodeForbidden || err.HTTPStatus != http.StatusForbidden {
		t.Fatalf("Forbidden() = %+v", err)
	}
}
