package httptransport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lihongjie0209/identity-service/internal/identity"
	"github.com/lihongjie0209/microservice-platform-go/audit"
)

func TestIdentityResponseExposesOnlyPublicFields(t *testing.T) {
	t.Parallel()
	const secretLockState = "internal-lock-state"
	user := identity.User{
		ID: "user-1", Username: "alice", DisplayName: "Alice", Email: "alice@example.test",
		Phone: "13800000000", Status: identity.StatusActive, FailedLoginCount: 9,
		LockedUntil: pointerTo(time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)),
		Fields:      audit.Fields{Version: 3, CreatedBy: secretLockState, UpdatedBy: "operator-1"},
	}

	encoded, err := json.Marshal(identityResponse(user))
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, forbidden := range []string{"failed_login_count", "locked_until"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response contains internal field %q: %s", forbidden, body)
		}
	}
	if strings.Contains(body, "9") && strings.Contains(body, "failed") {
		t.Fatalf("response contains authentication failure state: %s", body)
	}
	if !strings.Contains(body, secretLockState) {
		t.Fatalf("response omitted required audit actor: %s", body)
	}
}

func TestIdentityPageResponseMapsPaginationAndItems(t *testing.T) {
	t.Parallel()
	page := identity.Page[identity.User]{Items: []identity.User{{ID: "user-1", Username: "alice"}}, Total: 23, Page: 2, PageSize: 10}
	response := identityPageResponse(page)
	if len(response.Items) != 1 || response.Items[0].ID != "user-1" || response.Total != 23 || response.Page != 2 || response.PageSize != 10 {
		t.Fatalf("identityPageResponse() = %+v", response)
	}
}

func pointerTo[T any](value T) *T { return &value }
