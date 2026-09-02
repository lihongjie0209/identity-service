package grpctransport

import (
	"testing"
	"time"

	"github.com/lihongjie0209/identity-service/internal/auth"
	"github.com/lihongjie0209/identity-service/internal/config"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestIdentityGRPCRequirementCoversPlatformReadsOnly(t *testing.T) {
	t.Parallel()
	resolve := identityGRPCRequirement(true)
	for _, method := range []string{identityv1.IdentityService_GetUser_FullMethodName, identityv1.IdentityService_BatchGetUsers_FullMethodName, identityv1.IdentityService_ListUsers_FullMethodName} {
		requirement, ok := resolve(method)
		if !ok || requirement.Resource == "" || requirement.Action == "" || requirement.Scope != platformauthz.ScopePlatform {
			t.Fatalf("method %q requirement = %+v, %v", method, requirement, ok)
		}
	}
	for _, method := range []string{identityv1.IdentityService_ValidateSession_FullMethodName, identityv1.IdentityService_RevokeTenantSessions_FullMethodName, identityv1.IdentityService_IssueTenantToken_FullMethodName, identityv1.IdentityService_GetServiceAccount_FullMethodName} {
		if _, ok := resolve(method); ok {
			t.Fatalf("authentication fact method %q must not depend on authorization-service", method)
		}
	}
	if _, ok := identityGRPCRequirement(false)(identityv1.IdentityService_GetUser_FullMethodName); ok {
		t.Fatal("disabled authorization must not call the decision service")
	}
}

func TestAuthenticateGRPC_PSKWildcard(t *testing.T) {
	t.Parallel()
	const key = "01234567890123456789012345678901"
	authService := auth.New(config.Config{JWT: config.JWT{Issuer: "test", Secret: key, TTL: time.Hour}})
	cfg := config.Auth{
		SkipGRPCMethods: []string{"/hello.v1.UserService/*"},
		PSK:             config.PSK{Enabled: true, Key: key, GRPCMethods: []string{"/hello.v1.UserService/*"}},
	}
	for _, test := range []struct {
		name   string
		header string
		code   codes.Code
	}{
		{name: "valid", header: "PSK " + key, code: codes.OK},
		{name: "PSK precedes skip", code: codes.Unauthenticated},
		{name: "bearer rejected", header: "Bearer " + key, code: codes.Unauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", test.header))
			_, err := authenticateGRPC(ctx, "/hello.v1.UserService/GetUser", authService, cfg)
			if got := status.Code(err); got != test.code {
				t.Fatalf("status code = %s, want %s", got, test.code)
			}
		})
	}
}
