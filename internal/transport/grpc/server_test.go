package grpctransport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lihongjie0209/identity-service/internal/auth"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/idempotency"
	platformauthz "github.com/lihongjie0209/microservice-platform-go/authz"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type fakeGRPCIdempotencyManager struct {
	decision    idempotency.Decision
	fingerprint string
	completed   *cachedGRPCResponse
}

func (*fakeGRPCIdempotencyManager) Enabled() bool { return true }
func (m *fakeGRPCIdempotencyManager) Begin(_ context.Context, _, fingerprint string) (idempotency.Decision, error) {
	m.fingerprint = fingerprint
	return m.decision, nil
}
func (m *fakeGRPCIdempotencyManager) Complete(_ context.Context, _, _ string, response any) error {
	value, ok := response.(cachedGRPCResponse)
	if ok {
		m.completed = &value
	}
	return nil
}
func (*fakeGRPCIdempotencyManager) Fail(context.Context, string, string, idempotency.Failure) error {
	return nil
}

func TestIdempotencyExecutionInterceptorReplaysTenantSessionRevocation(t *testing.T) {
	t.Parallel()
	manager := &fakeGRPCIdempotencyManager{decision: idempotency.Decision{State: idempotency.StateAcquired, Owner: "owner-1"}}
	interceptor := idempotencyExecutionInterceptor(manager, []string{identityv1.IdentityService_RevokeTenantSessions_FullMethodName}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := idempotency.WithContext(t.Context(), "operation-1")
	request := &identityv1.RevokeTenantSessionsRequest{TenantId: "tenant-1"}
	expected := &identityv1.RevokeTenantSessionsResponse{}
	response, err := interceptor(ctx, request, &grpc.UnaryServerInfo{FullMethod: identityv1.IdentityService_RevokeTenantSessions_FullMethodName}, func(context.Context, any) (any, error) { return expected, nil })
	if err != nil || response != expected || manager.fingerprint == "" || manager.completed == nil {
		t.Fatalf("response=%v error=%v fingerprint=%q completed=%+v", response, err, manager.fingerprint, manager.completed)
	}
	encoded, err := json.Marshal(*manager.completed)
	if err != nil {
		t.Fatal(err)
	}
	manager.decision = idempotency.Decision{State: idempotency.StateCompleted, Response: encoded}
	calls := 0
	replayed, err := interceptor(ctx, request, &grpc.UnaryServerInfo{FullMethod: identityv1.IdentityService_RevokeTenantSessions_FullMethodName}, func(context.Context, any) (any, error) { calls++; return nil, nil })
	if err != nil || calls != 0 || !proto.Equal(replayed.(proto.Message), expected) {
		t.Fatalf("replayed=%v error=%v calls=%d", replayed, err, calls)
	}
}

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
