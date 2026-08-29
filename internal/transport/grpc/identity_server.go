package grpctransport

import (
	"context"

	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type identityServer struct {
	identityv1.UnimplementedIdentityServiceServer
	service *identitydomain.Service
}

func registerIdentityServer(server *grpc.Server, service *identitydomain.Service) {
	identityv1.RegisterIdentityServiceServer(server, &identityServer{service: service})
}

func (s *identityServer) GetUser(ctx context.Context, request *identityv1.GetUserRequest) (*identityv1.GetUserResponse, error) {
	user, err := s.service.GetUser(ctx, request.GetUserId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &identityv1.GetUserResponse{User: identityUser(user)}, nil
}

func (s *identityServer) BatchGetUsers(ctx context.Context, request *identityv1.BatchGetUsersRequest) (*identityv1.BatchGetUsersResponse, error) {
	if len(request.GetUserIds()) > 100 {
		return nil, status.Error(codes.InvalidArgument, "at most 100 user IDs are allowed")
	}
	users, err := s.service.BatchGetUsers(ctx, request.GetUserIds())
	if err != nil {
		return nil, grpcError(err)
	}
	result := make([]*identityv1.User, 0, len(users))
	for _, user := range users {
		result = append(result, identityUser(user))
	}
	return &identityv1.BatchGetUsersResponse{Users: result}, nil
}

func (s *identityServer) ValidateSession(ctx context.Context, request *identityv1.ValidateSessionRequest) (*identityv1.ValidateSessionResponse, error) {
	session, valid, err := s.service.ValidateSession(ctx, request.GetSessionId(), request.GetUserId())
	if err != nil {
		return nil, grpcError(err)
	}
	response := &identityv1.ValidateSessionResponse{Valid: valid}
	if !session.ExpiresAt.IsZero() {
		response.ExpiresAt = timestamppb.New(session.ExpiresAt)
	}
	return response, nil
}

func (s *identityServer) RevokeTenantSessions(ctx context.Context, request *identityv1.RevokeTenantSessionsRequest) (*identityv1.RevokeTenantSessionsResponse, error) {
	count, err := s.service.RevokeTenantSessions(ctx, request.GetUserId(), request.GetTenantId(), request.GetReason())
	if err != nil {
		return nil, grpcError(err)
	}
	return &identityv1.RevokeTenantSessionsResponse{RevokedCount: count}, nil
}

func (s *identityServer) IssueTenantToken(ctx context.Context, request *identityv1.IssueTenantTokenRequest) (*identityv1.IssueTenantTokenResponse, error) {
	token, expiresAt, err := s.service.IssueTenantToken(ctx, request.GetUserId(), request.GetTenantId(), request.GetMembershipId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &identityv1.IssueTenantTokenResponse{AccessToken: token, ExpiresAt: timestamppb.New(expiresAt)}, nil
}

func (s *identityServer) GetServiceAccount(ctx context.Context, request *identityv1.GetServiceAccountRequest) (*identityv1.GetServiceAccountResponse, error) {
	account, err := s.service.GetServiceAccount(ctx, request.GetServiceAccountId())
	if err != nil {
		return nil, grpcError(err)
	}
	return &identityv1.GetServiceAccountResponse{Id: account.ID, Name: account.Name, Enabled: account.Status == identitydomain.StatusActive, Audiences: account.Audiences}, nil
}

func identityUser(user identitydomain.User) *identityv1.User {
	statuses := map[string]identityv1.UserStatus{identitydomain.StatusActive: identityv1.UserStatus_USER_STATUS_ACTIVE, identitydomain.StatusDisabled: identityv1.UserStatus_USER_STATUS_DISABLED, identitydomain.StatusLocked: identityv1.UserStatus_USER_STATUS_LOCKED, identitydomain.StatusClosed: identityv1.UserStatus_USER_STATUS_CLOSED}
	return &identityv1.User{Id: user.ID, Username: user.Username, DisplayName: user.DisplayName, Email: user.Email, Phone: user.Phone, Status: statuses[user.Status], CreatedAt: timestamppb.New(user.CreatedAt), UpdatedAt: timestamppb.New(user.UpdatedAt), Version: user.Version, CreatedBy: user.CreatedBy, UpdatedBy: user.UpdatedBy}
}
