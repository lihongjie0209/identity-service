package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/audit"
	"github.com/lihongjie0209/microservice-platform-go/eventbus"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
	"go.uber.org/fx"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const refreshTTL = 30 * 24 * time.Hour
const loginFailureThreshold = 5
const loginLockDuration = 15 * time.Minute

type Service struct {
	repository      *Repository
	transactor      *database.Transactor
	hasher          *PasswordHasher
	issuer          *TokenIssuer
	mfa             *MFACrypto
	mfaChallengeTTL time.Duration
	now             func() time.Time
}

func NewService(repository *Repository, transactor *database.Transactor, cfg config.Config) (*Service, error) {
	hasher, err := NewPasswordHasher(DefaultPasswordParameters())
	if err != nil {
		return nil, err
	}
	seed := sha256.Sum256([]byte(cfg.JWT.Secret))
	keyID := cfg.JWT.KeyID
	if keyID == "" {
		keyID = "identity-current"
	}
	audiences := cfg.JWT.Audiences
	if len(audiences) == 0 {
		audiences = []string{cfg.App.Name}
	}
	issuer, err := NewTokenIssuer(cfg.JWT.Issuer, audiences, keyID, ed25519.NewKeyFromSeed(seed[:]), cfg.JWT.TTL)
	if err != nil {
		return nil, err
	}
	for previousKeyID, secret := range cfg.JWT.PreviousSecrets {
		previousSeed := sha256.Sum256([]byte(secret))
		previousPrivate := ed25519.NewKeyFromSeed(previousSeed[:])
		if err := issuer.AddVerificationKey(previousKeyID, previousPrivate.Public().(ed25519.PublicKey)); err != nil {
			return nil, err
		}
	}
	var mfa *MFACrypto
	if cfg.MFA.Enabled {
		mfa, err = NewMFACrypto(cfg.MFA.Issuer, cfg.MFA.EncryptionKey, cfg.MFA.RecoveryPepper)
		if err != nil {
			return nil, err
		}
	}
	return &Service{
		repository:      repository,
		transactor:      transactor,
		hasher:          hasher,
		issuer:          issuer,
		mfa:             mfa,
		mfaChallengeTTL: cfg.MFA.ChallengeTTL,
		now:             time.Now,
	}, nil
}

func (s *Service) Register(ctx context.Context, username, displayName, email, phone, password string) (User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	displayName = strings.TrimSpace(displayName)
	email = strings.ToLower(strings.TrimSpace(email))
	phone = strings.TrimSpace(phone)
	if username == "" || displayName == "" || email == "" {
		return User{}, apperror.Invalid("username, display_name, and email are required", nil)
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return User{}, apperror.Invalid(err.Error(), err)
	}
	fields, err := audit.New(ctx, s.now().UTC())
	if err != nil {
		return User{}, apperror.Unauthorized("authenticated actor is required")
	}
	user := User{ID: uuid.NewString(), Username: username, DisplayName: displayName, Email: email, Phone: phone, Status: StatusActive, Fields: fields}
	credential := Credential{ID: uuid.NewString(), UserID: user.ID, Type: "password", SecretHash: hash, Status: StatusActive, Fields: fields}
	event, err := newOutboxEvent(ctx, "platform.identity.user.created.v1", "platform.identity.v1.UserCreated", user.ID, fields.CreatedAt, &identityv1.UserCreatedEvent{User: protoIdentityUser(user)})
	if err != nil {
		return User{}, apperror.Internal(err)
	}
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.CreateUser(ctx, tx, user, credential); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return User{}, translateIdentityError(err)
	}
	return user, nil
}

func (s *Service) Login(ctx context.Context, login, password string, client SessionClient) (LoginResult, error) {
	login = strings.TrimSpace(login)
	if login == "" || password == "" {
		return LoginResult{}, apperror.Invalid("login and password are required", nil)
	}
	user, credential, err := s.repository.UserByLogin(ctx, login)
	if err != nil {
		return LoginResult{}, apperror.Unauthorized("invalid credentials")
	}
	now := s.now().UTC()
	if user.Status != StatusActive || (user.LockedUntil != nil && user.LockedUntil.After(now)) || credential.Status != StatusActive {
		return LoginResult{}, apperror.Unauthorized("account is unavailable")
	}
	valid, _, err := s.hasher.Verify(password, credential.SecretHash)
	if err != nil || !valid {
		_ = s.repository.RecordFailedLogin(ctx, user.ID, loginFailureThreshold, now.Add(loginLockDuration), now)
		return LoginResult{}, apperror.Unauthorized("invalid credentials")
	}
	if err := s.repository.ResetFailedLogin(ctx, user.ID, now); err != nil {
		return LoginResult{}, apperror.Internal(err)
	}
	enrollment, err := s.repository.GetMFA(ctx, user.ID)
	if err == nil && enrollment.Status == MFAStatusEnabled {
		if s.mfa == nil {
			return LoginResult{}, apperror.Unavailable("mfa verification is unavailable", nil)
		}
		return s.issueMFAChallenge(ctx, user.ID, client)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return LoginResult{}, translateIdentityError(err)
	}
	tokens, err := s.createSession(principal.SystemContext(ctx, "identity:login"), user.ID, "", "", client)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Tokens: tokens}, nil
}

func (s *Service) createSession(
	ctx context.Context,
	userID string,
	tenantID string,
	membershipID string,
	client SessionClient,
) (Tokens, error) {
	session, tokens, err := s.prepareSession(ctx, userID, tenantID, membershipID, client)
	if err != nil {
		return Tokens{}, err
	}
	if err := s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		return s.repository.CreateSession(ctx, tx, session)
	}); err != nil {
		return Tokens{}, translateIdentityError(err)
	}
	return tokens, nil
}

func (s *Service) prepareSession(
	ctx context.Context,
	userID string,
	tenantID string,
	membershipID string,
	client SessionClient,
) (Session, Tokens, error) {
	now := s.now().UTC()
	rawRefresh, refreshHash, err := newRefreshToken()
	if err != nil {
		return Session{}, Tokens{}, apperror.Internal(err)
	}
	fields, err := audit.New(ctx, now)
	if err != nil {
		return Session{}, Tokens{}, apperror.Unauthorized("authenticated actor is required")
	}
	session := Session{
		ID:               uuid.NewString(),
		UserID:           userID,
		RefreshTokenHash: refreshHash,
		TenantID:         tenantID,
		MembershipID:     membershipID,
		ExpiresAt:        now.Add(refreshTTL),
		LastUsedAt:       now,
		ClientIP:         truncateUTF8(strings.TrimSpace(client.IP), 128),
		UserAgent:        truncateUTF8(strings.TrimSpace(client.UserAgent), 1024),
		Fields:           fields,
	}
	access, expiresAt, err := s.issuer.Issue(userID, "user", session.ID, tenantID, membershipID)
	if err != nil {
		return Session{}, Tokens{}, apperror.Internal(err)
	}
	return session, Tokens{
		AccessToken:  access,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
		SessionID:    session.ID,
	}, nil
}

func truncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	for maxBytes > 0 && !utf8.ValidString(value[:maxBytes]) {
		maxBytes--
	}
	return value[:maxBytes]
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	hash := hashRefreshToken(refreshToken)
	if refreshToken == "" {
		return Tokens{}, apperror.Unauthorized("invalid refresh token")
	}
	session, err := s.repository.SessionByRefreshHash(ctx, hash)
	if err != nil || session.RevokedAt != nil || !session.ExpiresAt.After(s.now().UTC()) {
		return Tokens{}, apperror.Unauthorized("invalid refresh token")
	}
	user, err := s.repository.GetUser(ctx, session.UserID)
	if err != nil || user.Status != StatusActive {
		return Tokens{}, apperror.Unauthorized("account is unavailable")
	}
	rawRefresh, newHash, err := newRefreshToken()
	if err != nil {
		return Tokens{}, apperror.Internal(err)
	}
	now := s.now().UTC()
	session.RefreshTokenHash = newHash
	session.LastUsedAt = now
	session.UpdatedAt = now
	session.UpdatedBy = session.UserID
	access, expiresAt, err := s.issuer.Issue(user.ID, "user", session.ID, session.TenantID, session.MembershipID)
	if err != nil {
		return Tokens{}, apperror.Internal(err)
	}
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error { return s.repository.RotateSession(ctx, tx, session, hash) })
	if err != nil {
		return Tokens{}, apperror.Unauthorized("refresh token was already used")
	}
	return Tokens{AccessToken: access, RefreshToken: rawRefresh, TokenType: "Bearer", ExpiresAt: expiresAt, SessionID: session.ID}, nil
}

func (s *Service) Logout(ctx context.Context, sessionID, reason string) error {
	actor, err := principal.Require(ctx)
	if err != nil {
		return apperror.Unauthorized("authenticated actor is required")
	}
	if reason == "" {
		reason = "logout"
	}
	now := s.now().UTC()
	session, err := s.repository.GetSession(ctx, sessionID, actor.ID)
	if err != nil {
		return translateIdentityError(err)
	}
	event, err := newOutboxEvent(ctx, "platform.identity.session.revoked.v1", "platform.identity.v1.SessionRevoked", session.ID, now, &identityv1.SessionRevokedEvent{SessionId: session.ID, UserId: session.UserID, TenantId: session.TenantID, Reason: reason})
	if err != nil {
		return apperror.Internal(err)
	}
	if err := s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.RevokeSession(ctx, tx, sessionID, actor.ID, reason, actor.ID, now); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	}); err != nil {
		return translateIdentityError(err)
	}
	return nil
}

func (s *Service) ChangePassword(ctx context.Context, currentPassword, newPassword string) (uint64, error) {
	actor, err := principal.Require(ctx)
	if err != nil || actor.Type != principal.TypeUser || actor.SessionID == "" {
		return 0, apperror.Unauthorized("authenticated user session is required")
	}
	credential, err := s.repository.PasswordCredential(ctx, actor.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, apperror.Unauthorized("current password is invalid")
		}
		return 0, translateIdentityError(err)
	}
	if credential.Status != StatusActive {
		return 0, apperror.Unauthorized("current password is invalid")
	}
	valid, _, err := s.hasher.Verify(currentPassword, credential.SecretHash)
	if err != nil || !valid {
		return 0, apperror.Unauthorized("current password is invalid")
	}
	samePassword, _, err := s.hasher.Verify(newPassword, credential.SecretHash)
	if err != nil {
		return 0, apperror.Invalid("new password is invalid", err)
	}
	if samePassword {
		return 0, apperror.Invalid("new password must differ from current password", nil)
	}
	secretHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return 0, apperror.Invalid(err.Error(), err)
	}

	now := s.now().UTC()
	var revokedSessions uint64
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.UpdatePasswordCredential(
			ctx,
			tx,
			credential.ID,
			secretHash,
			actor.ID,
			credential.Version,
			now,
		); err != nil {
			return err
		}
		count, err := s.repository.RevokeOtherSessions(
			ctx,
			tx,
			actor.ID,
			actor.SessionID,
			"password changed",
			actor.ID,
			now,
		)
		if err != nil {
			return err
		}
		revokedSessions = count
		event, err := newOutboxEvent(
			ctx,
			"platform.identity.user.password-changed.v1",
			"platform.identity.v1.PasswordChanged",
			actor.ID,
			now,
			&identityv1.PasswordChangedEvent{
				UserId:          actor.ID,
				RevokedSessions: count,
				ChangeType:      identityv1.PasswordChangeType_PASSWORD_CHANGE_TYPE_SELF_SERVICE,
				Reason:          "user changed password",
			},
		)
		if err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return 0, translateIdentityError(err)
	}
	return revokedSessions, nil
}

func (s *Service) GetUser(ctx context.Context, id string) (User, error) {
	user, err := s.repository.GetUser(ctx, id)
	return user, translateIdentityError(err)
}
func (s *Service) ListUsers(ctx context.Context, keyword, status string, page, pageSize int) (Page[User], error) {
	if status != "" && status != StatusActive && status != StatusDisabled && status != StatusLocked && status != StatusClosed {
		return Page[User]{}, apperror.Invalid("invalid user status", nil)
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	items, total, err := s.repository.ListUsers(ctx, keyword, status, pageSize, (page-1)*pageSize)
	if err != nil {
		return Page[User]{}, translateIdentityError(err)
	}
	return Page[User]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}
func (s *Service) UpdateUserStatus(ctx context.Context, id, status, reason string, version int64) (User, error) {
	if status != StatusActive && status != StatusDisabled && status != StatusLocked && status != StatusClosed {
		return User{}, apperror.Invalid("invalid user status", nil)
	}
	actor, err := principal.Require(ctx)
	if err != nil {
		return User{}, apperror.Unauthorized("authenticated actor is required")
	}
	current, err := s.repository.GetUser(ctx, id)
	if err != nil {
		return User{}, translateIdentityError(err)
	}
	now := s.now().UTC()
	event, err := newOutboxEvent(ctx, "platform.identity.user.status-changed.v1", "platform.identity.v1.UserStatusChanged", id, now, &identityv1.UserStatusChangedEvent{UserId: id, PreviousStatus: identityv1.UserStatus(identityv1.UserStatus_value["USER_STATUS_"+strings.ToUpper(current.Status)]), CurrentStatus: identityv1.UserStatus(identityv1.UserStatus_value["USER_STATUS_"+strings.ToUpper(status)]), Reason: reason})
	if err != nil {
		return User{}, apperror.Internal(err)
	}
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.UpdateUserStatus(ctx, tx, id, status, actor.ID, version, now); err != nil {
			return err
		}
		if status != StatusActive {
			if _, err := s.repository.RevokeUserSessions(
				ctx,
				tx,
				id,
				"user status changed to "+status,
				actor.ID,
				now,
			); err != nil {
				return err
			}
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return User{}, translateIdentityError(err)
	}
	return s.repository.GetUser(ctx, id)
}

func (s *Service) UpdateUserProfile(
	ctx context.Context,
	id string,
	displayName string,
	email string,
	phone string,
	reason string,
	version int64,
) (User, error) {
	id = strings.TrimSpace(id)
	displayName = strings.TrimSpace(displayName)
	email = strings.ToLower(strings.TrimSpace(email))
	phone = strings.TrimSpace(phone)
	reason = strings.TrimSpace(reason)
	if id == "" || displayName == "" || email == "" || reason == "" || version < 1 {
		return User{}, apperror.Invalid("id, display_name, email, reason, and a positive version are required", nil)
	}
	actor, err := principal.Require(ctx)
	if err != nil {
		return User{}, apperror.Unauthorized("authenticated actor is required")
	}
	current, err := s.repository.GetUser(ctx, id)
	if err != nil {
		return User{}, translateIdentityError(err)
	}
	now := s.now().UTC()
	updated := current
	updated.DisplayName = displayName
	updated.Email = email
	updated.Phone = phone
	updated.Version = version + 1
	updated.UpdatedAt = now
	updated.UpdatedBy = actor.ID
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.user.profile-updated.v1",
		"platform.identity.v1.UserProfileUpdated",
		id,
		now,
		&identityv1.UserProfileUpdatedEvent{User: protoIdentityUser(updated), Reason: reason},
	)
	if err != nil {
		return User{}, apperror.Internal(err)
	}
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.UpdateUserProfile(ctx, tx, id, displayName, email, phone, actor.ID, version, now); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return User{}, translateIdentityError(err)
	}
	return s.repository.GetUser(ctx, id)
}
func (s *Service) BatchGetUsers(ctx context.Context, ids []string) ([]User, error) {
	users, err := s.repository.BatchGetUsers(ctx, ids)
	return users, translateIdentityError(err)
}
func (s *Service) ValidateSession(ctx context.Context, id, userID string) (Session, bool, error) {
	session, err := s.repository.GetSession(ctx, id, userID)
	if errors.Is(err, ErrNotFound) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, translateIdentityError(err)
	}
	return session, session.RevokedAt == nil && session.ExpiresAt.After(s.now().UTC()), nil
}
func (s *Service) ListSessions(
	ctx context.Context,
	userID string,
	tenantID string,
	status string,
	page int,
	pageSize int,
) (Page[Session], error) {
	if status != "" && status != "active" && status != "revoked" && status != "expired" {
		return Page[Session]{}, apperror.Invalid("invalid session status", nil)
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	items, total, err := s.repository.ListSessions(
		ctx,
		strings.TrimSpace(userID),
		strings.TrimSpace(tenantID),
		status,
		s.now().UTC(),
		pageSize,
		(page-1)*pageSize,
	)
	if err != nil {
		return Page[Session]{}, translateIdentityError(err)
	}
	return Page[Session]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *Service) ListOwnSessions(ctx context.Context, status string, page, pageSize int) (Page[Session], error) {
	actor, err := principal.Require(ctx)
	if err != nil || actor.Type != principal.TypeUser {
		return Page[Session]{}, apperror.Unauthorized("authenticated user is required")
	}
	return s.ListSessions(ctx, actor.ID, "", status, page, pageSize)
}

func (s *Service) RevokeOwnSessionByID(
	ctx context.Context,
	id string,
	reason string,
	version int64,
) (Session, error) {
	actor, err := principal.Require(ctx)
	if err != nil || actor.Type != principal.TypeUser {
		return Session{}, apperror.Unauthorized("authenticated user is required")
	}
	id = strings.TrimSpace(id)
	current, err := s.repository.GetSession(ctx, id, actor.ID)
	if err != nil {
		return Session{}, translateIdentityError(err)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "user security revocation"
	}
	now := s.now().UTC()
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.session.revoked.v1",
		"platform.identity.v1.SessionRevoked",
		current.ID,
		now,
		&identityv1.SessionRevokedEvent{
			SessionId: current.ID,
			UserId:    current.UserID,
			TenantId:  current.TenantID,
			Reason:    reason,
		},
	)
	if err != nil {
		return Session{}, apperror.Internal(err)
	}
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.RevokeOwnedSessionByID(
			ctx,
			tx,
			current.ID,
			actor.ID,
			reason,
			actor.ID,
			version,
			now,
		); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return Session{}, translateIdentityError(err)
	}
	return s.repository.GetSession(ctx, current.ID, actor.ID)
}

func (s *Service) RevokeSessionByID(ctx context.Context, id, reason string, version int64) (Session, error) {
	actor, err := principal.Require(ctx)
	if err != nil {
		return Session{}, apperror.Unauthorized("authenticated actor is required")
	}
	current, err := s.repository.GetSessionByID(ctx, strings.TrimSpace(id))
	if err != nil {
		return Session{}, translateIdentityError(err)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "administrative revocation"
	}
	now := s.now().UTC()
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.session.revoked.v1",
		"platform.identity.v1.SessionRevoked",
		current.ID,
		now,
		&identityv1.SessionRevokedEvent{
			SessionId: current.ID,
			UserId:    current.UserID,
			TenantId:  current.TenantID,
			Reason:    reason,
		},
	)
	if err != nil {
		return Session{}, apperror.Internal(err)
	}
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.RevokeSessionByID(
			ctx,
			tx,
			current.ID,
			reason,
			actor.ID,
			version,
			now,
		); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return Session{}, translateIdentityError(err)
	}
	return s.repository.GetSessionByID(ctx, current.ID)
}
func (s *Service) RevokeTenantSessions(ctx context.Context, userID, tenantID, reason string) (uint64, error) {
	actor, err := principal.Require(ctx)
	if err != nil {
		return 0, apperror.Unauthorized("authenticated actor is required")
	}
	count, err := s.repository.RevokeTenantSessions(ctx, userID, tenantID, reason, actor.ID, s.now().UTC())
	return count, translateIdentityError(err)
}
func (s *Service) IssueTenantToken(ctx context.Context, userID, tenantID, membershipID, sessionID string) (string, time.Time, error) {
	actor, err := principal.Require(ctx)
	if err != nil {
		return "", time.Time{}, apperror.Unauthorized("authenticated actor is required")
	}
	if actor.Type != principal.TypeServiceAccount && actor.Type != principal.TypeSystem {
		return "", time.Time{}, apperror.New(apperror.CodeForbidden, "tenant tokens may only be issued by a trusted service", 403, nil)
	}
	userID, tenantID, membershipID, sessionID = strings.TrimSpace(userID), strings.TrimSpace(tenantID), strings.TrimSpace(membershipID), strings.TrimSpace(sessionID)
	if userID == "" || tenantID == "" || membershipID == "" || sessionID == "" {
		return "", time.Time{}, apperror.Invalid("user_id, tenant_id, membership_id, and session_id are required", nil)
	}
	token, expiresAt, err := s.issuer.Issue(userID, "user", sessionID, tenantID, membershipID)
	if err != nil {
		return "", time.Time{}, apperror.Internal(err)
	}
	now := s.now().UTC()
	if err := s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		return s.repository.ScopeSession(ctx, tx, sessionID, userID, tenantID, membershipID, actor.ID, now)
	}); err != nil {
		return "", time.Time{}, translateIdentityError(err)
	}
	return token, expiresAt, nil
}
func (s *Service) GetServiceAccount(ctx context.Context, id string) (ServiceAccount, error) {
	account, err := s.repository.GetServiceAccount(ctx, id)
	if err == nil {
		if decodeErr := decodeServiceAccountAudiences(&account); decodeErr != nil {
			return ServiceAccount{}, apperror.Internal(decodeErr)
		}
	}
	return account, translateIdentityError(err)
}

func (s *Service) ListServiceAccounts(
	ctx context.Context,
	keyword string,
	status string,
	page int,
	pageSize int,
) (Page[ServiceAccount], error) {
	if status != "" && status != StatusActive && status != StatusDisabled {
		return Page[ServiceAccount]{}, apperror.Invalid("invalid service account status", nil)
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	items, total, err := s.repository.ListServiceAccounts(
		ctx,
		keyword,
		status,
		pageSize,
		(page-1)*pageSize,
	)
	if err != nil {
		return Page[ServiceAccount]{}, translateIdentityError(err)
	}
	for index := range items {
		if err := decodeServiceAccountAudiences(&items[index]); err != nil {
			return Page[ServiceAccount]{}, apperror.Internal(err)
		}
	}
	return Page[ServiceAccount]{Items: items, Total: total, Page: page, PageSize: pageSize}, nil
}
func (s *Service) CreateServiceAccount(ctx context.Context, name string, audiences []string) (ServiceAccount, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(audiences) == 0 {
		return ServiceAccount{}, "", apperror.Invalid("name and audiences are required", nil)
	}
	fields, err := audit.New(ctx, s.now().UTC())
	if err != nil {
		return ServiceAccount{}, "", apperror.Unauthorized("authenticated actor is required")
	}
	secret, hash, err := s.newServiceAccountSecret()
	if err != nil {
		return ServiceAccount{}, "", apperror.Internal(err)
	}
	encoded, err := json.Marshal(audiences)
	if err != nil {
		return ServiceAccount{}, "", apperror.Invalid("invalid audiences", err)
	}
	account := ServiceAccount{ID: uuid.NewString(), ClientID: "svc_" + uuid.NewString(), Name: name, SecretHash: hash, Status: StatusActive, AudiencesJSON: string(encoded), Audiences: audiences, Fields: fields}
	event, err := newOutboxEvent(ctx, "platform.identity.service-account.status-changed.v1", "platform.identity.v1.ServiceAccountStatusChanged", account.ID, fields.CreatedAt, &identityv1.ServiceAccountStatusChangedEvent{ServiceAccountId: account.ID, CurrentStatus: StatusActive, Reason: "created"})
	if err != nil {
		return ServiceAccount{}, "", apperror.Internal(err)
	}
	if err := s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.CreateServiceAccount(ctx, tx, account); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	}); err != nil {
		return ServiceAccount{}, "", translateIdentityError(err)
	}
	return account, secret, nil
}

func (s *Service) RotateServiceAccountSecret(ctx context.Context, id string, version int64) (string, int64, error) {
	id = strings.TrimSpace(id)
	if id == "" || version < 1 {
		return "", 0, apperror.Invalid("service account id and version are required", nil)
	}
	actor, err := principal.Require(ctx)
	if err != nil {
		return "", 0, apperror.Unauthorized("authenticated actor is required")
	}
	secret, hash, err := s.newServiceAccountSecret()
	if err != nil {
		return "", 0, apperror.Internal(err)
	}
	now := s.now().UTC()
	nextVersion := version + 1
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.service-account.secret-rotated.v1",
		"platform.identity.v1.ServiceAccountSecretRotated",
		id,
		now,
		&identityv1.ServiceAccountSecretRotatedEvent{ServiceAccountId: id, Version: nextVersion},
	)
	if err != nil {
		return "", 0, apperror.Internal(err)
	}
	if err := s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.RotateServiceAccountSecret(ctx, tx, id, hash, actor.ID, version, now); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	}); err != nil {
		return "", 0, translateIdentityError(err)
	}
	return secret, nextVersion, nil
}

func (s *Service) newServiceAccountSecret() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate service account secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := s.hasher.Hash(secret)
	if err != nil {
		return "", "", fmt.Errorf("hash service account secret: %w", err)
	}
	return secret, hash, nil
}

func (s *Service) UpdateServiceAccountStatus(ctx context.Context, id, status string, version int64) error {
	if status != StatusActive && status != StatusDisabled {
		return apperror.Invalid("status must be active or disabled", nil)
	}
	actor, err := principal.Require(ctx)
	if err != nil {
		return apperror.Unauthorized("authenticated actor is required")
	}
	current, err := s.repository.GetServiceAccount(ctx, id)
	if err != nil {
		return translateIdentityError(err)
	}
	now := s.now().UTC()
	event, err := newOutboxEvent(ctx, "platform.identity.service-account.status-changed.v1", "platform.identity.v1.ServiceAccountStatusChanged", id, now, &identityv1.ServiceAccountStatusChangedEvent{ServiceAccountId: id, PreviousStatus: current.Status, CurrentStatus: status, Reason: "administrative update"})
	if err != nil {
		return apperror.Internal(err)
	}
	return translateIdentityError(s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.UpdateServiceAccountStatus(ctx, tx, id, status, actor.ID, version, now); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	}))
}
func (s *Service) ServiceAccountToken(ctx context.Context, clientID, secret string) (string, time.Time, error) {
	account, err := s.repository.ServiceAccountByClientID(ctx, clientID)
	if err != nil || account.Status != StatusActive {
		return "", time.Time{}, apperror.Unauthorized("invalid service credentials")
	}
	valid, _, verifyErr := s.hasher.Verify(secret, account.SecretHash)
	if verifyErr != nil || !valid {
		return "", time.Time{}, apperror.Unauthorized("invalid service credentials")
	}
	return s.issuer.Issue(account.ID, "service_account", "", "", "")
}
func (s *Service) JWKS() JWKS                             { return s.issuer.JWKS() }
func (s *Service) Parse(raw string) (*TokenClaims, error) { return s.issuer.Parse(raw) }

func decodeServiceAccountAudiences(account *ServiceAccount) error {
	if err := json.Unmarshal([]byte(account.AudiencesJSON), &account.Audiences); err != nil {
		return fmt.Errorf("decode service account audiences: %w", err)
	}
	if account.Audiences == nil {
		account.Audiences = []string{}
	}
	return nil
}

func newRefreshToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, hashRefreshToken(token), nil
}
func hashRefreshToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func translateIdentityError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return apperror.NotFound("identity resource not found")
	case errors.Is(err, ErrConflict):
		return apperror.Conflict("identity resource already exists", err)
	case errors.Is(err, ErrStale):
		return apperror.StaleVersion(err)
	default:
		return apperror.Internal(err)
	}
}

func newOutboxEvent(ctx context.Context, subject, eventType, aggregateID string, occurredAt time.Time, payload proto.Message) (OutboxEvent, error) {
	actor, err := principal.Require(ctx)
	if err != nil {
		return OutboxEvent{}, err
	}
	id := uuid.NewString()
	envelope, err := eventbus.NewEnvelope(eventbus.Metadata{EventID: id, EventType: eventType, AggregateID: aggregateID, AggregateType: "identity", SchemaVersion: 1, ActorID: actor.ID, ActorType: string(actor.Type), OccurredAt: occurredAt}, payload)
	if err != nil {
		return OutboxEvent{}, err
	}
	encoded, err := proto.Marshal(envelope)
	if err != nil {
		return OutboxEvent{}, err
	}
	return OutboxEvent{ID: id, Subject: subject, Envelope: encoded, AvailableAt: occurredAt, Fields: audit.Fields{Version: 1, CreatedAt: occurredAt, UpdatedAt: occurredAt, CreatedBy: actor.ID, UpdatedBy: actor.ID}}, nil
}

func protoIdentityUser(user User) *identityv1.User {
	statuses := map[string]identityv1.UserStatus{StatusActive: identityv1.UserStatus_USER_STATUS_ACTIVE, StatusDisabled: identityv1.UserStatus_USER_STATUS_DISABLED, StatusLocked: identityv1.UserStatus_USER_STATUS_LOCKED, StatusClosed: identityv1.UserStatus_USER_STATUS_CLOSED}
	return &identityv1.User{Id: user.ID, Username: user.Username, DisplayName: user.DisplayName, Email: user.Email, Phone: user.Phone, Status: statuses[user.Status], CreatedAt: timestamppb.New(user.CreatedAt), UpdatedAt: timestamppb.New(user.UpdatedAt), Version: user.Version, CreatedBy: user.CreatedBy, UpdatedBy: user.UpdatedBy}
}

var Module = fx.Module("identity", fx.Provide(NewRepository, NewService, NewSessionCleaner), fx.Invoke(func(*SessionCleaner) {}))
