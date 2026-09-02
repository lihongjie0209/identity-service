package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/microservice-platform-go/audit"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
)

const passwordResetTTL = 30 * time.Minute

func (s *Service) IssuePasswordReset(
	ctx context.Context,
	userID string,
	reason string,
) (PasswordResetIssue, error) {
	actor, err := principal.Require(ctx)
	if err != nil {
		return PasswordResetIssue{}, apperror.Unauthorized("authenticated actor is required")
	}
	userID = strings.TrimSpace(userID)
	reason = strings.TrimSpace(reason)
	if userID == "" || reason == "" {
		return PasswordResetIssue{}, apperror.Invalid("user_id and reason are required", nil)
	}
	if actor.Type == principal.TypeUser && actor.ID == userID {
		return PasswordResetIssue{}, apperror.Invalid("use self-service password change for the current user", nil)
	}
	user, err := s.repository.GetUser(ctx, userID)
	if err != nil {
		return PasswordResetIssue{}, translateIdentityError(err)
	}
	if user.Status != StatusActive {
		return PasswordResetIssue{}, apperror.Invalid("password reset requires an active user", nil)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PasswordResetIssue{}, apperror.Internal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	fields, err := audit.New(ctx, now)
	if err != nil {
		return PasswordResetIssue{}, apperror.Unauthorized("authenticated actor is required")
	}
	challenge := PasswordResetChallenge{
		TokenHash: hashPasswordResetToken(token),
		UserID:    userID,
		Reason:    reason,
		ExpiresAt: now.Add(passwordResetTTL),
		Fields:    fields,
	}
	if err := s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.InvalidatePasswordResetChallenges(ctx, tx, userID, actor.ID, now); err != nil {
			return err
		}
		return s.repository.InsertPasswordResetChallenge(ctx, tx, challenge)
	}); err != nil {
		return PasswordResetIssue{}, translateIdentityError(err)
	}
	return PasswordResetIssue{ResetToken: token, ExpiresAt: challenge.ExpiresAt}, nil
}

func (s *Service) ConfirmPasswordReset(
	ctx context.Context,
	resetToken string,
	newPassword string,
) (PasswordResetResult, error) {
	resetToken = strings.TrimSpace(resetToken)
	if resetToken == "" {
		return PasswordResetResult{}, apperror.Invalid("reset_token is required", nil)
	}
	secretHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return PasswordResetResult{}, apperror.Invalid(err.Error(), err)
	}
	tokenHash := hashPasswordResetToken(resetToken)
	challenge, err := s.repository.GetPasswordResetChallenge(ctx, tokenHash)
	if err != nil {
		return PasswordResetResult{}, apperror.Unauthorized("invalid or expired password reset token")
	}
	now := s.now().UTC()
	if challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(now) {
		return PasswordResetResult{}, apperror.Unauthorized("invalid or expired password reset token")
	}
	user, err := s.repository.GetUser(ctx, challenge.UserID)
	if err != nil || user.Status != StatusActive {
		return PasswordResetResult{}, apperror.Unauthorized("account is unavailable")
	}
	credential, err := s.repository.PasswordCredential(ctx, challenge.UserID)
	if err != nil || credential.Status != StatusActive {
		return PasswordResetResult{}, apperror.Unauthorized("account is unavailable")
	}
	samePassword, _, err := s.hasher.Verify(newPassword, credential.SecretHash)
	if err != nil {
		return PasswordResetResult{}, apperror.Internal(err)
	}
	if samePassword {
		return PasswordResetResult{}, apperror.Invalid("new password must differ from current password", nil)
	}
	resetContext := principal.SystemContext(ctx, "identity:password-reset")
	var revokedSessions uint64
	err = s.transactor.Within(resetContext, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.ConsumePasswordResetChallenge(
			resetContext,
			tx,
			tokenHash,
			challenge.Version,
			"identity:password-reset",
			now,
		); err != nil {
			return err
		}
		if err := s.repository.UpdatePasswordCredential(
			resetContext,
			tx,
			credential.ID,
			secretHash,
			"identity:password-reset",
			credential.Version,
			now,
		); err != nil {
			return err
		}
		revokedSessions, err = s.repository.RevokeUserSessions(
			resetContext,
			tx,
			challenge.UserID,
			"password administratively recovered",
			"identity:password-reset",
			now,
		)
		if err != nil {
			return err
		}
		event, err := newOutboxEvent(
			resetContext,
			"platform.identity.user.password-changed.v1",
			"platform.identity.v1.PasswordChanged",
			challenge.UserID,
			now,
			&identityv1.PasswordChangedEvent{
				UserId:          challenge.UserID,
				RevokedSessions: revokedSessions,
				ChangeType:      identityv1.PasswordChangeType_PASSWORD_CHANGE_TYPE_ADMINISTRATIVE_RECOVERY,
				Reason:          challenge.Reason,
			},
		)
		if err != nil {
			return err
		}
		return s.repository.InsertOutbox(resetContext, tx, event)
	})
	if err != nil {
		if errors.Is(err, ErrStale) {
			return PasswordResetResult{}, apperror.Unauthorized("password reset token was already used")
		}
		return PasswordResetResult{}, translateIdentityError(err)
	}
	return PasswordResetResult{Changed: true, RevokedSessions: revokedSessions}, nil
}

func hashPasswordResetToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
