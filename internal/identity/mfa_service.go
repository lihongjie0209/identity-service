package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/microservice-platform-go/audit"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
)

const mfaSetupTTL = 10 * time.Minute

func (s *Service) issueMFAChallenge(
	ctx context.Context,
	userID string,
	client SessionClient,
) (LoginResult, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return LoginResult{}, apperror.Internal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := hashMFAChallengeToken(token)
	now := s.now().UTC()
	expiresAt := now.Add(s.mfaChallengeTTL)
	challengeContext := principal.SystemContext(ctx, "identity:login")
	fields, err := audit.New(challengeContext, now)
	if err != nil {
		return LoginResult{}, apperror.Internal(err)
	}
	challenge := MFALoginChallenge{
		TokenHash: tokenHash,
		UserID:    userID,
		ClientIP:  truncateUTF8(strings.TrimSpace(client.IP), 128),
		UserAgent: truncateUTF8(strings.TrimSpace(client.UserAgent), 1024),
		ExpiresAt: expiresAt,
		Fields:    fields,
	}
	if err := s.transactor.Within(challengeContext, nil, func(tx *sqlx.Tx) error {
		return s.repository.InsertMFAChallenge(challengeContext, tx, challenge)
	}); err != nil {
		return LoginResult{}, translateIdentityError(err)
	}
	return LoginResult{
		MFARequired:        true,
		MFAChallengeToken:  token,
		MFAChallengeExpiry: &expiresAt,
	}, nil
}

func (s *Service) VerifyMFAChallenge(
	ctx context.Context,
	challengeToken string,
	code string,
	recoveryCode string,
) (Tokens, error) {
	if s.mfa == nil {
		return Tokens{}, apperror.Unavailable("mfa verification is unavailable", nil)
	}
	challengeToken = strings.TrimSpace(challengeToken)
	code = strings.TrimSpace(code)
	recoveryCode = strings.TrimSpace(recoveryCode)
	if challengeToken == "" || (code == "") == (recoveryCode == "") {
		return Tokens{}, apperror.Invalid("challenge_token and exactly one verification code are required", nil)
	}
	tokenHash := hashMFAChallengeToken(challengeToken)
	challenge, err := s.repository.GetMFAChallenge(ctx, tokenHash)
	if err != nil {
		return Tokens{}, apperror.Unauthorized("invalid or expired mfa challenge")
	}
	now := s.now().UTC()
	if challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(now) {
		return Tokens{}, apperror.Unauthorized("invalid or expired mfa challenge")
	}
	user, err := s.repository.GetUser(ctx, challenge.UserID)
	if err != nil || user.Status != StatusActive {
		return Tokens{}, apperror.Unauthorized("account is unavailable")
	}
	enrollment, err := s.repository.GetMFA(ctx, challenge.UserID)
	if err != nil || enrollment.Status != MFAStatusEnabled {
		return Tokens{}, apperror.Unauthorized("mfa is not enabled")
	}
	verifyContext := principal.SystemContext(ctx, "identity:mfa")
	var step int64
	var recoveryHash string
	if code != "" {
		secret, decryptErr := s.mfa.DecryptSecret(challenge.UserID, enrollment.SecretCiphertext)
		if decryptErr != nil {
			return Tokens{}, apperror.Internal(decryptErr)
		}
		var valid bool
		step, valid = s.mfa.ValidateTOTP(secret, code, now)
		if !valid || step <= enrollment.LastUsedStep {
			return Tokens{}, apperror.Unauthorized("invalid or already used mfa code")
		}
	} else {
		recoveryHash = s.mfa.RecoveryCodeHash(recoveryCode)
	}
	session, tokens, err := s.prepareSession(
		verifyContext,
		challenge.UserID,
		"",
		"",
		SessionClient{IP: challenge.ClientIP, UserAgent: challenge.UserAgent},
	)
	if err != nil {
		return Tokens{}, err
	}
	err = s.transactor.Within(verifyContext, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.ConsumeMFAChallenge(
			verifyContext,
			tx,
			tokenHash,
			"identity:mfa",
			challenge.Version,
			now,
		); err != nil {
			return err
		}
		if recoveryHash != "" {
			if err := s.repository.ConsumeRecoveryCode(
				verifyContext,
				tx,
				challenge.UserID,
				recoveryHash,
				"identity:mfa",
				now,
			); err != nil {
				return err
			}
		} else if err := s.repository.AdvanceMFAStep(
			verifyContext,
			tx,
			challenge.UserID,
			step,
			"identity:mfa",
			now,
		); err != nil {
			return err
		}
		return s.repository.CreateSession(verifyContext, tx, session)
	})
	if err != nil {
		if errors.Is(err, ErrStale) {
			return Tokens{}, apperror.Unauthorized("invalid or already used mfa verification")
		}
		return Tokens{}, translateIdentityError(err)
	}
	return tokens, nil
}

func hashMFAChallengeToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *Service) MFAStatus(ctx context.Context) (MFAStatus, error) {
	actor, err := requireMFAUser(ctx)
	if err != nil {
		return MFAStatus{}, err
	}
	if s.mfa == nil {
		return MFAStatus{Available: false, Status: MFAStatusDisabled}, nil
	}
	enrollment, err := s.repository.GetMFA(ctx, actor.ID)
	if errors.Is(err, ErrNotFound) {
		return MFAStatus{Available: true, Status: MFAStatusDisabled}, nil
	}
	if err != nil {
		return MFAStatus{}, translateIdentityError(err)
	}
	remaining := int64(0)
	if enrollment.Status == MFAStatusEnabled {
		remaining, err = s.repository.CountRecoveryCodes(ctx, actor.ID)
		if err != nil {
			return MFAStatus{}, translateIdentityError(err)
		}
	}
	return MFAStatus{
		Available:              true,
		Enabled:                enrollment.Status == MFAStatusEnabled,
		Status:                 enrollment.Status,
		RecoveryCodesRemaining: remaining,
		Version:                enrollment.Version,
		EnabledAt:              enrollment.EnabledAt,
	}, nil
}

func (s *Service) AdminMFAStatus(ctx context.Context, userID string) (MFAStatus, error) {
	if _, err := principal.Require(ctx); err != nil {
		return MFAStatus{}, apperror.Unauthorized("authenticated actor is required")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return MFAStatus{}, apperror.Invalid("user_id is required", nil)
	}
	if _, err := s.repository.GetUser(ctx, userID); err != nil {
		return MFAStatus{}, translateIdentityError(err)
	}
	enrollment, err := s.repository.GetMFA(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return MFAStatus{Available: true, Status: MFAStatusDisabled}, nil
	}
	if err != nil {
		return MFAStatus{}, translateIdentityError(err)
	}
	remaining := int64(0)
	if enrollment.Status == MFAStatusEnabled {
		remaining, err = s.repository.CountRecoveryCodes(ctx, userID)
		if err != nil {
			return MFAStatus{}, translateIdentityError(err)
		}
	}
	return MFAStatus{
		Available:              true,
		Enabled:                enrollment.Status == MFAStatusEnabled,
		Status:                 enrollment.Status,
		RecoveryCodesRemaining: remaining,
		Version:                enrollment.Version,
		EnabledAt:              enrollment.EnabledAt,
	}, nil
}

func (s *Service) StartMFASetup(ctx context.Context, currentPassword string) (MFASetup, error) {
	actor, err := requireMFAUser(ctx)
	if err != nil {
		return MFASetup{}, err
	}
	if s.mfa == nil {
		return MFASetup{}, apperror.Unavailable("mfa is not configured", nil)
	}
	if err := s.verifyCurrentPassword(ctx, actor.ID, currentPassword); err != nil {
		return MFASetup{}, err
	}
	user, err := s.repository.GetUser(ctx, actor.ID)
	if err != nil {
		return MFASetup{}, translateIdentityError(err)
	}
	secret, uri, err := s.mfa.GenerateTOTP(user.Email)
	if err != nil {
		return MFASetup{}, apperror.Internal(err)
	}
	encrypted, err := s.mfa.EncryptSecret(actor.ID, secret)
	if err != nil {
		return MFASetup{}, apperror.Internal(err)
	}
	now := s.now().UTC()
	fields, err := audit.New(ctx, now)
	if err != nil {
		return MFASetup{}, apperror.Unauthorized("authenticated actor is required")
	}
	current, getErr := s.repository.GetMFA(ctx, actor.ID)
	if getErr == nil && current.Status == MFAStatusEnabled {
		return MFASetup{}, apperror.Conflict("mfa is already enabled", nil)
	}
	if getErr != nil && !errors.Is(getErr, ErrNotFound) {
		return MFASetup{}, translateIdentityError(getErr)
	}
	version := int64(1)
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if errors.Is(getErr, ErrNotFound) {
			return s.repository.InsertMFA(ctx, tx, MFAEnrollment{
				UserID:           actor.ID,
				Method:           "totp",
				SecretCiphertext: encrypted,
				Status:           MFAStatusPending,
				LastUsedStep:     -1,
				Fields:           fields,
			})
		}
		if err := s.repository.ResetPendingMFA(
			ctx,
			tx,
			actor.ID,
			encrypted,
			actor.ID,
			current.Version,
			now,
		); err != nil {
			return err
		}
		version = current.Version + 1
		return s.repository.DeleteRecoveryCodes(ctx, tx, actor.ID)
	})
	if err != nil {
		return MFASetup{}, translateIdentityError(err)
	}
	return MFASetup{Secret: secret, URI: uri, Version: version, ExpiresAt: now.Add(mfaSetupTTL)}, nil
}

func (s *Service) ConfirmMFASetup(ctx context.Context, code string, version int64) (MFAConfirmation, error) {
	actor, err := requireMFAUser(ctx)
	if err != nil {
		return MFAConfirmation{}, err
	}
	if s.mfa == nil {
		return MFAConfirmation{}, apperror.Unavailable("mfa is not configured", nil)
	}
	enrollment, err := s.repository.GetMFA(ctx, actor.ID)
	if err != nil {
		return MFAConfirmation{}, translateIdentityError(err)
	}
	now := s.now().UTC()
	if enrollment.Status != MFAStatusPending || !enrollment.UpdatedAt.Add(mfaSetupTTL).After(now) {
		return MFAConfirmation{}, apperror.Invalid("mfa setup is not pending or has expired", nil)
	}
	secret, err := s.mfa.DecryptSecret(actor.ID, enrollment.SecretCiphertext)
	if err != nil {
		return MFAConfirmation{}, apperror.Internal(err)
	}
	step, valid := s.mfa.ValidateTOTP(secret, strings.TrimSpace(code), now)
	if !valid {
		return MFAConfirmation{}, apperror.Unauthorized("invalid mfa code")
	}
	codes, hashes, err := s.mfa.GenerateRecoveryCodes()
	if err != nil {
		return MFAConfirmation{}, apperror.Internal(err)
	}
	fields, err := audit.New(ctx, now)
	if err != nil {
		return MFAConfirmation{}, apperror.Unauthorized("authenticated actor is required")
	}
	recoveryCodes := make([]MFARecoveryCode, 0, len(hashes))
	for _, hash := range hashes {
		recoveryCodes = append(recoveryCodes, MFARecoveryCode{
			ID:       uuid.NewString(),
			UserID:   actor.ID,
			CodeHash: hash,
			Fields:   fields,
		})
	}
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.mfa.status-changed.v1",
		"platform.identity.v1.MFAStatusChanged",
		actor.ID,
		now,
		&identityv1.MFAStatusChangedEvent{
			UserId:                 actor.ID,
			Enabled:                true,
			RecoveryCodesRemaining: uint32(len(recoveryCodes)),
			ChangeType:             identityv1.MFAStatusChangeType_MFA_STATUS_CHANGE_TYPE_ENABLED,
			Reason:                 "user enabled mfa",
		},
	)
	if err != nil {
		return MFAConfirmation{}, apperror.Internal(err)
	}
	var revokedSessions uint64
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.EnableMFA(ctx, tx, actor.ID, step, actor.ID, version, now); err != nil {
			return err
		}
		if err := s.repository.ReplaceRecoveryCodes(ctx, tx, recoveryCodes); err != nil {
			return err
		}
		revokedSessions, err = s.repository.RevokeOtherSessions(
			ctx,
			tx,
			actor.ID,
			actor.SessionID,
			"mfa enabled",
			actor.ID,
			now,
		)
		if err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return MFAConfirmation{}, translateIdentityError(err)
	}
	return MFAConfirmation{RecoveryCodes: codes, RevokedSessions: revokedSessions, Version: version + 1}, nil
}

func (s *Service) DisableMFA(
	ctx context.Context,
	currentPassword string,
	code string,
	version int64,
) (uint64, error) {
	actor, err := requireMFAUser(ctx)
	if err != nil {
		return 0, err
	}
	if s.mfa == nil {
		return 0, apperror.Unavailable("mfa is not configured", nil)
	}
	if err := s.verifyCurrentPassword(ctx, actor.ID, currentPassword); err != nil {
		return 0, err
	}
	enrollment, err := s.repository.GetMFA(ctx, actor.ID)
	if err != nil {
		return 0, translateIdentityError(err)
	}
	if enrollment.Status != MFAStatusEnabled {
		return 0, apperror.Invalid("mfa is not enabled", nil)
	}
	secret, err := s.mfa.DecryptSecret(actor.ID, enrollment.SecretCiphertext)
	if err != nil {
		return 0, apperror.Internal(err)
	}
	now := s.now().UTC()
	step, valid := s.mfa.ValidateTOTP(secret, strings.TrimSpace(code), now)
	if !valid || step <= enrollment.LastUsedStep {
		return 0, apperror.Unauthorized("invalid or already used mfa code")
	}
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.mfa.status-changed.v1",
		"platform.identity.v1.MFAStatusChanged",
		actor.ID,
		now,
		&identityv1.MFAStatusChangedEvent{
			UserId:     actor.ID,
			Enabled:    false,
			ChangeType: identityv1.MFAStatusChangeType_MFA_STATUS_CHANGE_TYPE_DISABLED,
			Reason:     "user disabled mfa",
		},
	)
	if err != nil {
		return 0, apperror.Internal(err)
	}
	var revokedSessions uint64
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.DisableMFA(ctx, tx, actor.ID, step, actor.ID, version, now); err != nil {
			return err
		}
		if err := s.repository.DeleteRecoveryCodes(ctx, tx, actor.ID); err != nil {
			return err
		}
		revokedSessions, err = s.repository.RevokeOtherSessions(
			ctx,
			tx,
			actor.ID,
			actor.SessionID,
			"mfa disabled",
			actor.ID,
			now,
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

func (s *Service) RegenerateMFARecoveryCodes(
	ctx context.Context,
	currentPassword string,
	code string,
	version int64,
) (MFARecoveryRotation, error) {
	actor, err := requireMFAUser(ctx)
	if err != nil {
		return MFARecoveryRotation{}, err
	}
	if s.mfa == nil {
		return MFARecoveryRotation{}, apperror.Unavailable("mfa is not configured", nil)
	}
	if err := s.verifyCurrentPassword(ctx, actor.ID, currentPassword); err != nil {
		return MFARecoveryRotation{}, err
	}
	enrollment, err := s.repository.GetMFA(ctx, actor.ID)
	if err != nil {
		return MFARecoveryRotation{}, translateIdentityError(err)
	}
	if enrollment.Status != MFAStatusEnabled {
		return MFARecoveryRotation{}, apperror.Invalid("mfa is not enabled", nil)
	}
	secret, err := s.mfa.DecryptSecret(actor.ID, enrollment.SecretCiphertext)
	if err != nil {
		return MFARecoveryRotation{}, apperror.Internal(err)
	}
	now := s.now().UTC()
	step, valid := s.mfa.ValidateTOTP(secret, strings.TrimSpace(code), now)
	if !valid || step <= enrollment.LastUsedStep {
		return MFARecoveryRotation{}, apperror.Unauthorized("invalid or already used mfa code")
	}
	codes, hashes, err := s.mfa.GenerateRecoveryCodes()
	if err != nil {
		return MFARecoveryRotation{}, apperror.Internal(err)
	}
	fields, err := audit.New(ctx, now)
	if err != nil {
		return MFARecoveryRotation{}, apperror.Unauthorized("authenticated actor is required")
	}
	recoveryCodes := make([]MFARecoveryCode, 0, len(hashes))
	for _, hash := range hashes {
		recoveryCodes = append(recoveryCodes, MFARecoveryCode{
			ID:       uuid.NewString(),
			UserID:   actor.ID,
			CodeHash: hash,
			Fields:   fields,
		})
	}
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.mfa.status-changed.v1",
		"platform.identity.v1.MFAStatusChanged",
		actor.ID,
		now,
		&identityv1.MFAStatusChangedEvent{
			UserId:                 actor.ID,
			Enabled:                true,
			RecoveryCodesRemaining: uint32(len(recoveryCodes)),
			ChangeType:             identityv1.MFAStatusChangeType_MFA_STATUS_CHANGE_TYPE_RECOVERY_CODES_ROTATED,
			Reason:                 "user rotated mfa recovery codes",
		},
	)
	if err != nil {
		return MFARecoveryRotation{}, apperror.Internal(err)
	}
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.AdvanceMFAStepAtVersion(
			ctx,
			tx,
			actor.ID,
			step,
			actor.ID,
			version,
			now,
		); err != nil {
			return err
		}
		if err := s.repository.ReplaceRecoveryCodes(ctx, tx, recoveryCodes); err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return MFARecoveryRotation{}, translateIdentityError(err)
	}
	return MFARecoveryRotation{RecoveryCodes: codes, Version: version + 1}, nil
}

func (s *Service) AdminResetMFA(
	ctx context.Context,
	userID string,
	reason string,
	version int64,
) (AdminMFAResetResult, error) {
	actor, err := principal.Require(ctx)
	if err != nil {
		return AdminMFAResetResult{}, apperror.Unauthorized("authenticated actor is required")
	}
	userID = strings.TrimSpace(userID)
	reason = strings.TrimSpace(reason)
	if userID == "" || reason == "" || version < 1 {
		return AdminMFAResetResult{}, apperror.Invalid("user_id, reason, and version are required", nil)
	}
	if actor.Type == principal.TypeUser && actor.ID == userID {
		return AdminMFAResetResult{}, apperror.Invalid("use self-service mfa disable for the current user", nil)
	}
	enrollment, err := s.repository.GetMFA(ctx, userID)
	if err != nil {
		return AdminMFAResetResult{}, translateIdentityError(err)
	}
	if enrollment.Status != MFAStatusEnabled {
		return AdminMFAResetResult{}, apperror.Invalid("mfa is not enabled", nil)
	}
	now := s.now().UTC()
	event, err := newOutboxEvent(
		ctx,
		"platform.identity.mfa.status-changed.v1",
		"platform.identity.v1.MFAStatusChanged",
		userID,
		now,
		newAdministrativeMFAResetEvent(userID, reason),
	)
	if err != nil {
		return AdminMFAResetResult{}, apperror.Internal(err)
	}
	var revokedSessions uint64
	err = s.transactor.Within(ctx, nil, func(tx *sqlx.Tx) error {
		if err := s.repository.AdminResetMFA(ctx, tx, userID, actor.ID, version, now); err != nil {
			return err
		}
		if err := s.repository.DeleteRecoveryCodes(ctx, tx, userID); err != nil {
			return err
		}
		revokedSessions, err = s.repository.RevokeUserSessions(
			ctx,
			tx,
			userID,
			"mfa administratively reset: "+reason,
			actor.ID,
			now,
		)
		if err != nil {
			return err
		}
		return s.repository.InsertOutbox(ctx, tx, event)
	})
	if err != nil {
		return AdminMFAResetResult{}, translateIdentityError(err)
	}
	return AdminMFAResetResult{
		UserID:          userID,
		Reset:           true,
		RevokedSessions: revokedSessions,
		Version:         version + 1,
	}, nil
}

func newAdministrativeMFAResetEvent(userID, reason string) *identityv1.MFAStatusChangedEvent {
	return &identityv1.MFAStatusChangedEvent{
		UserId:     userID,
		Enabled:    false,
		ChangeType: identityv1.MFAStatusChangeType_MFA_STATUS_CHANGE_TYPE_ADMINISTRATIVE_RESET,
		Reason:     strings.TrimSpace(reason),
	}
}

func (s *Service) verifyCurrentPassword(ctx context.Context, userID, password string) error {
	credential, err := s.repository.PasswordCredential(ctx, userID)
	if err != nil || credential.Status != StatusActive {
		return apperror.Unauthorized("current password is invalid")
	}
	valid, _, err := s.hasher.Verify(password, credential.SecretHash)
	if err != nil || !valid {
		return apperror.Unauthorized("current password is invalid")
	}
	return nil
}

func requireMFAUser(ctx context.Context) (principal.Principal, error) {
	actor, err := principal.Require(ctx)
	if err != nil || actor.Type != principal.TypeUser || actor.SessionID == "" {
		return principal.Principal{}, apperror.Unauthorized("authenticated user session is required")
	}
	return actor, nil
}
