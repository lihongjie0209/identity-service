package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

const mfaColumns = "user_id, method, secret_ciphertext, status, last_used_step, enabled_at, version, created_at, updated_at, created_by, updated_by"

func (r *Repository) GetMFA(ctx context.Context, userID string) (MFAEnrollment, error) {
	var enrollment MFAEnrollment
	query := r.db.Rebind("SELECT " + mfaColumns + " FROM user_mfa WHERE user_id = ?")
	if err := r.db.GetContext(ctx, &enrollment, query, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MFAEnrollment{}, ErrNotFound
		}
		return MFAEnrollment{}, fmt.Errorf("select user mfa: %w", err)
	}
	return enrollment, nil
}

func (r *Repository) InsertMFA(ctx context.Context, tx *sqlx.Tx, enrollment MFAEnrollment) error {
	query := r.db.Rebind(
		"INSERT INTO user_mfa (user_id, method, secret_ciphertext, status, last_used_step, enabled_at, version, created_at, updated_at, created_by, updated_by) " +
			"VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
	)
	_, err := tx.ExecContext(
		ctx,
		query,
		enrollment.UserID,
		enrollment.Method,
		enrollment.SecretCiphertext,
		enrollment.Status,
		enrollment.LastUsedStep,
		enrollment.Version,
		enrollment.CreatedAt,
		enrollment.UpdatedAt,
		enrollment.CreatedBy,
		enrollment.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("insert user mfa: %w", err)
	}
	return nil
}

func (r *Repository) ResetPendingMFA(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	secretCiphertext string,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE user_mfa SET secret_ciphertext = ?, status = ?, last_used_step = -1, enabled_at = NULL, " +
			"version = version + 1, updated_at = ?, updated_by = ? WHERE user_id = ? AND status <> ? AND version = ?",
	)
	result, err := tx.ExecContext(
		ctx,
		query,
		secretCiphertext,
		MFAStatusPending,
		now,
		actor,
		userID,
		MFAStatusEnabled,
		version,
	)
	if err != nil {
		return fmt.Errorf("reset pending mfa: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) EnableMFA(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	step int64,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE user_mfa SET status = ?, last_used_step = ?, enabled_at = ?, version = version + 1, " +
			"updated_at = ?, updated_by = ? WHERE user_id = ? AND status = ? AND version = ?",
	)
	result, err := tx.ExecContext(
		ctx,
		query,
		MFAStatusEnabled,
		step,
		now,
		now,
		actor,
		userID,
		MFAStatusPending,
		version,
	)
	if err != nil {
		return fmt.Errorf("enable mfa: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) DisableMFA(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	step int64,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE user_mfa SET status = ?, last_used_step = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE user_id = ? AND status = ? AND last_used_step < ? AND version = ?",
	)
	result, err := tx.ExecContext(
		ctx,
		query,
		MFAStatusDisabled,
		step,
		now,
		actor,
		userID,
		MFAStatusEnabled,
		step,
		version,
	)
	if err != nil {
		return fmt.Errorf("disable mfa: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) ReplaceRecoveryCodes(
	ctx context.Context,
	tx *sqlx.Tx,
	codes []MFARecoveryCode,
) error {
	if len(codes) == 0 {
		return errors.New("replace recovery codes: codes are required")
	}
	deleteQuery := r.db.Rebind("DELETE FROM mfa_recovery_codes WHERE user_id = ?")
	if _, err := tx.ExecContext(ctx, deleteQuery, codes[0].UserID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	insertQuery := r.db.Rebind(
		"INSERT INTO mfa_recovery_codes (id, user_id, code_hash, consumed_at, version, created_at, updated_at, created_by, updated_by) " +
			"VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)",
	)
	for _, code := range codes {
		if _, err := tx.ExecContext(
			ctx,
			insertQuery,
			code.ID,
			code.UserID,
			code.CodeHash,
			code.Version,
			code.CreatedAt,
			code.UpdatedAt,
			code.CreatedBy,
			code.UpdatedBy,
		); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return nil
}

func (r *Repository) DeleteRecoveryCodes(ctx context.Context, tx *sqlx.Tx, userID string) error {
	query := r.db.Rebind("DELETE FROM mfa_recovery_codes WHERE user_id = ?")
	if _, err := tx.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	return nil
}

func (r *Repository) CountRecoveryCodes(ctx context.Context, userID string) (int64, error) {
	var count int64
	query := r.db.Rebind("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ? AND consumed_at IS NULL")
	if err := r.db.GetContext(ctx, &count, query, userID); err != nil {
		return 0, fmt.Errorf("count recovery codes: %w", err)
	}
	return count, nil
}

func (r *Repository) AdvanceMFAStep(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	step int64,
	actor string,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE user_mfa SET last_used_step = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE user_id = ? AND status = ? AND last_used_step < ?",
	)
	result, err := tx.ExecContext(ctx, query, step, now, actor, userID, MFAStatusEnabled, step)
	if err != nil {
		return fmt.Errorf("advance mfa step: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) ConsumeRecoveryCode(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	codeHash string,
	actor string,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE mfa_recovery_codes SET consumed_at = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE user_id = ? AND code_hash = ? AND consumed_at IS NULL",
	)
	result, err := tx.ExecContext(ctx, query, now, now, actor, userID, codeHash)
	if err != nil {
		return fmt.Errorf("consume recovery code: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) InsertMFAChallenge(
	ctx context.Context,
	tx *sqlx.Tx,
	challenge MFALoginChallenge,
) error {
	query := r.db.Rebind(
		"INSERT INTO mfa_login_challenges (token_hash, user_id, client_ip, user_agent, expires_at, consumed_at, version, created_at, updated_at, created_by, updated_by) " +
			"VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
	)
	_, err := tx.ExecContext(
		ctx,
		query,
		challenge.TokenHash,
		challenge.UserID,
		challenge.ClientIP,
		challenge.UserAgent,
		challenge.ExpiresAt,
		challenge.Version,
		challenge.CreatedAt,
		challenge.UpdatedAt,
		challenge.CreatedBy,
		challenge.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("insert mfa login challenge: %w", err)
	}
	return nil
}

func (r *Repository) GetMFAChallenge(ctx context.Context, tokenHash string) (MFALoginChallenge, error) {
	var challenge MFALoginChallenge
	query := r.db.Rebind(
		"SELECT token_hash, user_id, client_ip, user_agent, expires_at, consumed_at, version, created_at, updated_at, created_by, updated_by " +
			"FROM mfa_login_challenges WHERE token_hash = ?",
	)
	if err := r.db.GetContext(ctx, &challenge, query, tokenHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MFALoginChallenge{}, ErrNotFound
		}
		return MFALoginChallenge{}, fmt.Errorf("select mfa login challenge: %w", err)
	}
	return challenge, nil
}

func (r *Repository) ConsumeMFAChallenge(
	ctx context.Context,
	tx *sqlx.Tx,
	tokenHash string,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE mfa_login_challenges SET consumed_at = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND version = ?",
	)
	result, err := tx.ExecContext(ctx, query, now, now, actor, tokenHash, now, version)
	if err != nil {
		return fmt.Errorf("consume mfa login challenge: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) DeleteExpiredMFAChallengesBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	var hashes []string
	query := r.db.Rebind(
		"SELECT token_hash FROM mfa_login_challenges WHERE expires_at < ? ORDER BY expires_at, token_hash LIMIT ?",
	)
	if err := r.db.SelectContext(ctx, &hashes, query, before, limit); err != nil || len(hashes) == 0 {
		return 0, err
	}
	deleteQuery, args, err := sqlx.In(
		"DELETE FROM mfa_login_challenges WHERE token_hash IN (?) AND expires_at < ?",
		hashes,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("build mfa challenge cleanup: %w", err)
	}
	result, err := r.db.ExecContext(ctx, r.db.Rebind(deleteQuery), args...)
	if err != nil {
		return 0, fmt.Errorf("delete expired mfa challenges: %w", err)
	}
	return result.RowsAffected()
}
