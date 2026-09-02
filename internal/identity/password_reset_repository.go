package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

const passwordResetColumns = "token_hash, user_id, reason, expires_at, consumed_at, version, created_at, updated_at, created_by, updated_by"

func (r *Repository) GetPasswordResetChallenge(ctx context.Context, tokenHash string) (PasswordResetChallenge, error) {
	var challenge PasswordResetChallenge
	query := r.db.Rebind("SELECT " + passwordResetColumns + " FROM password_reset_challenges WHERE token_hash = ?")
	if err := r.db.GetContext(ctx, &challenge, query, tokenHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PasswordResetChallenge{}, ErrNotFound
		}
		return PasswordResetChallenge{}, fmt.Errorf("select password reset challenge: %w", err)
	}
	return challenge, nil
}

func (r *Repository) InvalidatePasswordResetChallenges(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	actor string,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE password_reset_challenges SET consumed_at = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE user_id = ? AND consumed_at IS NULL",
	)
	if _, err := tx.ExecContext(ctx, query, now, now, actor, userID); err != nil {
		return fmt.Errorf("invalidate password reset challenges: %w", err)
	}
	return nil
}

func (r *Repository) InsertPasswordResetChallenge(
	ctx context.Context,
	tx *sqlx.Tx,
	challenge PasswordResetChallenge,
) error {
	query := r.db.Rebind(
		"INSERT INTO password_reset_challenges " +
			"(token_hash, user_id, reason, expires_at, consumed_at, version, created_at, updated_at, created_by, updated_by) " +
			"VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
	)
	if _, err := tx.ExecContext(
		ctx,
		query,
		challenge.TokenHash,
		challenge.UserID,
		challenge.Reason,
		challenge.ExpiresAt,
		challenge.Version,
		challenge.CreatedAt,
		challenge.UpdatedAt,
		challenge.CreatedBy,
		challenge.UpdatedBy,
	); err != nil {
		return fmt.Errorf("insert password reset challenge: %w", err)
	}
	return nil
}

func (r *Repository) ConsumePasswordResetChallenge(
	ctx context.Context,
	tx *sqlx.Tx,
	tokenHash string,
	expectedVersion int64,
	actor string,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE password_reset_challenges SET consumed_at = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND version = ?",
	)
	result, err := tx.ExecContext(ctx, query, now, now, actor, tokenHash, now, expectedVersion)
	if err != nil {
		return fmt.Errorf("consume password reset challenge: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) DeleteExpiredPasswordResetChallengesBefore(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	var hashes []string
	query := r.db.Rebind(
		"SELECT token_hash FROM password_reset_challenges WHERE expires_at < ? ORDER BY expires_at, token_hash LIMIT ?",
	)
	if err := r.db.SelectContext(ctx, &hashes, query, before, limit); err != nil || len(hashes) == 0 {
		return 0, err
	}
	deleteQuery, args, err := sqlx.In(
		"DELETE FROM password_reset_challenges WHERE token_hash IN (?) AND expires_at < ?",
		hashes,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("build password reset cleanup: %w", err)
	}
	result, err := r.db.ExecContext(ctx, r.db.Rebind(deleteQuery), args...)
	if err != nil {
		return 0, fmt.Errorf("delete expired password reset challenges: %w", err)
	}
	return result.RowsAffected()
}
