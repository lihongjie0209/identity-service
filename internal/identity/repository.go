package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

var (
	ErrNotFound = errors.New("identity resource not found")
	ErrConflict = errors.New("identity resource conflict")
	ErrStale    = errors.New("identity resource version is stale")
)

type Repository struct{ db *sqlx.DB }

func NewRepository(db *sqlx.DB) *Repository { return &Repository{db: db} }

const userColumns = "id, username, name, email, phone, status, failed_login_count, locked_until, version, created_at, updated_at, created_by, updated_by"

func (r *Repository) CreateUser(ctx context.Context, tx *sqlx.Tx, user User, credential Credential) error {
	userQuery := r.db.Rebind("INSERT INTO users (id, username, name, email, phone, status, failed_login_count, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if _, err := tx.ExecContext(ctx, userQuery, user.ID, user.Username, user.DisplayName, user.Email, user.Phone, user.Status, user.FailedLoginCount, user.Version, user.CreatedAt, user.UpdatedAt, user.CreatedBy, user.UpdatedBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrConflict
		}
		return fmt.Errorf("insert identity user: %w", err)
	}
	credentialQuery := r.db.Rebind("INSERT INTO credentials (id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if _, err := tx.ExecContext(ctx, credentialQuery, credential.ID, credential.UserID, credential.Type, credential.SecretHash, credential.Status, credential.Version, credential.CreatedAt, credential.UpdatedAt, credential.CreatedBy, credential.UpdatedBy); err != nil {
		return fmt.Errorf("insert password credential: %w", err)
	}
	return nil
}

func (r *Repository) InsertOutbox(ctx context.Context, tx *sqlx.Tx, event OutboxEvent) error {
	query := r.db.Rebind("INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)")
	if _, err := tx.ExecContext(ctx, query, event.ID, event.Subject, event.Envelope, event.AvailableAt, event.Version, event.CreatedAt, event.UpdatedAt, event.CreatedBy, event.UpdatedBy); err != nil {
		return fmt.Errorf("insert identity outbox: %w", err)
	}
	return nil
}

func (r *Repository) UserByLogin(ctx context.Context, login string) (User, Credential, error) {
	var user User
	query := r.db.Rebind("SELECT " + userColumns + " FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)")
	if err := r.db.GetContext(ctx, &user, query, login, login); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, Credential{}, ErrNotFound
		}
		return User{}, Credential{}, fmt.Errorf("select login user: %w", err)
	}
	var credential Credential
	if err := r.db.GetContext(ctx, &credential, r.db.Rebind("SELECT id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by FROM credentials WHERE user_id = ? AND type = 'password'"), user.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, Credential{}, ErrNotFound
		}
		return User{}, Credential{}, fmt.Errorf("select password credential: %w", err)
	}
	return user, credential, nil
}

func (r *Repository) GetUser(ctx context.Context, id string) (User, error) {
	var user User
	if err := r.db.GetContext(ctx, &user, r.db.Rebind("SELECT "+userColumns+" FROM users WHERE id = ?"), id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("select identity user: %w", err)
	}
	return user, nil
}

func (r *Repository) RecordFailedLogin(ctx context.Context, userID string, threshold int, lockedUntil, now time.Time) error {
	query := r.db.Rebind("UPDATE users SET failed_login_count = failed_login_count + 1, locked_until = CASE WHEN failed_login_count + 1 >= ? THEN ? ELSE locked_until END, version = version + 1, updated_at = ?, updated_by = 'identity:login' WHERE id = ?")
	if _, err := r.db.ExecContext(ctx, query, threshold, lockedUntil, now, userID); err != nil {
		return fmt.Errorf("record failed login: %w", err)
	}
	return nil
}

func (r *Repository) ResetFailedLogin(ctx context.Context, userID string, now time.Time) error {
	query := r.db.Rebind("UPDATE users SET failed_login_count = 0, locked_until = NULL, version = version + 1, updated_at = ?, updated_by = 'identity:login' WHERE id = ? AND (failed_login_count <> 0 OR locked_until IS NOT NULL)")
	if _, err := r.db.ExecContext(ctx, query, now, userID); err != nil {
		return fmt.Errorf("reset failed login: %w", err)
	}
	return nil
}

func (r *Repository) UpdateUserStatus(ctx context.Context, tx *sqlx.Tx, id, status, actor string, version int64, now time.Time) error {
	result, err := tx.ExecContext(ctx, r.db.Rebind("UPDATE users SET status=?, failed_login_count=0, locked_until=NULL, version=version+1, updated_at=?, updated_by=? WHERE id=? AND version=?"), status, now, actor, id, version)
	if err != nil {
		return fmt.Errorf("update user status: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) BatchGetUsers(ctx context.Context, ids []string) ([]User, error) {
	if len(ids) == 0 {
		return []User{}, nil
	}
	query, args, err := sqlx.In("SELECT "+userColumns+" FROM users WHERE id IN (?)", ids)
	if err != nil {
		return nil, fmt.Errorf("build batch users query: %w", err)
	}
	users := make([]User, 0, len(ids))
	if err := r.db.SelectContext(ctx, &users, r.db.Rebind(query), args...); err != nil {
		return nil, fmt.Errorf("select batch users: %w", err)
	}
	return users, nil
}

func (r *Repository) CreateSession(ctx context.Context, tx *sqlx.Tx, session Session) error {
	query := r.db.Rebind("INSERT INTO sessions (id, user_id, refresh_token_hash, tenant_id, membership_id, expires_at, revoked_at, revoke_reason, version, created_at, updated_at, created_by, updated_by, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL, '', ?, ?, ?, ?, ?, ?)")
	_, err := tx.ExecContext(ctx, query, session.ID, session.UserID, session.RefreshTokenHash, session.TenantID, session.MembershipID, session.ExpiresAt, session.Version, session.CreatedAt, session.UpdatedAt, session.CreatedBy, session.UpdatedBy, session.LastUsedAt)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (r *Repository) SessionByRefreshHash(ctx context.Context, hash string) (Session, error) {
	var session Session
	query := r.db.Rebind("SELECT id, user_id, refresh_token_hash, tenant_id, membership_id, expires_at, revoked_at, revoke_reason, version, created_at, updated_at, created_by, updated_by, last_used_at FROM sessions WHERE refresh_token_hash = ?")
	if err := r.db.GetContext(ctx, &session, query, hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, fmt.Errorf("select refresh session: %w", err)
	}
	return session, nil
}

func (r *Repository) GetSession(ctx context.Context, id, userID string) (Session, error) {
	var session Session
	query := r.db.Rebind("SELECT id, user_id, refresh_token_hash, tenant_id, membership_id, expires_at, revoked_at, revoke_reason, version, created_at, updated_at, created_by, updated_by, last_used_at FROM sessions WHERE id = ? AND user_id = ?")
	if err := r.db.GetContext(ctx, &session, query, id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, fmt.Errorf("select session: %w", err)
	}
	return session, nil
}

func (r *Repository) RotateSession(ctx context.Context, tx *sqlx.Tx, session Session, previousHash string) error {
	result, err := tx.ExecContext(ctx, r.db.Rebind("UPDATE sessions SET refresh_token_hash = ?, last_used_at = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND refresh_token_hash = ? AND revoked_at IS NULL AND version = ?"), session.RefreshTokenHash, session.LastUsedAt, session.UpdatedAt, session.UpdatedBy, session.ID, previousHash, session.Version)
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) RevokeSession(ctx context.Context, tx *sqlx.Tx, id, userID, reason, actor string, now time.Time) error {
	result, err := tx.ExecContext(ctx, r.db.Rebind("UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL"), now, reason, now, actor, id, userID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) RevokeTenantSessions(ctx context.Context, userID, tenantID, reason, actor string, now time.Time) (uint64, error) {
	result, err := r.db.ExecContext(ctx, r.db.Rebind("UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE user_id = ? AND tenant_id = ? AND revoked_at IS NULL"), now, reason, now, actor, userID, tenantID)
	if err != nil {
		return 0, fmt.Errorf("revoke tenant sessions: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read revoked sessions: %w", err)
	}
	return uint64(count), nil
}

func (r *Repository) GetServiceAccount(ctx context.Context, id string) (ServiceAccount, error) {
	var account ServiceAccount
	query := r.db.Rebind("SELECT id, client_id, name, secret_hash, status, audiences_json, version, created_at, updated_at, created_by, updated_by FROM service_accounts WHERE id = ?")
	if err := r.db.GetContext(ctx, &account, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ServiceAccount{}, ErrNotFound
		}
		return ServiceAccount{}, fmt.Errorf("select service account: %w", err)
	}
	return account, nil
}

func (r *Repository) CreateServiceAccount(ctx context.Context, tx *sqlx.Tx, account ServiceAccount) error {
	query := r.db.Rebind("INSERT INTO service_accounts (id, client_id, name, secret_hash, status, audiences_json, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if _, err := tx.ExecContext(ctx, query, account.ID, account.ClientID, account.Name, account.SecretHash, account.Status, account.AudiencesJSON, account.Version, account.CreatedAt, account.UpdatedAt, account.CreatedBy, account.UpdatedBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrConflict
		}
		return fmt.Errorf("insert service account: %w", err)
	}
	return nil
}

func (r *Repository) ServiceAccountByClientID(ctx context.Context, clientID string) (ServiceAccount, error) {
	var account ServiceAccount
	query := r.db.Rebind("SELECT id, client_id, name, secret_hash, status, audiences_json, version, created_at, updated_at, created_by, updated_by FROM service_accounts WHERE client_id = ?")
	if err := r.db.GetContext(ctx, &account, query, clientID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ServiceAccount{}, ErrNotFound
		}
		return ServiceAccount{}, fmt.Errorf("select service account by client: %w", err)
	}
	return account, nil
}

func (r *Repository) UpdateServiceAccountStatus(ctx context.Context, tx *sqlx.Tx, id, status, actor string, version int64, now time.Time) error {
	result, err := tx.ExecContext(ctx, r.db.Rebind("UPDATE service_accounts SET status = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?"), status, now, actor, id, version)
	if err != nil {
		return fmt.Errorf("update service account status: %w", err)
	}
	return requireAffected(result)
}

func requireAffected(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read affected rows: %w", err)
	}
	if count == 0 {
		return ErrStale
	}
	return nil
}
