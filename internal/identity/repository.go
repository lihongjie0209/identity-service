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
const serviceAccountColumns = "id, client_id, name, secret_hash, status, audiences_json, version, created_at, updated_at, created_by, updated_by"
const sessionColumns = "id, user_id, refresh_token_hash, tenant_id, membership_id, expires_at, revoked_at, revoke_reason, version, created_at, updated_at, created_by, updated_by, last_used_at, client_ip, user_agent"
const sessionListColumns = "s.id, s.user_id, u.username, u.name AS user_display_name, s.refresh_token_hash, s.tenant_id, s.membership_id, s.expires_at, s.revoked_at, s.revoke_reason, s.version, s.created_at, s.updated_at, s.created_by, s.updated_by, s.last_used_at, s.client_ip, s.user_agent"

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

func (r *Repository) PasswordCredential(ctx context.Context, userID string) (Credential, error) {
	var credential Credential
	query := r.db.Rebind("SELECT id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by FROM credentials WHERE user_id = ? AND type = 'password'")
	if err := r.db.GetContext(ctx, &credential, query, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Credential{}, ErrNotFound
		}
		return Credential{}, fmt.Errorf("select password credential: %w", err)
	}
	return credential, nil
}

func (r *Repository) UpdatePasswordCredential(
	ctx context.Context,
	tx *sqlx.Tx,
	credentialID string,
	secretHash string,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE credentials SET secret_hash = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE id = ? AND type = 'password' AND status = ? AND version = ?",
	)
	result, err := tx.ExecContext(ctx, query, secretHash, now, actor, credentialID, StatusActive, version)
	if err != nil {
		return fmt.Errorf("update password credential: %w", err)
	}
	return requireAffected(result)
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

func (r *Repository) ListUsers(ctx context.Context, keyword, status string, limit, offset int) ([]User, int64, error) {
	keyword = strings.TrimSpace(keyword)
	status = strings.TrimSpace(status)
	where := " WHERE 1=1"
	args := make([]any, 0, 4)
	if status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}
	if keyword != "" {
		where += " AND (LOWER(username) LIKE LOWER(?) OR LOWER(name) LIKE LOWER(?) OR LOWER(email) LIKE LOWER(?))"
		pattern := "%" + keyword + "%"
		args = append(args, pattern, pattern, pattern)
	}
	var total int64
	if err := r.db.GetContext(ctx, &total, r.db.Rebind("SELECT COUNT(*) FROM users"+where), args...); err != nil {
		return nil, 0, fmt.Errorf("count identity users: %w", err)
	}
	queryArgs := append(append([]any(nil), args...), limit, offset)
	users := make([]User, 0, limit)
	query := r.db.Rebind("SELECT " + userColumns + " FROM users" + where + " ORDER BY created_at DESC, id LIMIT ? OFFSET ?")
	if err := r.db.SelectContext(ctx, &users, query, queryArgs...); err != nil {
		return nil, 0, fmt.Errorf("list identity users: %w", err)
	}
	return users, total, nil
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

func (r *Repository) UpdateUserProfile(
	ctx context.Context,
	tx *sqlx.Tx,
	id string,
	displayName string,
	email string,
	phone string,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind("UPDATE users SET name=?, email=?, phone=?, version=version+1, updated_at=?, updated_by=? WHERE id=? AND version=?")
	result, err := tx.ExecContext(ctx, query, displayName, email, phone, now, actor, id, version)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "duplicate") || strings.Contains(message, "unique") {
			return ErrConflict
		}
		return fmt.Errorf("update user profile: %w", err)
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
	query := r.db.Rebind("INSERT INTO sessions (id, user_id, refresh_token_hash, tenant_id, membership_id, expires_at, revoked_at, revoke_reason, version, created_at, updated_at, created_by, updated_by, last_used_at, client_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, NULL, '', ?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := tx.ExecContext(ctx, query, session.ID, session.UserID, session.RefreshTokenHash, session.TenantID, session.MembershipID, session.ExpiresAt, session.Version, session.CreatedAt, session.UpdatedAt, session.CreatedBy, session.UpdatedBy, session.LastUsedAt, session.ClientIP, session.UserAgent)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

func (r *Repository) DeleteExpiredOrRevokedSessionsBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	var ids []string
	query := r.db.Rebind("SELECT id FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at<?) OR (revoked_at IS NULL AND expires_at<?) ORDER BY COALESCE(revoked_at,expires_at),id LIMIT ?")
	if err := r.db.SelectContext(ctx, &ids, query, before, before, limit); err != nil || len(ids) == 0 {
		return 0, err
	}
	query, args, err := sqlx.In("DELETE FROM sessions WHERE id IN (?) AND ((revoked_at IS NOT NULL AND revoked_at<?) OR (revoked_at IS NULL AND expires_at<?))", ids, before, before)
	if err != nil {
		return 0, err
	}
	result, err := r.db.ExecContext(ctx, r.db.Rebind(query), args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *Repository) SessionByRefreshHash(ctx context.Context, hash string) (Session, error) {
	var session Session
	query := r.db.Rebind("SELECT " + sessionColumns + " FROM sessions WHERE refresh_token_hash = ?")
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
	query := r.db.Rebind("SELECT " + sessionColumns + " FROM sessions WHERE id = ? AND user_id = ?")
	if err := r.db.GetContext(ctx, &session, query, id, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, fmt.Errorf("select session: %w", err)
	}
	return session, nil
}

func (r *Repository) GetSessionByID(ctx context.Context, id string) (Session, error) {
	var session Session
	query := r.db.Rebind("SELECT " + sessionColumns + " FROM sessions WHERE id = ?")
	if err := r.db.GetContext(ctx, &session, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, fmt.Errorf("select session by id: %w", err)
	}
	return session, nil
}

func (r *Repository) ListSessions(
	ctx context.Context,
	userID string,
	tenantID string,
	status string,
	now time.Time,
	limit int,
	offset int,
) ([]Session, int64, error) {
	where := " WHERE 1=1"
	args := make([]any, 0, 4)
	if userID != "" {
		where += " AND s.user_id = ?"
		args = append(args, userID)
	}
	if tenantID != "" {
		where += " AND s.tenant_id = ?"
		args = append(args, tenantID)
	}
	switch status {
	case "active":
		where += " AND s.revoked_at IS NULL AND s.expires_at > ?"
		args = append(args, now)
	case "revoked":
		where += " AND s.revoked_at IS NOT NULL"
	case "expired":
		where += " AND s.revoked_at IS NULL AND s.expires_at <= ?"
		args = append(args, now)
	}

	var total int64
	if err := r.db.GetContext(ctx, &total, r.db.Rebind("SELECT COUNT(*) FROM sessions s"+where), args...); err != nil {
		return nil, 0, fmt.Errorf("count sessions: %w", err)
	}
	queryArgs := append(append([]any(nil), args...), limit, offset)
	sessions := make([]Session, 0, limit)
	query := r.db.Rebind(
		"SELECT " + sessionListColumns + " FROM sessions s JOIN users u ON u.id = s.user_id" + where +
			" ORDER BY s.last_used_at DESC, s.id LIMIT ? OFFSET ?",
	)
	if err := r.db.SelectContext(ctx, &sessions, query, queryArgs...); err != nil {
		return nil, 0, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, total, nil
}

func (r *Repository) RotateSession(ctx context.Context, tx *sqlx.Tx, session Session, previousHash string) error {
	result, err := tx.ExecContext(ctx, r.db.Rebind("UPDATE sessions SET refresh_token_hash = ?, last_used_at = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND refresh_token_hash = ? AND revoked_at IS NULL AND version = ?"), session.RefreshTokenHash, session.LastUsedAt, session.UpdatedAt, session.UpdatedBy, session.ID, previousHash, session.Version)
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) ScopeSession(ctx context.Context, tx *sqlx.Tx, sessionID, userID, tenantID, membershipID, actor string, now time.Time) error {
	result, err := tx.ExecContext(ctx, r.db.Rebind("UPDATE sessions SET tenant_id = ?, membership_id = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?"), tenantID, membershipID, now, actor, sessionID, userID, now)
	if err != nil {
		return fmt.Errorf("scope session to tenant: %w", err)
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

func (r *Repository) RevokeOtherSessions(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	currentSessionID string,
	reason string,
	actor string,
	now time.Time,
) (uint64, error) {
	query := r.db.Rebind(
		"UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE user_id = ? AND id <> ? AND revoked_at IS NULL AND expires_at > ?",
	)
	result, err := tx.ExecContext(ctx, query, now, reason, now, actor, userID, currentSessionID, now)
	if err != nil {
		return 0, fmt.Errorf("revoke other sessions: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read revoked other sessions: %w", err)
	}
	return uint64(count), nil
}

func (r *Repository) RevokeUserSessions(
	ctx context.Context,
	tx *sqlx.Tx,
	userID string,
	reason string,
	actor string,
	now time.Time,
) (uint64, error) {
	query := r.db.Rebind(
		"UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, updated_at = ?, updated_by = ? " +
			"WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?",
	)
	result, err := tx.ExecContext(ctx, query, now, reason, now, actor, userID, now)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read revoked user sessions: %w", err)
	}
	return uint64(count), nil
}

func (r *Repository) RevokeSessionByID(
	ctx context.Context,
	tx *sqlx.Tx,
	id string,
	reason string,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, " +
			"updated_at = ?, updated_by = ? WHERE id = ? AND version = ? AND revoked_at IS NULL",
	)
	result, err := tx.ExecContext(ctx, query, now, reason, now, actor, id, version)
	if err != nil {
		return fmt.Errorf("administratively revoke session: %w", err)
	}
	return requireAffected(result)
}

func (r *Repository) RevokeOwnedSessionByID(
	ctx context.Context,
	tx *sqlx.Tx,
	id string,
	userID string,
	reason string,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind(
		"UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, " +
			"updated_at = ?, updated_by = ? WHERE id = ? AND user_id = ? AND version = ? AND revoked_at IS NULL",
	)
	result, err := tx.ExecContext(ctx, query, now, reason, now, actor, id, userID, version)
	if err != nil {
		return fmt.Errorf("revoke owned session: %w", err)
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
	query := r.db.Rebind("SELECT " + serviceAccountColumns + " FROM service_accounts WHERE id = ?")
	if err := r.db.GetContext(ctx, &account, query, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ServiceAccount{}, ErrNotFound
		}
		return ServiceAccount{}, fmt.Errorf("select service account: %w", err)
	}
	return account, nil
}

func (r *Repository) ListServiceAccounts(
	ctx context.Context,
	keyword string,
	status string,
	limit int,
	offset int,
) ([]ServiceAccount, int64, error) {
	keyword = strings.TrimSpace(keyword)
	status = strings.TrimSpace(status)
	where := " WHERE 1=1"
	args := make([]any, 0, 3)
	if status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}
	if keyword != "" {
		where += " AND (LOWER(client_id) LIKE LOWER(?) OR LOWER(name) LIKE LOWER(?))"
		pattern := "%" + keyword + "%"
		args = append(args, pattern, pattern)
	}

	var total int64
	if err := r.db.GetContext(
		ctx,
		&total,
		r.db.Rebind("SELECT COUNT(*) FROM service_accounts"+where),
		args...,
	); err != nil {
		return nil, 0, fmt.Errorf("count service accounts: %w", err)
	}

	queryArgs := append(append([]any(nil), args...), limit, offset)
	accounts := make([]ServiceAccount, 0, limit)
	query := r.db.Rebind(
		"SELECT " + serviceAccountColumns + " FROM service_accounts" + where +
			" ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
	)
	if err := r.db.SelectContext(ctx, &accounts, query, queryArgs...); err != nil {
		return nil, 0, fmt.Errorf("list service accounts: %w", err)
	}
	return accounts, total, nil
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
	query := r.db.Rebind("SELECT " + serviceAccountColumns + " FROM service_accounts WHERE client_id = ?")
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

func (r *Repository) RotateServiceAccountSecret(
	ctx context.Context,
	tx *sqlx.Tx,
	id string,
	secretHash string,
	actor string,
	version int64,
	now time.Time,
) error {
	query := r.db.Rebind("UPDATE service_accounts SET secret_hash = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?")
	result, err := tx.ExecContext(ctx, query, secretHash, now, actor, id, version)
	if err != nil {
		return fmt.Errorf("rotate service account secret: %w", err)
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
