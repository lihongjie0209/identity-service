package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

func newPasswordResetServiceForTest(t *testing.T, db *sqlx.DB) *Service {
	t.Helper()
	service, err := NewService(
		NewRepository(db),
		database.NewTransactor(db),
		config.Config{
			App: config.App{Name: "identity-service"},
			JWT: config.JWT{
				Issuer: "test",
				Secret: "01234567890123456789012345678901",
				TTL:    time.Hour,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	service.hasher, err = NewPasswordHasher(PasswordParameters{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func passwordResetAdminContext() context.Context {
	return principal.WithContext(
		context.Background(),
		principal.Principal{ID: "admin-1", Type: principal.TypeUser, SessionID: "admin-session"},
	)
}

func TestServiceIssuePasswordResetStoresOnlyTokenHash(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service := newPasswordResetServiceForTest(t, sqlDB)
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + userColumns + " FROM users WHERE id = ?")).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow("user-1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 1, now, now, "admin", "admin"))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(
		"UPDATE password_reset_challenges SET consumed_at = ?, version = version + 1, updated_at = ?, updated_by = ? "+
			"WHERE user_id = ? AND consumed_at IS NULL",
	)).WithArgs(now, now, "admin-1", "user-1").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(
		"INSERT INTO password_reset_challenges "+
			"(token_hash, user_id, reason, expires_at, consumed_at, version, created_at, updated_at, created_by, updated_by) "+
			"VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
	)).WithArgs(
		sqlmock.AnyArg(), "user-1", "verified account owner", now.Add(passwordResetTTL), int64(1),
		now, now, "admin-1", "admin-1",
	).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	issue, err := service.IssuePasswordReset(passwordResetAdminContext(), "user-1", " verified account owner ")
	if err != nil {
		t.Fatal(err)
	}
	if issue.ResetToken == "" || !issue.ExpiresAt.Equal(now.Add(passwordResetTTL)) {
		t.Fatalf("IssuePasswordReset() = %+v", issue)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(issue.ResetToken)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("unsafe reset token: %q, %v", issue.ResetToken, err)
	}
	if hashPasswordResetToken(issue.ResetToken) == issue.ResetToken {
		t.Fatal("password reset token hash must differ from plaintext")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryConsumePasswordResetRequiresExpiryAndVersion(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	repository := NewRepository(sqlDB)
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	tx, err := sqlDB.BeginTxx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta(
		"UPDATE password_reset_challenges SET consumed_at = ?, version = version + 1, updated_at = ?, updated_by = ? "+
			"WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND version = ?",
	)).WithArgs(now, now, "identity:password-reset", "token-hash", now, int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.ConsumePasswordResetChallenge(
		t.Context(), tx, "token-hash", 3, "identity:password-reset", now,
	); err != nil {
		t.Fatal(err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceIssuePasswordResetRejectsSelfServiceBypass(t *testing.T) {
	t.Parallel()
	service := &Service{}
	_, err := service.IssuePasswordReset(
		principal.WithContext(
			context.Background(),
			principal.Principal{ID: "user-1", Type: principal.TypeUser, SessionID: "session-1"},
		),
		"user-1",
		"forgot password",
	)
	var appErr *apperror.Error
	if !errors.As(err, &appErr) || appErr.Code != apperror.CodeInvalidArgument {
		t.Fatalf("IssuePasswordReset() error = %v", err)
	}
}
