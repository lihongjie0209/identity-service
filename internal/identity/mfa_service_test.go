package identity

import (
	"context"
	"database/sql"
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

func newMFAServiceForTest(t *testing.T, db *sqlx.DB) *Service {
	t.Helper()
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	pepper := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyzABCDEF"))
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
			MFA: config.MFA{
				Enabled:        true,
				Issuer:         "Platform",
				EncryptionKey:  key,
				RecoveryPepper: pepper,
				ChallengeTTL:   5 * time.Minute,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func mfaUserContext() context.Context {
	return principal.WithContext(
		context.Background(),
		principal.Principal{ID: "user-1", Type: principal.TypeUser, SessionID: "session-1"},
	)
}

func TestServiceMFAStatusReportsUnavailable(t *testing.T) {
	t.Parallel()
	service := &Service{}
	status, err := service.MFAStatus(mfaUserContext())
	if err != nil {
		t.Fatal(err)
	}
	if status.Available || status.Enabled || status.Status != MFAStatusDisabled {
		t.Fatalf("MFAStatus() = %#v", status)
	}
}

func TestServiceStartMFASetupVerifiesPasswordAndEncryptsSecret(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service := newMFAServiceForTest(t, sqlDB)
	now := time.Date(2026, time.September, 2, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	passwordHash, err := service.hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by FROM credentials WHERE user_id = ? AND type = 'password'",
	)).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "type", "secret_hash", "status", "version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow("credential-1", "user-1", "password", passwordHash, StatusActive, 1, now, now, "admin", "admin"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + userColumns + " FROM users WHERE id = ?")).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow("user-1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 1, now, now, "admin", "admin"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + mfaColumns + " FROM user_mfa WHERE user_id = ?")).
		WithArgs("user-1").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(
		"INSERT INTO user_mfa (user_id, method, secret_ciphertext, status, last_used_step, enabled_at, version, created_at, updated_at, created_by, updated_by) "+
			"VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)",
	)).
		WithArgs(
			"user-1",
			"totp",
			sqlmock.AnyArg(),
			MFAStatusPending,
			int64(-1),
			int64(1),
			now,
			now,
			"user-1",
			"user-1",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	setup, err := service.StartMFASetup(mfaUserContext(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if setup.Secret == "" || setup.URI == "" || setup.Version != 1 || !setup.ExpiresAt.Equal(now.Add(mfaSetupTTL)) {
		t.Fatalf("StartMFASetup() = %#v", setup)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryDisableMFARequiresNewStepAndExpectedVersion(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	repository := NewRepository(sqlDB)
	now := time.Date(2026, time.September, 2, 10, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	tx, err := sqlDB.BeginTxx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta(
		"UPDATE user_mfa SET status = ?, last_used_step = ?, version = version + 1, updated_at = ?, updated_by = ? "+
			"WHERE user_id = ? AND status = ? AND last_used_step < ? AND version = ?",
	)).
		WithArgs(MFAStatusDisabled, int64(123), now, "user-1", "user-1", MFAStatusEnabled, int64(123), int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.DisableMFA(t.Context(), tx, "user-1", 123, "user-1", 4, now); err != nil {
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

func TestRepositoryRecoveryCodeRotationRequiresNewStepAndExpectedVersion(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	repository := NewRepository(sqlDB)
	now := time.Date(2026, time.September, 2, 10, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	tx, err := sqlDB.BeginTxx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta(
		"UPDATE user_mfa SET last_used_step = ?, version = version + 1, updated_at = ?, updated_by = ? "+
			"WHERE user_id = ? AND status = ? AND last_used_step < ? AND version = ?",
	)).
		WithArgs(int64(124), now, "user-1", "user-1", MFAStatusEnabled, int64(124), int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.AdvanceMFAStepAtVersion(
		t.Context(),
		tx,
		"user-1",
		124,
		"user-1",
		7,
		now,
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

func TestRepositoryConsumeMFAChallengeRequiresExpiryAndVersion(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	repository := NewRepository(sqlDB)
	now := time.Date(2026, time.September, 2, 10, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	tx, err := sqlDB.BeginTxx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(regexp.QuoteMeta(
		"UPDATE mfa_login_challenges SET consumed_at = ?, version = version + 1, updated_at = ?, updated_by = ? "+
			"WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? AND version = ?",
	)).
		WithArgs(now, now, "identity:mfa", "token-hash", now, int64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := repository.ConsumeMFAChallenge(
		t.Context(),
		tx,
		"token-hash",
		"identity:mfa",
		2,
		now,
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

func TestServiceVerifyMFAChallengeRequiresExactlyOneCode(t *testing.T) {
	t.Parallel()
	service := &Service{mfa: testMFACrypto(t)}
	for _, test := range []struct {
		name         string
		code         string
		recoveryCode string
	}{
		{name: "neither code"},
		{name: "both codes", code: "123456", recoveryCode: "ABCD-EFGH-IJKL-MNOP"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.VerifyMFAChallenge(t.Context(), "challenge", test.code, test.recoveryCode)
			var appErr *apperror.Error
			if !errors.As(err, &appErr) || appErr.Code != apperror.CodeInvalidArgument {
				t.Fatalf("VerifyMFAChallenge() error = %v", err)
			}
		})
	}
}

func TestServiceConfirmMFARejectsInvalidCodeWithoutMutation(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service := newMFAServiceForTest(t, sqlDB)
	now := time.Date(2026, time.September, 2, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	encrypted, err := service.mfa.EncryptSecret("user-1", "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + mfaColumns + " FROM user_mfa WHERE user_id = ?")).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"user_id", "method", "secret_ciphertext", "status", "last_used_step", "enabled_at",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow("user-1", "totp", encrypted, MFAStatusPending, -1, nil, 2, now, now, "user-1", "user-1"))
	_, err = service.ConfirmMFASetup(mfaUserContext(), "000000", 2)
	var appErr *apperror.Error
	if !errors.As(err, &appErr) || appErr.Code != apperror.CodeUnauthorized {
		t.Fatalf("ConfirmMFASetup() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
