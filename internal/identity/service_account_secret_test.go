package identity

import (
	"bytes"
	"database/sql/driver"
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

type captureStringArgument struct {
	value string
}

type captureBytesArgument struct {
	value []byte
}

func (argument *captureBytesArgument) Match(value driver.Value) bool {
	data, ok := value.([]byte)
	if ok {
		argument.value = append(argument.value[:0], data...)
	}
	return ok
}

func (argument *captureStringArgument) Match(value driver.Value) bool {
	text, ok := value.(string)
	if ok {
		argument.value = text
	}
	return ok
}

func TestServiceRotateServiceAccountSecretPersistsHashAndOutboxAtomically(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(
		NewRepository(sqlDB),
		database.NewTransactor(sqlDB),
		config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}},
	)
	if err != nil {
		t.Fatal(err)
	}
	service.hasher, err = NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 3, 9, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	hash := &captureStringArgument{}
	envelope := &captureBytesArgument{}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE service_accounts SET secret_hash = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?")).
		WithArgs(hash, now, "admin-1", "service-account-1", int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)")).
		WithArgs(sqlmock.AnyArg(), "platform.identity.service-account.secret-rotated.v1", envelope, now, int64(1), now, now, "admin-1", "admin-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "admin-1", Type: principal.TypeUser})
	secret, version, err := service.RotateServiceAccountSecret(ctx, "service-account-1", 4)
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || version != 5 {
		t.Fatalf("RotateServiceAccountSecret() secret empty=%v version=%d", secret == "", version)
	}
	valid, _, err := service.hasher.Verify(secret, hash.value)
	if err != nil || !valid {
		t.Fatalf("stored hash does not verify returned secret: valid=%v err=%v", valid, err)
	}
	if bytes.Contains(envelope.value, []byte(secret)) {
		t.Fatal("outbox event contains the plaintext client secret")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRotateServiceAccountSecretRejectsStaleVersionWithoutReturningSecret(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(
		NewRepository(sqlDB),
		database.NewTransactor(sqlDB),
		config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}},
	)
	if err != nil {
		t.Fatal(err)
	}
	service.hasher, err = NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE service_accounts SET secret_hash = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND version = ?")).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "admin-1", "service-account-1", int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "admin-1", Type: principal.TypeUser})
	secret, version, err := service.RotateServiceAccountSecret(ctx, "service-account-1", 3)
	if identityErrorCode(err) != apperror.CodeStaleVersion {
		t.Fatalf("RotateServiceAccountSecret() error = %#v, want version conflict", err)
	}
	if secret != "" || version != 0 {
		t.Fatalf("RotateServiceAccountSecret() returned secret=%q version=%d after rollback", secret, version)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
