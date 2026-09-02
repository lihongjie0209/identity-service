package identity

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/principal"
	commonv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/common/v1"
	identityv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/identity/v1"
	"google.golang.org/protobuf/proto"
)

func TestServiceUpdateUserProfilePersistsAuditAndEventAtomically(t *testing.T) {
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
	now := time.Date(2026, time.September, 3, 10, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	userRows := func(displayName, email, phone, updatedBy string, version int64) *sqlmock.Rows {
		return sqlmock.NewRows([]string{
			"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow("user-1", "alice", displayName, email, phone, StatusActive, 0, nil, version, now, now, "creator-1", updatedBy)
	}
	envelopeBytes := &captureBytesArgument{}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + userColumns + " FROM users WHERE id = ?")).
		WithArgs("user-1").
		WillReturnRows(userRows("Alice", "alice@example.com", "", "creator-1", 4))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET name=?, email=?, phone=?, version=version+1, updated_at=?, updated_by=? WHERE id=? AND version=?")).
		WithArgs("Alice Zhang", "alice.zhang@example.com", "13800000000", now, "admin-1", "user-1", int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)")).
		WithArgs(sqlmock.AnyArg(), "platform.identity.user.profile-updated.v1", envelopeBytes, now, int64(1), now, now, "admin-1", "admin-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + userColumns + " FROM users WHERE id = ?")).
		WithArgs("user-1").
		WillReturnRows(userRows("Alice Zhang", "alice.zhang@example.com", "13800000000", "admin-1", 5))

	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "admin-1", Type: principal.TypeUser})
	updated, err := service.UpdateUserProfile(
		ctx,
		"user-1",
		" Alice Zhang ",
		" ALICE.ZHANG@example.com ",
		" 13800000000 ",
		" verified by support ",
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "Alice Zhang" || updated.Email != "alice.zhang@example.com" || updated.Version != 5 {
		t.Fatalf("UpdateUserProfile() = %#v", updated)
	}
	var envelope commonv1.EventEnvelope
	if err := proto.Unmarshal(envelopeBytes.value, &envelope); err != nil {
		t.Fatal(err)
	}
	var event identityv1.UserProfileUpdatedEvent
	if err := proto.Unmarshal(envelope.Payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.User.GetEmail() != "alice.zhang@example.com" || event.User.GetVersion() != 5 || event.GetReason() != "verified by support" {
		t.Fatalf("event = %#v", &event)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceUpdateUserProfileValidatesBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()
	service := &Service{}
	tests := []struct {
		name        string
		displayName string
		email       string
		reason      string
		version     int64
	}{
		{name: "missing display name", email: "alice@example.com", reason: "support request", version: 1},
		{name: "missing email", displayName: "Alice", reason: "support request", version: 1},
		{name: "missing reason", displayName: "Alice", email: "alice@example.com", version: 1},
		{name: "invalid version", displayName: "Alice", email: "alice@example.com", reason: "support request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.UpdateUserProfile(context.Background(), "user-1", test.displayName, test.email, "", test.reason, test.version)
			if identityErrorCode(err) != apperror.CodeInvalidArgument {
				t.Fatalf("UpdateUserProfile() error = %#v, want invalid argument", err)
			}
		})
	}
}

func TestServiceUpdateUserProfileRollsBackStaleVersion(t *testing.T) {
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
	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + userColumns + " FROM users WHERE id = ?")).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow("user-1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 5, now, now, "creator-1", "admin-1"))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET name=?, email=?, phone=?, version=version+1, updated_at=?, updated_by=? WHERE id=? AND version=?")).
		WithArgs("Alice Zhang", "alice.zhang@example.com", "", sqlmock.AnyArg(), "admin-1", "user-1", int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	ctx := principal.WithContext(t.Context(), principal.Principal{ID: "admin-1", Type: principal.TypeUser})
	_, err = service.UpdateUserProfile(ctx, "user-1", "Alice Zhang", "alice.zhang@example.com", "", "support request", 4)
	if identityErrorCode(err) != apperror.CodeStaleVersion {
		t.Fatalf("UpdateUserProfile() error = %#v, want stale version", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
