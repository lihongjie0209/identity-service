package identity

import (
	"context"
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

func TestRepositoryListSessionsFiltersAndPaginates(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := NewRepository(sqlx.NewDb(db, "sqlmock"))
	now := time.Now().UTC()
	where := " WHERE 1=1 AND user_id = ? AND tenant_id = ? AND revoked_at IS NULL AND expires_at > ?"
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM sessions"+where)).
		WithArgs("user-1", "tenant-1", now).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT "+sessionColumns+" FROM sessions"+where+
			" ORDER BY last_used_at DESC, id LIMIT ? OFFSET ?",
	)).
		WithArgs("user-1", "tenant-1", now, 20, 20).
		WillReturnRows(sessionRows(now).AddRow(
			"session-1", "user-1", "refresh-hash", "tenant-1", "membership-1",
			now.Add(time.Hour), nil, "", 1, now, now, "user-1", "user-1", now,
		))

	sessions, total, err := repository.ListSessions(
		t.Context(),
		"user-1",
		"tenant-1",
		"active",
		now,
		20,
		20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(sessions) != 1 || sessions[0].ID != "session-1" {
		t.Fatalf("ListSessions() = sessions:%#v total:%d", sessions, total)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceListSessionsRejectsUnknownStatus(t *testing.T) {
	t.Parallel()
	service := &Service{}
	_, err := service.ListSessions(t.Context(), "", "", "closed", 1, 20)
	var appErr *apperror.Error
	if !errors.As(err, &appErr) || appErr.Code != apperror.CodeInvalidArgument {
		t.Fatalf("ListSessions() error = %v", err)
	}
}

func TestServiceRevokeSessionByIDUsesExpectedVersionAndWritesOutbox(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(
		NewRepository(sqlDB),
		database.NewTransactor(sqlDB),
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
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + sessionColumns + " FROM sessions WHERE id = ?")).
		WithArgs("session-1").
		WillReturnRows(sessionRows(now).AddRow(
			"session-1", "user-1", "refresh-hash", "tenant-1", "membership-1",
			now.Add(time.Hour), nil, "", 4, now, now, "user-1", "user-1", now,
		))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(
		"UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, "+
			"updated_at = ?, updated_by = ? WHERE id = ? AND version = ? AND revoked_at IS NULL",
	)).
		WithArgs(now, "suspected compromise", now, "admin-1", "session-1", int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(
		"INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)",
	)).
		WithArgs(
			sqlmock.AnyArg(),
			"platform.identity.session.revoked.v1",
			sqlmock.AnyArg(),
			now,
			int64(1),
			now,
			now,
			"admin-1",
			"admin-1",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	revokedAt := now
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + sessionColumns + " FROM sessions WHERE id = ?")).
		WithArgs("session-1").
		WillReturnRows(sessionRows(now).AddRow(
			"session-1", "user-1", "refresh-hash", "tenant-1", "membership-1",
			now.Add(time.Hour), revokedAt, "suspected compromise", 5, now, now, "user-1", "admin-1", now,
		))

	ctx := principal.WithContext(
		context.Background(),
		principal.Principal{ID: "admin-1", Type: principal.TypeUser},
	)
	updated, err := service.RevokeSessionByID(ctx, "session-1", "suspected compromise", 4)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 5 || updated.RevokedAt == nil || updated.UpdatedBy != "admin-1" {
		t.Fatalf("RevokeSessionByID() = %#v", updated)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func sessionRows(_ time.Time) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "user_id", "refresh_token_hash", "tenant_id", "membership_id", "expires_at",
		"revoked_at", "revoke_reason", "version", "created_at", "updated_at", "created_by",
		"updated_by", "last_used_at",
	})
}
