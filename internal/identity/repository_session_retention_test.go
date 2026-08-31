package identity

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
)

func TestRepositoryDeleteExpiredOrRevokedSessionsBefore(t *testing.T) {
	t.Parallel()

	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	repository := NewRepository(sqlx.NewDb(database, "sqlmock"))
	before := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	selectQuery := "SELECT id FROM sessions WHERE (revoked_at IS NOT NULL AND revoked_at<?) OR (revoked_at IS NULL AND expires_at<?) ORDER BY COALESCE(revoked_at,expires_at),id LIMIT ?"
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).WithArgs(before, before, 2).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("session-1").AddRow("session-2"))
	mock.ExpectExec(regexp.QuoteMeta("DELETE FROM sessions WHERE id IN (?, ?) AND ((revoked_at IS NOT NULL AND revoked_at<?) OR (revoked_at IS NULL AND expires_at<?))")).WithArgs("session-1", "session-2", before, before).WillReturnResult(sqlmock.NewResult(0, 2))

	deleted, err := repository.DeleteExpiredOrRevokedSessionsBefore(t.Context(), before, 2)
	if err != nil {
		t.Fatalf("DeleteExpiredOrRevokedSessionsBefore() error = %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
