package identity

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
)

func TestRepositoryListUsersFiltersAndPaginates(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := NewRepository(sqlx.NewDb(db, "sqlmock"))
	pattern := "%alice%"
	where := " WHERE 1=1 AND status = ? AND (LOWER(username) LIKE LOWER(?) OR LOWER(name) LIKE LOWER(?) OR LOWER(email) LIKE LOWER(?))"
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM users"+where)).
		WithArgs(StatusActive, pattern, pattern, pattern).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT "+userColumns+" FROM users"+where+" ORDER BY created_at DESC, id LIMIT ? OFFSET ?")).
		WithArgs(StatusActive, pattern, pattern, pattern, 20, 20).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until", "version", "created_at", "updated_at", "created_by", "updated_by"}).
			AddRow("user-1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 1, now, now, "admin", "admin"))

	users, total, err := repository.ListUsers(t.Context(), "alice", StatusActive, 20, 20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(users) != 1 || users[0].ID != "user-1" {
		t.Fatalf("ListUsers() = users:%#v total:%d", users, total)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
