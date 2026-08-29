package identity

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
)

func TestRepositoryUserByLoginScansEmbeddedAuditFields(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	repository := NewRepository(sqlx.NewDb(db, "sqlmock"))
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT "+userColumns+" FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)")).WithArgs("alice", "alice").WillReturnRows(sqlmock.NewRows([]string{"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until", "version", "created_at", "updated_at", "created_by", "updated_by"}).AddRow("u1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 1, now, now, "admin", "admin"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by FROM credentials WHERE user_id = ? AND type = 'password'")).WithArgs("u1").WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "type", "secret_hash", "status", "version", "created_at", "updated_at", "created_by", "updated_by"}).AddRow("c1", "u1", "password", "hash", StatusActive, 1, now, now, "admin", "admin"))
	user, credential, err := repository.UserByLogin(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if user.CreatedBy != "admin" || credential.UpdatedBy != "admin" {
		t.Fatalf("user=%#v credential=%#v", user, credential)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
