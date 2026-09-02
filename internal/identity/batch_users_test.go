package identity

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
)

func TestServiceBatchGetUsersNormalizesAndDeduplicatesIDs(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := &Service{repository: NewRepository(sqlx.NewDb(db, "sqlmock"))}
	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT "+userColumns+" FROM users WHERE id IN (?, ?)")).
		WithArgs("user-1", "user-2").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow("user-1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 1, now, now, "admin", "admin"))

	users, err := service.BatchGetUsers(t.Context(), []string{" user-1 ", "user-2", "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].ID != "user-1" {
		t.Fatalf("BatchGetUsers() = %#v", users)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceBatchGetUsersRejectsInvalidInputBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()
	service := &Service{}
	tests := []struct {
		name string
		ids  []string
	}{
		{name: "too many IDs", ids: make([]string, 101)},
		{name: "empty ID", ids: []string{"user-1", " "}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.BatchGetUsers(t.Context(), test.ids)
			if identityErrorCode(err) != apperror.CodeInvalidArgument {
				t.Fatalf("BatchGetUsers() error = %#v, want invalid argument", err)
			}
		})
	}
}
