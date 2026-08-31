package identity

import (
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/database"
)

func TestRepositoryListServiceAccountsFiltersAndPaginates(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := NewRepository(sqlx.NewDb(db, "sqlmock"))
	pattern := "%report%"
	where := " WHERE 1=1 AND status = ? AND (LOWER(client_id) LIKE LOWER(?) OR LOWER(name) LIKE LOWER(?))"
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM service_accounts"+where)).
		WithArgs(StatusActive, pattern, pattern).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT "+serviceAccountColumns+" FROM service_accounts"+where+
			" ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
	)).
		WithArgs(StatusActive, pattern, pattern, 20, 20).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "client_id", "name", "secret_hash", "status", "audiences_json",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow(
			"account-1", "svc_report", "Reporting", "secret-hash", StatusActive,
			`["reporting-api"]`, 1, now, now, "admin", "admin",
		))

	accounts, total, err := repository.ListServiceAccounts(
		t.Context(),
		"report",
		StatusActive,
		20,
		20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(accounts) != 1 || accounts[0].ID != "account-1" {
		t.Fatalf("ListServiceAccounts() = accounts:%#v total:%d", accounts, total)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceListServiceAccountsNormalizesPaginationAndAudiences(t *testing.T) {
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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM service_accounts WHERE 1=1")).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT "+serviceAccountColumns+
			" FROM service_accounts WHERE 1=1 ORDER BY created_at DESC, id LIMIT ? OFFSET ?",
	)).
		WithArgs(20, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "client_id", "name", "secret_hash", "status", "audiences_json",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow(
			"account-1", "svc_report", "Reporting", "secret-hash", StatusActive,
			`["reporting-api","billing-api"]`, 1, now, now, "admin", "admin",
		))

	page, err := service.ListServiceAccounts(t.Context(), "", "", 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if page.Page != 1 || page.PageSize != 20 || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("ListServiceAccounts() = %#v", page)
	}
	if len(page.Items[0].Audiences) != 2 || page.Items[0].Audiences[1] != "billing-api" {
		t.Fatalf("audiences = %#v", page.Items[0].Audiences)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceListServiceAccountsRejectsUnknownStatus(t *testing.T) {
	t.Parallel()
	service := &Service{}
	_, err := service.ListServiceAccounts(t.Context(), "", "closed", 1, 20)
	var appErr *apperror.Error
	if !errors.As(err, &appErr) || appErr.Code != apperror.CodeInvalidArgument {
		t.Fatalf("ListServiceAccounts() error = %v", err)
	}
}
