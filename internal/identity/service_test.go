package identity

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/identity-service/internal/apperror"
	"github.com/lihongjie0209/identity-service/internal/config"
	"github.com/lihongjie0209/identity-service/internal/database"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

func TestServiceRegisterPersistsAuditActorInOneTransaction(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(NewRepository(sqlDB), database.NewTransactor(sqlDB), config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	service.hasher, _ = NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO users (id, username, name, email, phone, status, failed_login_count, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")).WithArgs(sqlmock.AnyArg(), "alice", "Alice", "alice@example.com", "", StatusActive, 0, int64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), "admin-1", "admin-1").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO credentials (id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "password", sqlmock.AnyArg(), StatusActive, int64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), "admin-1", "admin-1").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)")).WithArgs(sqlmock.AnyArg(), "platform.identity.user.created.v1", sqlmock.AnyArg(), sqlmock.AnyArg(), int64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), "admin-1", "admin-1").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	ctx := principal.WithContext(context.Background(), principal.Principal{ID: "admin-1", Type: principal.TypeUser})
	created, err := service.Register(ctx, "Alice", "Alice", "ALICE@example.com", "", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if created.Username != "alice" || created.CreatedBy != "admin-1" {
		t.Fatalf("created = %#v", created)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceIssuesTokenForConfiguredServiceAudiences(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	audiences := []string{"identity-service", "tenant-service", "authorization-service"}
	service, err := NewService(NewRepository(sqlx.NewDb(db, "sqlmock")), &database.Transactor{}, config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "identity-service", Audiences: audiences, Secret: "01234567890123456789012345678901", TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := service.issuer.Issue("user-1", "user", "session-1", "tenant-1", "membership-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := service.issuer.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, audience := range audiences {
		if !slices.Contains(claims.Audience, audience) {
			t.Fatalf("token audiences %v do not contain %q", claims.Audience, audience)
		}
	}
}

func TestIssueTenantTokenRequiresTrustedService(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(NewRepository(sqlDB), database.NewTransactor(sqlDB), config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}

	userContext := principal.WithContext(t.Context(), principal.Principal{ID: "user-1", Type: principal.TypeUser})
	if _, _, err := service.IssueTenantToken(userContext, "user-1", "tenant-1", "membership-1", "session-1"); identityErrorCode(err) != apperror.CodeForbidden {
		t.Fatalf("IssueTenantToken(user) error = %#v, want forbidden", err)
	}

	serviceContext := principal.WithContext(t.Context(), principal.Principal{ID: "tenant-service", Type: principal.TypeServiceAccount})
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE sessions SET tenant_id = ?, membership_id = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?")).WithArgs("tenant-1", "membership-1", sqlmock.AnyArg(), "tenant-service", "session-1", "user-1", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	token, _, err := service.IssueTenantToken(serviceContext, "user-1", "tenant-1", "membership-1", "session-1")
	if err != nil || token == "" {
		t.Fatalf("IssueTenantToken(service) token empty=%v error=%v", token == "", err)
	}
	claims, err := service.issuer.Parse(token)
	if err != nil || claims.TenantID != "tenant-1" || claims.MembershipID != "membership-1" || claims.SessionID != "session-1" {
		t.Fatalf("tenant token claims = %+v error=%v", claims, err)
	}
	if _, _, err := service.IssueTenantToken(serviceContext, "user-1", "", "membership-1", "session-1"); identityErrorCode(err) != apperror.CodeInvalidArgument {
		t.Fatalf("IssueTenantToken(invalid scope) error = %#v, want invalid", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func identityErrorCode(err error) int {
	var appErr *apperror.Error
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return 0
}

func TestServiceLoginRecordsFailureBeforeRejectingCredentials(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	sqlDB := sqlx.NewDb(db, "sqlmock")
	service, err := NewService(NewRepository(sqlDB), database.NewTransactor(sqlDB), config.Config{App: config.App{Name: "identity-service"}, JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	service.hasher, _ = NewPasswordHasher(PasswordParameters{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 16})
	hash, err := service.hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT "+userColumns+" FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)")).WithArgs("alice", "alice").WillReturnRows(sqlmock.NewRows([]string{"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until", "version", "created_at", "updated_at", "created_by", "updated_by"}).AddRow("u1", "alice", "Alice", "alice@example.com", "", StatusActive, 0, nil, 1, now, now, "admin", "admin"))
	mock.ExpectQuery("SELECT id, user_id, type, secret_hash").WithArgs("u1").WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "type", "secret_hash", "status", "version", "created_at", "updated_at", "created_by", "updated_by"}).AddRow("c1", "u1", "password", hash, StatusActive, 1, now, now, "admin", "admin"))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET failed_login_count = failed_login_count + 1, locked_until = CASE WHEN failed_login_count + 1 >= ? THEN ? ELSE locked_until END, version = version + 1, updated_at = ?, updated_by = 'identity:login' WHERE id = ?")).WithArgs(loginFailureThreshold, sqlmock.AnyArg(), sqlmock.AnyArg(), "u1").WillReturnResult(sqlmock.NewResult(0, 1))
	if _, err := service.Login(t.Context(), "alice", "wrong password value"); err == nil {
		t.Fatal("Login() error = nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceChangePasswordUpdatesCredentialAndRevokesOtherSessions(t *testing.T) {
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
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   16,
	})
	if err != nil {
		t.Fatal(err)
	}
	currentHash, err := service.hasher.Hash("current horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by FROM credentials WHERE user_id = ? AND type = 'password'")).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "type", "secret_hash", "status", "version", "created_at", "updated_at", "created_by", "updated_by"}).
			AddRow("credential-1", "user-1", "password", currentHash, StatusActive, 3, now, now, "admin", "admin"))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE credentials SET secret_hash = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE id = ? AND type = 'password' AND status = ? AND version = ?")).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "user-1", "credential-1", StatusActive, int64(3)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE user_id = ? AND id <> ? AND revoked_at IS NULL AND expires_at > ?")).
		WithArgs(sqlmock.AnyArg(), "password changed", sqlmock.AnyArg(), "user-1", "user-1", "session-current", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)")).
		WithArgs(sqlmock.AnyArg(), "platform.identity.user.password-changed.v1", sqlmock.AnyArg(), sqlmock.AnyArg(), int64(1), sqlmock.AnyArg(), sqlmock.AnyArg(), "user-1", "user-1").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	ctx := principal.WithContext(
		t.Context(),
		principal.Principal{ID: "user-1", Type: principal.TypeUser, SessionID: "session-current"},
	)
	revoked, err := service.ChangePassword(
		ctx,
		"current horse battery staple",
		"different horse battery staple",
	)
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 2 {
		t.Fatalf("ChangePassword() revoked = %d, want 2", revoked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceChangePasswordRejectsInvalidCurrentPasswordBeforeWriting(t *testing.T) {
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
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   16,
	})
	if err != nil {
		t.Fatal(err)
	}
	currentHash, err := service.hasher.Hash("current horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, user_id, type, secret_hash, status, version, created_at, updated_at, created_by, updated_by FROM credentials WHERE user_id = ? AND type = 'password'")).
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "type", "secret_hash", "status", "version", "created_at", "updated_at", "created_by", "updated_by"}).
			AddRow("credential-1", "user-1", "password", currentHash, StatusActive, 3, now, now, "admin", "admin"))

	ctx := principal.WithContext(
		t.Context(),
		principal.Principal{ID: "user-1", Type: principal.TypeUser, SessionID: "session-current"},
	)
	_, err = service.ChangePassword(ctx, "wrong horse battery staple", "different horse battery staple")
	if identityErrorCode(err) != apperror.CodeUnauthorized {
		t.Fatalf("ChangePassword() error = %#v, want unauthorized", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceUpdateUserStatusRevokesActiveSessionsWhenDisabling(t *testing.T) {
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
	now := time.Now().UTC()
	userRows := func(status string, version int64) *sqlmock.Rows {
		return sqlmock.NewRows([]string{
			"id", "username", "name", "email", "phone", "status", "failed_login_count", "locked_until",
			"version", "created_at", "updated_at", "created_by", "updated_by",
		}).AddRow(
			"user-1", "alice", "Alice", "alice@example.com", "", status, 0, nil, version,
			now, now, "admin-1", "admin-1",
		)
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + userColumns + " FROM users WHERE id = ?")).
		WithArgs("user-1").
		WillReturnRows(userRows(StatusActive, 4))
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("UPDATE users SET status=?, failed_login_count=0, locked_until=NULL, version=version+1, updated_at=?, updated_by=? WHERE id=? AND version=?")).
		WithArgs(StatusDisabled, sqlmock.AnyArg(), "admin-1", "user-1", int64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE sessions SET revoked_at = ?, revoke_reason = ?, version = version + 1, updated_at = ?, updated_by = ? WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?")).
		WithArgs(
			sqlmock.AnyArg(),
			"user status changed to disabled",
			sqlmock.AnyArg(),
			"admin-1",
			"user-1",
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO outbox_events (id, subject, envelope, attempts, available_at, published_at, last_error, version, created_at, updated_at, created_by, updated_by) VALUES (?, ?, ?, 0, ?, NULL, '', ?, ?, ?, ?, ?)")).
		WithArgs(
			sqlmock.AnyArg(),
			"platform.identity.user.status-changed.v1",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			int64(1),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"admin-1",
			"admin-1",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT " + userColumns + " FROM users WHERE id = ?")).
		WithArgs("user-1").
		WillReturnRows(userRows(StatusDisabled, 5))

	ctx := principal.WithContext(
		t.Context(),
		principal.Principal{ID: "admin-1", Type: principal.TypeUser, SessionID: "admin-session"},
	)
	updated, err := service.UpdateUserStatus(ctx, "user-1", StatusDisabled, "security review", 4)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != StatusDisabled || updated.Version != 5 {
		t.Fatalf("UpdateUserStatus() = %#v", updated)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
