package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lihongjie0209/identity-service/internal/config"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
)

type identityVerifierStub struct {
	claims *identitydomain.TokenClaims
	valid  bool
	err    error
}

func (stub *identityVerifierStub) Parse(string) (*identitydomain.TokenClaims, error) {
	return stub.claims, stub.err
}

func (stub *identityVerifierStub) ValidateSession(
	context.Context,
	string,
	string,
) (identitydomain.Session, bool, error) {
	return identitydomain.Session{}, stub.valid, stub.err
}

func TestService_IssueAndParse(t *testing.T) {
	t.Parallel()
	service := New(config.Config{JWT: config.JWT{Issuer: "test", Secret: "01234567890123456789012345678901", TTL: time.Hour}, Auth: config.Auth{ClientID: "client", ClientSecret: "secret"}})
	token, err := service.Issue("client")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	claims, err := service.Parse(token)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.Subject != "client" {
		t.Fatalf("Subject = %q, want client", claims.Subject)
	}
}

func TestService_Authenticate(t *testing.T) {
	t.Parallel()
	service := New(config.Config{JWT: config.JWT{Secret: "01234567890123456789012345678901"}, Auth: config.Auth{ClientID: "client", ClientSecret: "secret"}})
	if !service.Authenticate("client", "secret") {
		t.Fatal("Authenticate() = false, want true")
	}
	if service.Authenticate("client", "wrong") {
		t.Fatal("Authenticate() = true, want false")
	}
}

func TestServiceVerifyBearerRejectsRevokedUserSession(t *testing.T) {
	t.Parallel()
	service := &Service{identities: &identityVerifierStub{
		claims: &identitydomain.TokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "user-1"},
			SubjectType:      "user",
			SessionID:        "session-1",
		},
		valid: false,
	}}
	if _, err := service.VerifyBearer(t.Context(), "token"); err == nil {
		t.Fatal("VerifyBearer() error = nil")
	}
}

func TestServiceVerifyBearerAcceptsServiceAccountWithoutSessionLookup(t *testing.T) {
	t.Parallel()
	service := &Service{identities: &serviceAccountVerifierStub{
		claims: &identitydomain.TokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "service-account-1"},
			SubjectType:      "service_account",
		},
	}}
	principal, err := service.VerifyBearer(t.Context(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "service-account-1" {
		t.Fatalf("principal = %#v", principal)
	}
}

type serviceAccountVerifierStub struct {
	claims *identitydomain.TokenClaims
}

func (stub *serviceAccountVerifierStub) Parse(string) (*identitydomain.TokenClaims, error) {
	return stub.claims, nil
}

func (*serviceAccountVerifierStub) ValidateSession(
	context.Context,
	string,
	string,
) (identitydomain.Session, bool, error) {
	return identitydomain.Session{}, false, errors.New("unexpected session lookup")
}
