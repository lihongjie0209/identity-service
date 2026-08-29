package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestTokenIssuerRoundTripAndJWKS(t *testing.T) {
	t.Parallel()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	issuer, err := NewTokenIssuer("identity-service", []string{"platform-api"}, "key-1", privateKey, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return time.Unix(1000, 0) }
	raw, expiresAt, err := issuer.Issue("user-1", "user", "session-1", "tenant-1", "membership-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := issuer.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-1" || claims.SessionID != "session-1" || claims.TenantID != "tenant-1" || claims.MembershipID != "membership-1" {
		t.Fatalf("claims = %+v", claims)
	}
	if !expiresAt.Equal(time.Unix(1000, 0).Add(15 * time.Minute)) {
		t.Fatalf("expires at = %v", expiresAt)
	}
	jwks := issuer.JWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyID != "key-1" || jwks.Keys[0].Algorithm != "EdDSA" {
		t.Fatalf("JWKS = %+v", jwks)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("JWK public key = %x, %v", publicKey, err)
	}
}

func TestTokenIssuerRejectsWrongKey(t *testing.T) {
	t.Parallel()
	first, _ := GenerateSigningKey()
	second, _ := GenerateSigningKey()
	issuer, _ := NewTokenIssuer("identity-service", []string{"platform-api"}, "key-1", first, time.Minute)
	other, _ := NewTokenIssuer("identity-service", []string{"platform-api"}, "key-2", second, time.Minute)
	raw, _, _ := issuer.Issue("user-1", "user", "", "", "")
	if _, err := other.Parse(raw); err == nil {
		t.Fatal("Parse() error = nil")
	}
}

func TestTokenIssuerAcceptsPreviousVerificationKey(t *testing.T) {
	t.Parallel()
	oldKey, _ := GenerateSigningKey()
	newKey, _ := GenerateSigningKey()
	oldIssuer, _ := NewTokenIssuer("identity-service", []string{"platform-api"}, "key-old", oldKey, time.Minute)
	newIssuer, _ := NewTokenIssuer("identity-service", []string{"platform-api"}, "key-new", newKey, time.Minute)
	if err := newIssuer.AddVerificationKey("key-old", oldKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	raw, _, err := oldIssuer.Issue("user-1", "user", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newIssuer.Parse(raw); err != nil {
		t.Fatalf("Parse old token after rotation: %v", err)
	}
	if got := newIssuer.JWKS(); len(got.Keys) != 2 {
		t.Fatalf("JWKS keys=%d", len(got.Keys))
	}
}
