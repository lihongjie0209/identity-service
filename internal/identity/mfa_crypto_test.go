package identity

import (
	"encoding/base32"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testMFACrypto(t *testing.T) *MFACrypto {
	t.Helper()
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	pepper := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyzABCDEF"))
	crypto, err := NewMFACrypto("Platform", key, pepper)
	if err != nil {
		t.Fatal(err)
	}
	return crypto
}

func TestHOTPMatchesRFC4226Vectors(t *testing.T) {
	t.Parallel()
	secret := []byte("12345678901234567890")
	expected := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, want := range expected {
		if got := hotp(secret, uint64(counter), 6); got != want {
			t.Fatalf("hotp(counter=%d) = %q, want %q", counter, got, want)
		}
	}
}

func TestMFACryptoValidatesTOTPWindow(t *testing.T) {
	t.Parallel()
	mfa := testMFACrypto(t)
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(59, 0)
	code := hotp([]byte("12345678901234567890"), 1, 6)
	step, ok := mfa.ValidateTOTP(secret, code, now)
	if !ok || step != 1 {
		t.Fatalf("ValidateTOTP() = %d, %v", step, ok)
	}
	if _, ok := mfa.ValidateTOTP(secret, "000000", now); ok {
		t.Fatal("ValidateTOTP() accepted invalid code")
	}
}

func TestMFACryptoEncryptsWithUserBinding(t *testing.T) {
	t.Parallel()
	mfa := testMFACrypto(t)
	encrypted, err := mfa.EncryptSecret("user-1", "TOTPSECRET")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := mfa.DecryptSecret("user-1", encrypted)
	if err != nil || decrypted != "TOTPSECRET" {
		t.Fatalf("DecryptSecret() = %q, %v", decrypted, err)
	}
	if _, err := mfa.DecryptSecret("user-2", encrypted); err == nil {
		t.Fatal("DecryptSecret() accepted a different user binding")
	}
}

func TestMFACryptoGeneratesInteroperableURIAndRecoveryCodes(t *testing.T) {
	t.Parallel()
	mfa := testMFACrypto(t)
	secret, uri, err := mfa.GenerateTOTP("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Query().Get("secret") != secret || parsed.Query().Get("issuer") != "Platform" {
		t.Fatalf("GenerateTOTP() URI = %q", uri)
	}
	codes, hashes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount || len(hashes) != recoveryCodeCount {
		t.Fatalf("GenerateRecoveryCodes() = %d codes, %d hashes", len(codes), len(hashes))
	}
	seen := make(map[string]struct{}, len(codes))
	for index, code := range codes {
		if _, exists := seen[code]; exists || strings.Contains(hashes[index], code) {
			t.Fatalf("unsafe recovery code result at %d", index)
		}
		seen[code] = struct{}{}
		if got := mfa.RecoveryCodeHash(strings.ToLower(strings.ReplaceAll(code, "-", ""))); got != hashes[index] {
			t.Fatalf("RecoveryCodeHash() normalization mismatch at %d", index)
		}
	}
}
