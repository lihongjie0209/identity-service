package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 interoperability requires HMAC-SHA1; it is not used for signatures.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpPeriod        = 30 * time.Second
	totpDigits        = 6
	totpWindow        = 1
	totpSecretBytes   = 20
	recoveryCodeCount = 10
	recoveryCodeBytes = 10
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

type MFACrypto struct {
	aead           cipher.AEAD
	recoveryPepper []byte
	issuer         string
}

func NewMFACrypto(issuer, encryptionKey, recoveryPepper string) (*MFACrypto, error) {
	key, err := decodeMFAKey(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decode mfa encryption key: %w", err)
	}
	pepper, err := decodeMFAKey(recoveryPepper)
	if err != nil {
		return nil, fmt.Errorf("decode mfa recovery pepper: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create mfa cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create mfa aead: %w", err)
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, errors.New("mfa issuer is required")
	}
	return &MFACrypto{aead: aead, recoveryPepper: pepper, issuer: issuer}, nil
}

func decodeMFAKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("key must be base64 encoded 32 bytes")
}

func (m *MFACrypto) GenerateTOTP(account string) (secret, uri string, err error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate totp secret: %w", err)
	}
	secret = base32NoPadding.EncodeToString(raw)
	label := m.issuer + ":" + strings.TrimSpace(account)
	query := url.Values{
		"secret":    []string{secret},
		"issuer":    []string{m.issuer},
		"algorithm": []string{"SHA1"},
		"digits":    []string{strconv.Itoa(totpDigits)},
		"period":    []string{strconv.Itoa(int(totpPeriod / time.Second))},
	}
	uri = (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + label, RawQuery: query.Encode()}).String()
	return secret, uri, nil
}

func (m *MFACrypto) EncryptSecret(userID, secret string) (string, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate mfa nonce: %w", err)
	}
	ciphertext := m.aead.Seal(nil, nonce, []byte(secret), []byte(userID))
	payload := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func (m *MFACrypto) DecryptSecret(userID, encrypted string) (string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil || len(payload) < m.aead.NonceSize() {
		return "", errors.New("invalid encrypted mfa secret")
	}
	nonce := payload[:m.aead.NonceSize()]
	plaintext, err := m.aead.Open(nil, nonce, payload[m.aead.NonceSize():], []byte(userID))
	if err != nil {
		return "", errors.New("decrypt mfa secret")
	}
	return string(plaintext), nil
}

func (m *MFACrypto) ValidateTOTP(secret, code string, now time.Time) (int64, bool) {
	secretBytes, err := base32NoPadding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(secretBytes) == 0 || len(code) != totpDigits {
		return 0, false
	}
	step := now.Unix() / int64(totpPeriod/time.Second)
	for offset := int64(-totpWindow); offset <= totpWindow; offset++ {
		candidateStep := step + offset
		if candidateStep < 0 {
			continue
		}
		expected := hotp(secretBytes, uint64(candidateStep), totpDigits)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return candidateStep, true
		}
	}
	return 0, false
}

func hotp(secret []byte, counter uint64, digits int) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for range digits {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%modulus)
}

func (m *MFACrypto) GenerateRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	hashes := make([]string, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("generate recovery code: %w", err)
		}
		compact := base32NoPadding.EncodeToString(raw)
		code := compact[:4] + "-" + compact[4:8] + "-" + compact[8:12] + "-" + compact[12:]
		codes = append(codes, code)
		hashes = append(hashes, m.RecoveryCodeHash(code))
	}
	return codes, hashes, nil
}

func (m *MFACrypto) RecoveryCodeHash(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	mac := hmac.New(sha256.New, m.recoveryPepper)
	_, _ = mac.Write([]byte(normalized))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
