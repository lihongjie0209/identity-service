package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	SubjectType  string `json:"subject_type"`
	SessionID    string `json:"sid,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	MembershipID string `json:"membership_id,omitempty"`
	jwt.RegisteredClaims
}

type TokenIssuer struct {
	issuer     string
	audiences  []string
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	ttl        time.Duration
	now        func() time.Time
}

func NewTokenIssuer(issuer string, audiences []string, keyID string, privateKey ed25519.PrivateKey, ttl time.Duration) (*TokenIssuer, error) {
	if issuer == "" || len(audiences) == 0 || keyID == "" || len(privateKey) != ed25519.PrivateKeySize || ttl <= 0 {
		return nil, errors.New("issuer, audience, key id, Ed25519 private key, and positive ttl are required")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &TokenIssuer{issuer: issuer, audiences: audiences, keyID: keyID, privateKey: privateKey, publicKey: publicKey, ttl: ttl, now: time.Now}, nil
}

func GenerateSigningKey() (ed25519.PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	return privateKey, err
}

func (i *TokenIssuer) Issue(subject, subjectType, sessionID, tenantID, membershipID string) (string, time.Time, error) {
	if subject == "" || subjectType == "" {
		return "", time.Time{}, errors.New("token subject and subject type are required")
	}
	now := i.now().UTC()
	expiresAt := now.Add(i.ttl)
	tokenID, err := randomTokenID()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate token id: %w", err)
	}
	claims := TokenClaims{
		SubjectType: subjectType, SessionID: sessionID, TenantID: tenantID, MembershipID: membershipID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: i.issuer, Subject: subject, Audience: i.audiences,
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt), ID: tokenID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = i.keyID
	signed, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return signed, expiresAt, nil
}

func (i *TokenIssuer) Parse(raw string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &TokenClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA || token.Header["kid"] != i.keyID {
			return nil, errors.New("unexpected token signing key or method")
		}
		return i.publicKey, nil
	}, jwt.WithIssuer(i.issuer), jwt.WithAudience(i.audiences[0]), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(i.now))
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid access token claims")
	}
	return claims, nil
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	X         string `json:"x"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (i *TokenIssuer) JWKS() JWKS {
	return JWKS{Keys: []JWK{{KeyType: "OKP", Use: "sig", KeyID: i.keyID, Curve: "Ed25519", Algorithm: "EdDSA", X: base64.RawURLEncoding.EncodeToString(i.publicKey)}}}
}

func randomTokenID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
