package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lihongjie0209/identity-service/internal/config"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
	"github.com/lihongjie0209/microservice-platform-go/authn"
	"github.com/lihongjie0209/microservice-platform-go/principal"
)

type Claims struct{ jwt.RegisteredClaims }
type Service struct {
	issuer       string
	secret       []byte
	ttl          time.Duration
	clientID     string
	clientSecret string
	identities   *identitydomain.Service
}

func (s *Service) VerifyBearer(_ context.Context, raw string) (principal.Principal, error) {
	if s.identities != nil {
		claims, err := s.identities.Parse(raw)
		if err != nil {
			return principal.Principal{}, err
		}
		return principal.Principal{ID: claims.Subject, Type: principal.Type(claims.SubjectType), TenantID: claims.TenantID, MembershipID: claims.MembershipID, SessionID: claims.SessionID}, nil
	}
	claims, err := s.Parse(raw)
	if err != nil {
		return principal.Principal{}, err
	}
	return principal.Principal{ID: claims.Subject, Type: principal.TypeServiceAccount}, nil
}

func (s *Service) Policy(cfg config.Auth) authn.Policy {
	policy := authn.Policy{SkipTargets: cfg.SkipHTTPPaths, Bearer: s}
	if cfg.PSK.Enabled {
		policy.PSK = []authn.PSKPolicy{{
			Key:       cfg.PSK.Key,
			Targets:   cfg.PSK.HTTPPaths,
			Principal: principal.Principal{ID: "psk", Type: principal.TypeServiceAccount},
		}}
	}
	return policy
}

func (s *Service) GRPCPolicy(cfg config.Auth) authn.Policy {
	policy := authn.Policy{SkipTargets: cfg.SkipGRPCMethods, Bearer: s}
	if cfg.PSK.Enabled {
		policy.PSK = []authn.PSKPolicy{{
			Key:       cfg.PSK.Key,
			Targets:   cfg.PSK.GRPCMethods,
			Principal: principal.Principal{ID: "psk", Type: principal.TypeServiceAccount},
		}}
	}
	return policy
}

func New(cfg config.Config) *Service {
	return &Service{issuer: cfg.JWT.Issuer, secret: []byte(cfg.JWT.Secret), ttl: cfg.JWT.TTL, clientID: cfg.Auth.ClientID, clientSecret: cfg.Auth.ClientSecret}
}

func NewWithIdentity(cfg config.Config, identities *identitydomain.Service) *Service {
	service := New(cfg)
	service.identities = identities
	return service
}

func (s *Service) Enabled() bool {
	return len(s.secret) >= 32 && s.clientID != "" && s.clientSecret != ""
}
func (s *Service) Authenticate(clientID, clientSecret string) bool {
	if !s.Enabled() {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(clientID), []byte(s.clientID)) == 1 && subtle.ConstantTimeCompare([]byte(clientSecret), []byte(s.clientSecret)) == 1
}
func (s *Service) Issue(subject string) (string, error) {
	if !s.Enabled() {
		return "", errors.New("authentication is not configured")
	}
	now := time.Now()
	jti, err := randomID()
	if err != nil {
		return "", fmt.Errorf("create token id: %w", err)
	}
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: s.issuer, Subject: subject, ID: jti, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl))}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}
func (s *Service) Parse(raw string) (*Claims, error) {
	if !s.Enabled() {
		return nil, errors.New("authentication is not configured")
	}
	token, err := jwt.ParseWithClaims(raw, &Claims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
		}
		return s.secret, nil
	}, jwt.WithIssuer(s.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid jwt claims")
	}
	return claims, nil
}
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
