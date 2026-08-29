package identity

import (
	"time"

	"github.com/lihongjie0209/microservice-platform-go/audit"
)

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusLocked   = "locked"
	StatusClosed   = "closed"
)

type User struct {
	ID               string     `db:"id" json:"id"`
	Username         string     `db:"username" json:"username"`
	DisplayName      string     `db:"name" json:"display_name"`
	Email            string     `db:"email" json:"email"`
	Phone            string     `db:"phone" json:"phone"`
	Status           string     `db:"status" json:"status"`
	FailedLoginCount int        `db:"failed_login_count" json:"-"`
	LockedUntil      *time.Time `db:"locked_until" json:"locked_until,omitempty"`
	audit.Fields
}

type Credential struct {
	ID         string `db:"id"`
	UserID     string `db:"user_id"`
	Type       string `db:"type"`
	SecretHash string `db:"secret_hash"`
	Status     string `db:"status"`
	audit.Fields
}

type Session struct {
	ID               string     `db:"id" json:"session_id"`
	UserID           string     `db:"user_id" json:"user_id"`
	RefreshTokenHash string     `db:"refresh_token_hash" json:"-"`
	TenantID         string     `db:"tenant_id" json:"tenant_id,omitempty"`
	MembershipID     string     `db:"membership_id" json:"membership_id,omitempty"`
	ExpiresAt        time.Time  `db:"expires_at" json:"expires_at"`
	RevokedAt        *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	RevokeReason     string     `db:"revoke_reason" json:"revoke_reason,omitempty"`
	LastUsedAt       time.Time  `db:"last_used_at" json:"last_used_at"`
	audit.Fields
}

type ServiceAccount struct {
	ID            string   `db:"id" json:"id"`
	ClientID      string   `db:"client_id" json:"client_id"`
	Name          string   `db:"name" json:"name"`
	SecretHash    string   `db:"secret_hash" json:"-"`
	Status        string   `db:"status" json:"status"`
	AudiencesJSON string   `db:"audiences_json" json:"-"`
	Audiences     []string `db:"-" json:"audiences"`
	audit.Fields
}

type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	SessionID    string    `json:"session_id"`
}

type OutboxEvent struct {
	ID          string
	Subject     string
	Envelope    []byte
	AvailableAt time.Time
	audit.Fields
}
