package identity

import (
	"time"

	"github.com/lihongjie0209/microservice-platform-go/audit"
)

const (
	MFAStatusPending  = "pending"
	MFAStatusEnabled  = "enabled"
	MFAStatusDisabled = "disabled"
)

type MFAEnrollment struct {
	UserID           string     `db:"user_id"`
	Method           string     `db:"method"`
	SecretCiphertext string     `db:"secret_ciphertext"`
	Status           string     `db:"status"`
	LastUsedStep     int64      `db:"last_used_step"`
	EnabledAt        *time.Time `db:"enabled_at"`
	audit.Fields
}

type MFARecoveryCode struct {
	ID         string     `db:"id"`
	UserID     string     `db:"user_id"`
	CodeHash   string     `db:"code_hash"`
	ConsumedAt *time.Time `db:"consumed_at"`
	audit.Fields
}

type MFALoginChallenge struct {
	TokenHash  string     `db:"token_hash"`
	UserID     string     `db:"user_id"`
	ClientIP   string     `db:"client_ip"`
	UserAgent  string     `db:"user_agent"`
	ExpiresAt  time.Time  `db:"expires_at"`
	ConsumedAt *time.Time `db:"consumed_at"`
	audit.Fields
}

type MFAStatus struct {
	Available              bool
	Enabled                bool
	Status                 string
	RecoveryCodesRemaining int64
	Version                int64
	EnabledAt              *time.Time
}

type MFASetup struct {
	Secret    string
	URI       string
	Version   int64
	ExpiresAt time.Time
}

type MFAConfirmation struct {
	RecoveryCodes   []string
	RevokedSessions uint64
	Version         int64
}

type MFARecoveryRotation struct {
	RecoveryCodes []string
	Version       int64
}

type LoginResult struct {
	Tokens             Tokens
	MFARequired        bool
	MFAChallengeToken  string
	MFAChallengeExpiry *time.Time
}
