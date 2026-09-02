CREATE TABLE user_mfa (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    secret_ciphertext TEXT NOT NULL,
    status TEXT NOT NULL,
    last_used_step BIGINT NOT NULL DEFAULT -1,
    enabled_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    CHECK (method = 'totp'),
    CHECK (status IN ('pending', 'enabled', 'disabled'))
);

CREATE TABLE mfa_recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    consumed_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    UNIQUE (user_id, code_hash)
);
CREATE INDEX idx_mfa_recovery_codes_active ON mfa_recovery_codes (user_id, id) WHERE consumed_at IS NULL;

CREATE TABLE mfa_login_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE INDEX idx_mfa_login_challenges_expiry ON mfa_login_challenges (expires_at, token_hash);
COMMENT ON TABLE mfa_login_challenges IS 'Ephemeral MFA login challenges; delete consumed or expired rows after 24 hours.';
