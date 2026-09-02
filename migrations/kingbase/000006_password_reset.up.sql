CREATE TABLE password_reset_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE INDEX idx_password_reset_user_active ON password_reset_challenges (user_id, expires_at, token_hash);
CREATE INDEX idx_password_reset_expiry ON password_reset_challenges (expires_at, token_hash);
COMMENT ON TABLE password_reset_challenges IS 'One-time password recovery challenges; delete consumed or expired rows after 24 hours.';
