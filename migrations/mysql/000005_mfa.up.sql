CREATE TABLE user_mfa (
    user_id VARCHAR(36) PRIMARY KEY,
    method VARCHAR(16) NOT NULL,
    secret_ciphertext TEXT NOT NULL,
    status VARCHAR(16) NOT NULL,
    last_used_step BIGINT NOT NULL DEFAULT -1,
    enabled_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    CONSTRAINT fk_user_mfa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_user_mfa_method CHECK (method = 'totp'),
    CONSTRAINT chk_user_mfa_status CHECK (status IN ('pending', 'enabled', 'disabled'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE mfa_recovery_codes (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    consumed_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    UNIQUE KEY uq_mfa_recovery_user_hash (user_id, code_hash),
    INDEX idx_mfa_recovery_codes_active (user_id, consumed_at, id),
    CONSTRAINT fk_mfa_recovery_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE mfa_login_challenges (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    consumed_at DATETIME(6) NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    INDEX idx_mfa_login_challenges_expiry (expires_at, token_hash),
    CONSTRAINT fk_mfa_challenge_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
