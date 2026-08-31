ALTER TABLE users
    ADD COLUMN username VARCHAR(64),
    ADD COLUMN phone VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'active',
    ADD COLUMN failed_login_count INT NOT NULL DEFAULT 0,
    ADD COLUMN locked_until DATETIME(6) NULL;

UPDATE users SET username = CONCAT('user_', REPLACE(id, '-', '')) WHERE username IS NULL;
CREATE UNIQUE INDEX uq_users_username ON users (username);

CREATE TABLE credentials (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    type VARCHAR(32) NOT NULL,
    secret_hash TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    UNIQUE KEY uq_credentials_user_type (user_id, type),
    CONSTRAINT fk_credentials_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE sessions (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    refresh_token_hash VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(36) NOT NULL DEFAULT '',
    membership_id VARCHAR(36) NOT NULL DEFAULT '',
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6) NULL,
    revoke_reason VARCHAR(255) NOT NULL DEFAULT '',
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    last_used_at DATETIME(6) NOT NULL,
    INDEX idx_sessions_user_expires (user_id, expires_at),
    INDEX idx_sessions_revoked_retention (revoked_at, id),
    INDEX idx_sessions_expired_retention (expires_at, id),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE service_accounts (
    id VARCHAR(36) PRIMARY KEY,
    client_id VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    secret_hash TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    audiences_json TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE outbox_events (
    id VARCHAR(36) PRIMARY KEY,
    subject VARCHAR(255) NOT NULL,
    envelope LONGBLOB NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    available_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    published_at DATETIME(6) NULL,
    last_error TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_outbox_events_pending ON outbox_events (published_at, available_at, created_at);
