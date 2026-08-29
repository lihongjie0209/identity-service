DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS service_accounts;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS credentials;
DROP INDEX IF EXISTS uq_users_email_lower;
DROP INDEX IF EXISTS uq_users_username_lower;
ALTER TABLE users
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS failed_login_count,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS phone,
    DROP COLUMN IF EXISTS username;

