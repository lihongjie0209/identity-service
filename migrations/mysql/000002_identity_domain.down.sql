DROP TABLE IF EXISTS outbox_events;
DROP TABLE IF EXISTS service_accounts;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS credentials;
DROP INDEX uq_users_username ON users;
ALTER TABLE users
    DROP COLUMN locked_until,
    DROP COLUMN failed_login_count,
    DROP COLUMN status,
    DROP COLUMN phone,
    DROP COLUMN username;

