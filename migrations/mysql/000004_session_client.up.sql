ALTER TABLE sessions
    ADD COLUMN client_ip TEXT NULL,
    ADD COLUMN user_agent TEXT NULL;

UPDATE sessions SET client_ip = '', user_agent = '' WHERE client_ip IS NULL OR user_agent IS NULL;

ALTER TABLE sessions
    MODIFY COLUMN client_ip TEXT NOT NULL,
    MODIFY COLUMN user_agent TEXT NOT NULL;
