CREATE INDEX outbox_events_retention_idx ON outbox_events (published_at, id);
