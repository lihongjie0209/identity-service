package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lihongjie0209/microservice-platform-go/outbox"
	commonv1 "github.com/lihongjie0209/platform-protos/gen/go/platform/common/v1"
	"google.golang.org/protobuf/proto"
)

type OutboxStore struct {
	db  *sqlx.DB
	now func() time.Time
}

func NewOutboxStore(db *sqlx.DB) *OutboxStore { return &OutboxStore{db: db, now: time.Now} }
func (s *OutboxStore) Claim(ctx context.Context, limit int, lease time.Duration) ([]outbox.Event, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin identity outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := s.now()
	var rows []struct {
		ID       string `db:"id"`
		Subject  string `db:"subject"`
		Envelope []byte `db:"envelope"`
	}
	if err := tx.SelectContext(ctx, &rows, s.db.Rebind("SELECT id, subject, envelope FROM outbox_events WHERE published_at IS NULL AND available_at <= ? ORDER BY available_at, created_at LIMIT ? FOR UPDATE SKIP LOCKED"), now, limit); err != nil {
		return nil, fmt.Errorf("select identity outbox: %w", err)
	}
	events := make([]outbox.Event, 0, len(rows))
	for _, row := range rows {
		envelope := new(commonv1.EventEnvelope)
		if err := proto.Unmarshal(row.Envelope, envelope); err != nil {
			return nil, fmt.Errorf("decode identity outbox %q: %w", row.ID, err)
		}
		if _, err := tx.ExecContext(ctx, s.db.Rebind("UPDATE outbox_events SET attempts=attempts+1, available_at=?, version=version+1, updated_at=?, updated_by='outbox-dispatcher' WHERE id=? AND published_at IS NULL"), now.Add(lease), now, row.ID); err != nil {
			return nil, fmt.Errorf("lease identity outbox %q: %w", row.ID, err)
		}
		events = append(events, outbox.Event{ID: row.ID, Subject: row.Subject, Envelope: envelope})
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit identity outbox claim: %w", err)
	}
	return events, nil
}
func (s *OutboxStore) MarkPublished(ctx context.Context, event outbox.Event, now time.Time) error {
	result, err := s.db.ExecContext(ctx, s.db.Rebind("UPDATE outbox_events SET published_at=?, version=version+1, updated_at=?, updated_by='outbox-dispatcher', last_error='' WHERE id=? AND published_at IS NULL"), now, now, event.ID)
	return identityOutboxAffected(result, err, event.ID)
}
func (s *OutboxStore) MarkFailed(ctx context.Context, event outbox.Event, message string, retryAt time.Time) error {
	if len(message) > 4096 {
		message = message[:4096]
	}
	result, err := s.db.ExecContext(ctx, s.db.Rebind("UPDATE outbox_events SET available_at=?, last_error=?, version=version+1, updated_at=?, updated_by='outbox-dispatcher' WHERE id=? AND published_at IS NULL"), retryAt, message, s.now(), event.ID)
	return identityOutboxAffected(result, err, event.ID)
}
func identityOutboxAffected(result sql.Result, err error, id string) error {
	if err != nil {
		return fmt.Errorf("update identity outbox %q: %w", id, err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("identity outbox %q is no longer pending", id)
	}
	return nil
}
