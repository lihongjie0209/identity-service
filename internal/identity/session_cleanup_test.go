package identity

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lihongjie0209/identity-service/internal/config"
	"go.uber.org/fx/fxtest"
)

type sessionRetentionStub struct {
	counts          []int64
	challengeCounts []int64
	before          []time.Time
	challengeBefore []time.Time
}

func (s *sessionRetentionStub) DeleteExpiredMFAChallengesBefore(
	_ context.Context,
	before time.Time,
	_ int,
) (int64, error) {
	s.challengeBefore = append(s.challengeBefore, before)
	count := s.challengeCounts[0]
	s.challengeCounts = s.challengeCounts[1:]
	return count, nil
}

func (s *sessionRetentionStub) DeleteExpiredOrRevokedSessionsBefore(_ context.Context, before time.Time, _ int) (int64, error) {
	s.before = append(s.before, before)
	count := s.counts[0]
	s.counts = s.counts[1:]
	return count, nil
}

func TestSessionCleanerDeletesInBoundedBatches(t *testing.T) {
	t.Parallel()

	store := &sessionRetentionStub{counts: []int64{2, 1}, challengeCounts: []int64{2, 0}}
	cleaner, err := newSessionCleaner(fxtest.NewLifecycle(t), store, slog.New(slog.NewTextHandler(io.Discard, nil)), config.Config{Database: config.Database{Enabled: true}, Cron: config.Cron{SessionRetention: 30 * 24 * time.Hour, SessionCleanupInterval: time.Hour, SessionCleanupBatchSize: 2}})
	if err != nil {
		t.Fatalf("newSessionCleaner() error = %v", err)
	}
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	cleaner.now = func() time.Time { return now }
	if err := cleaner.clean(t.Context()); err != nil {
		t.Fatalf("clean() error = %v", err)
	}
	if len(store.before) != 2 || !store.before[0].Equal(now.Add(-30*24*time.Hour)) {
		t.Fatalf("unexpected cleanup cutoffs: %v", store.before)
	}
	if len(store.challengeBefore) != 2 || !store.challengeBefore[0].Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("unexpected mfa challenge cleanup cutoffs: %v", store.challengeBefore)
	}
}

func TestSessionCleanerAppliesSafeDefaults(t *testing.T) {
	t.Parallel()

	cleaner, err := newSessionCleaner(
		fxtest.NewLifecycle(t),
		&sessionRetentionStub{counts: []int64{0}, challengeCounts: []int64{0}},
		slog.Default(),
		config.Config{},
	)
	if err != nil {
		t.Fatalf("newSessionCleaner() error = %v", err)
	}
	if cleaner.retention != 30*24*time.Hour || cleaner.interval != time.Hour || cleaner.batchSize != 500 {
		t.Fatalf("unexpected defaults: retention=%v interval=%v batch=%d", cleaner.retention, cleaner.interval, cleaner.batchSize)
	}
}
