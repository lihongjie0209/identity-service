package identity

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lihongjie0209/identity-service/internal/config"
	"go.uber.org/fx"
)

type sessionRetentionStore interface {
	DeleteExpiredOrRevokedSessionsBefore(context.Context, time.Time, int) (int64, error)
}

type SessionCleaner struct {
	store     sessionRetentionStore
	logger    *slog.Logger
	retention time.Duration
	interval  time.Duration
	batchSize int
	enabled   bool
	now       func() time.Time
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewSessionCleaner(lifecycle fx.Lifecycle, repository *Repository, logger *slog.Logger, cfg config.Config) (*SessionCleaner, error) {
	return newSessionCleaner(lifecycle, repository, logger, cfg)
}

func newSessionCleaner(lifecycle fx.Lifecycle, store sessionRetentionStore, logger *slog.Logger, cfg config.Config) (*SessionCleaner, error) {
	if store == nil {
		return nil, nil
	}
	if logger == nil {
		return nil, errors.New("identity session cleaner logger is required")
	}
	if cfg.Cron.SessionRetention <= 0 {
		cfg.Cron.SessionRetention = 30 * 24 * time.Hour
	}
	if cfg.Cron.SessionCleanupInterval <= 0 {
		cfg.Cron.SessionCleanupInterval = time.Hour
	}
	if cfg.Cron.SessionCleanupBatchSize <= 0 {
		cfg.Cron.SessionCleanupBatchSize = 500
	}
	cleaner := &SessionCleaner{store: store, logger: logger, retention: cfg.Cron.SessionRetention, interval: cfg.Cron.SessionCleanupInterval, batchSize: cfg.Cron.SessionCleanupBatchSize, enabled: cfg.Database.Enabled, now: time.Now}
	lifecycle.Append(fx.Hook{OnStart: cleaner.start, OnStop: cleaner.stop})
	return cleaner, nil
}

func (c *SessionCleaner) clean(ctx context.Context) error {
	for {
		deleted, err := c.store.DeleteExpiredOrRevokedSessionsBefore(ctx, c.now().Add(-c.retention), c.batchSize)
		if err != nil {
			return err
		}
		if deleted > 0 {
			c.logger.InfoContext(ctx, "deleted expired identity sessions", "count", deleted)
		}
		if deleted < int64(c.batchSize) {
			return nil
		}
	}
}

func (c *SessionCleaner) start(context.Context) error {
	if !c.enabled {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			if err := c.clean(ctx); err != nil && !errors.Is(err, context.Canceled) {
				c.logger.ErrorContext(ctx, "clean expired identity sessions", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}

func (c *SessionCleaner) stop(context.Context) error {
	if c.cancel != nil {
		c.cancel()
		c.wg.Wait()
	}
	return nil
}
