package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lihongjie0209/identity-service/internal/config"
	identitydomain "github.com/lihongjie0209/identity-service/internal/identity"
	"github.com/lihongjie0209/microservice-platform-go/eventbus"
	platformoutbox "github.com/lihongjie0209/microservice-platform-go/outbox"
	"go.uber.org/fx"
)

type eventRuntime struct {
	config config.Config
	store  *identitydomain.OutboxStore
	logger *slog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
	bus    *eventbus.Bus
}

func newEventRuntime(lifecycle fx.Lifecycle, cfg config.Config, store *identitydomain.OutboxStore, logger *slog.Logger) *eventRuntime {
	runtime := &eventRuntime{config: cfg, store: store, logger: logger}
	lifecycle.Append(fx.Hook{OnStart: runtime.start, OnStop: runtime.stop})
	return runtime
}
func (r *eventRuntime) start(ctx context.Context) error {
	if !r.config.EventBus.Enabled {
		return nil
	}
	bus, err := eventbus.New(ctx, eventbus.Config{URLs: r.config.EventBus.URLs, ClientName: r.config.App.Name, StreamName: r.config.EventBus.StreamName, Subjects: []string{"platform.>"}, Storage: r.config.EventBus.Storage, MaxAge: r.config.EventBus.MaxAge, DuplicateWindow: r.config.EventBus.DuplicateWindow, ConnectTimeout: r.config.EventBus.ConnectTimeout, PublishTimeout: r.config.EventBus.PublishTimeout})
	if err != nil {
		return err
	}
	dispatcher, err := platformoutbox.New(r.store, bus, platformoutbox.Config{BatchSize: r.config.EventBus.DispatchBatchSize, Lease: r.config.EventBus.DispatchLease, RetryDelay: r.config.EventBus.DispatchRetryDelay})
	if err != nil {
		_ = bus.Close()
		return err
	}
	r.bus = bus
	runCtx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Go(func() { r.dispatch(runCtx, dispatcher) })
	return nil
}
func (r *eventRuntime) dispatch(ctx context.Context, dispatcher *platformoutbox.Dispatcher) {
	ticker := time.NewTicker(r.config.EventBus.DispatchInterval)
	defer ticker.Stop()
	for {
		if _, err := dispatcher.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.ErrorContext(ctx, "dispatch identity outbox failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *eventRuntime) stop(context.Context) error {
	if r.cancel != nil {
		r.cancel()
		r.wg.Wait()
	}
	if r.bus != nil {
		return r.bus.Close()
	}
	return nil
}

var EventBusModule = fx.Module("event-bus", fx.Provide(identitydomain.NewOutboxStore, newEventRuntime), fx.Invoke(func(*eventRuntime) {}))
