package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestConfig_AuthorizationRequiresConfiguredUpstream(t *testing.T) {
	cfg, err := Load("../../config/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Authorization.Enabled = true
	delete(cfg.Outbound.GRPC, "authorization")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "outbound.grpc.authorization") {
		t.Fatalf("Validate() error = %v, want authorization upstream requirement", err)
	}
}

func TestConfig_ProductionRequiresAuthorization(t *testing.T) {
	cfg, err := Load("../../config/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.App.Env = "production"
	cfg.GRPC.Enabled = false
	cfg.GRPC.ReflectionEnabled = false
	cfg.Swagger.RequireAuth = true
	cfg.Authorization.Enabled = false
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "authorization must be enabled") {
		t.Fatalf("Validate() error = %v, want production authorization requirement", err)
	}
}

func TestLoad_DefaultAudiencesIncludeRuleService(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(path, []byte("app:\n  env: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !slices.Contains(cfg.JWT.Audiences, "rule-service") {
		t.Fatalf("JWT audiences = %v, want rule-service", cfg.JWT.Audiences)
	}
	if !slices.Contains(cfg.JWT.Audiences, "data-export-service") {
		t.Fatalf("JWT audiences = %v, want data-export-service", cfg.JWT.Audiences)
	}
	if !slices.Contains(cfg.JWT.Audiences, "import-service") {
		t.Fatalf("JWT audiences = %v, want import-service", cfg.JWT.Audiences)
	}
}

func TestLoad_EnvironmentOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("http:\n  address: 127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_HTTP_ADDRESS", "127.0.0.1:9090")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTP.Address != "127.0.0.1:9090" {
		t.Fatalf("HTTP.Address = %q, want %q", cfg.HTTP.Address, "127.0.0.1:9090")
	}
	if cfg.Cron.SessionRetention != 30*24*time.Hour || cfg.Cron.SessionCleanupInterval != time.Hour || cfg.Cron.SessionCleanupBatchSize != 500 {
		t.Fatalf("unexpected session retention defaults: %+v", cfg.Cron)
	}
	if cfg.EventBus.PublishedRetention != 7*24*time.Hour || cfg.EventBus.CleanupInterval != time.Hour || cfg.EventBus.CleanupBatchSize != 1000 {
		t.Fatalf("unexpected outbox cleanup defaults: %+v", cfg.EventBus)
	}
}

func TestConfigRejectsInvalidOutboxCleanup(t *testing.T) {
	cfg, err := LoadWithProfile("../../config/config.yaml", "development")
	if err != nil {
		t.Fatal(err)
	}
	cfg.EventBus.Enabled = true
	for _, mutate := range []func(*EventBus){
		func(eventBus *EventBus) { eventBus.PublishedRetention = eventBus.MaxAge - time.Second },
		func(eventBus *EventBus) { eventBus.CleanupBatchSize = 0 },
	} {
		candidate := cfg
		mutate(&candidate.EventBus)
		if err := candidate.Validate(); err == nil {
			t.Fatal("Validate() error = nil, want outbox cleanup validation error")
		}
	}
}

func TestLoad_SessionRetentionEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("http:\n  address: 127.0.0.1:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_CRON_SESSION_RETENTION", "2160h")
	t.Setenv("APP_CRON_SESSION_CLEANUP_BATCH_SIZE", "250")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Cron.SessionRetention != 90*24*time.Hour || cfg.Cron.SessionCleanupBatchSize != 250 {
		t.Fatalf("unexpected session retention overrides: %+v", cfg.Cron)
	}
}

func TestConfig_ValidateJWTSecret(t *testing.T) {
	t.Parallel()
	cfg := Config{HTTP: HTTP{Address: "127.0.0.1:8080"}, Auth: Auth{ClientID: "client", ClientSecret: "secret"}, JWT: JWT{Secret: "short"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
}

func TestLoadWithProfile_MergesProfileThenEnvironment(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "config.yaml")
	profile := filepath.Join(dir, "config-test.yaml")
	if err := os.WriteFile(base, []byte("app:\n  env: development\nlog:\n  level: info\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, []byte("log:\n  level: debug\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APP_LOG_LEVEL", "error")
	cfg, err := LoadWithProfile(base, "test")
	if err != nil {
		t.Fatalf("LoadWithProfile() error = %v", err)
	}
	if cfg.App.Env != "test" || cfg.Runtime.ActiveProfile != "test" {
		t.Fatalf("active profile = %q/%q", cfg.App.Env, cfg.Runtime.ActiveProfile)
	}
	if cfg.Log.Level != "error" {
		t.Fatalf("Log.Level = %q, want environment override", cfg.Log.Level)
	}
	if len(cfg.Runtime.ConfigFiles) != 2 || cfg.Runtime.ConfigFiles[1] != profile {
		t.Fatalf("ConfigFiles = %v", cfg.Runtime.ConfigFiles)
	}
}

func TestConfig_ValidateAuthSkipPattern(t *testing.T) {
	t.Parallel()
	cfg := Config{HTTP: HTTP{Address: "127.0.0.1:8080", RequestTimeout: time.Second}, Health: Health{DatabaseTimeout: time.Second, RedisTimeout: time.Second}, User: User{CacheTTL: time.Second, LockTTL: time.Second, LockRetryDelay: time.Millisecond}, Auth: Auth{SkipHTTPPaths: []string{"/api/v1/[broken"}}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want invalid wildcard error")
	}
}

func TestConfig_ValidateAutoMigration(t *testing.T) {
	t.Parallel()
	cfg := Config{
		HTTP:      HTTP{Address: "127.0.0.1:8080", RequestTimeout: time.Second},
		Health:    Health{DatabaseTimeout: time.Second, RedisTimeout: time.Second},
		User:      User{CacheTTL: time.Second, LockTTL: time.Second, LockRetryDelay: time.Millisecond},
		Migration: Migration{AutoUp: true, Path: "migrations/postgres"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want auto migration dependency error")
	}
}
