package migration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityDomainMigration_BackwardCompatibleAndAudited(t *testing.T) {
	tests := []struct {
		name     string
		database string
		want     []string
		notWant  string
	}{
		{
			name:     "postgres",
			database: "postgres",
			want:     []string{"version BIGINT NOT NULL DEFAULT 1", "created_by TEXT NOT NULL", "updated_by TEXT NOT NULL", "PARTITION BY RANGE (created_at)"},
			notWant:  "ALTER COLUMN username SET NOT NULL",
		},
		{
			name:     "mysql",
			database: "mysql",
			want:     []string{"version BIGINT NOT NULL DEFAULT 1", "created_by VARCHAR(255) NOT NULL", "updated_by VARCHAR(255) NOT NULL", "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"},
			notWant:  "MODIFY username VARCHAR(64) NOT NULL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "migrations", tt.database, "000002_identity_domain.up.sql")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			sql := string(content)
			for _, want := range tt.want {
				if !strings.Contains(sql, want) {
					t.Errorf("migration missing %q", want)
				}
			}
			if strings.Contains(sql, tt.notWant) {
				t.Errorf("migration contains backward-incompatible %q", tt.notWant)
			}
		})
	}
}

func TestMySQLSessionClientMigrationBackfillsBeforeNotNull(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "migrations", "mysql", "000004_session_client.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(content)
	if strings.Contains(sql, "TEXT NOT NULL DEFAULT") {
		t.Fatal("mysql text columns cannot use defaults on every supported server mode")
	}
	for _, want := range []string{
		"ADD COLUMN client_ip TEXT NULL",
		"UPDATE sessions SET client_ip = '', user_agent = ''",
		"MODIFY COLUMN client_ip TEXT NOT NULL",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("migration missing %q", want)
		}
	}
}
