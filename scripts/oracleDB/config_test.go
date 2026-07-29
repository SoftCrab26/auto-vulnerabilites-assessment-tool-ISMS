package main

import (
	"strings"
	"testing"
)

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("ORACLE_CONNECT", "/@wallet_alias")
	t.Setenv("ORACLE_SQLPLUS", "")
	t.Setenv("ORACLE_QUERY_TIMEOUT", "")
	t.Setenv("ORACLE_OUTPUT_DIR", t.TempDir())

	cfg, err := loadConfigFromEnv()
	if err != nil {
		t.Fatalf("loadConfigFromEnv returned error: %v", err)
	}
	if cfg.SQLPlusPath != "sqlplus" {
		t.Fatalf("SQLPlusPath = %q, want sqlplus", cfg.SQLPlusPath)
	}
	if cfg.QueryTimeout != defaultQueryTimeout {
		t.Fatalf("QueryTimeout = %v, want %v", cfg.QueryTimeout, defaultQueryTimeout)
	}
}

func TestConfigValidationDoesNotExposeSecret(t *testing.T) {
	secret := "audit_user/top-secret@prod\nselect 1 from dual"
	cfg := Config{
		SQLPlusPath:  "sqlplus",
		QueryTimeout: defaultQueryTimeout,
		OutputDir:    t.TempDir(),
		connectSpec:  secret,
	}

	err := cfg.validate()
	if err == nil {
		t.Fatal("expected multiline connection specification to fail")
	}
	if strings.Contains(err.Error(), "top-secret") || strings.Contains(err.Error(), secret) {
		t.Fatalf("validation error exposed connection secret: %q", err)
	}
}

func TestConfigRequiresConnection(t *testing.T) {
	t.Setenv("ORACLE_CONNECT", "")
	t.Setenv("ORACLE_OUTPUT_DIR", t.TempDir())
	_, err := loadConfigFromEnv()
	if err == nil || err.Error() != "ORACLE_CONNECT is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}
