package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultQueryTimeout = 45 * time.Second // D-18 PUBLIC privilege inventory can be slow on large catalogs
	minQueryTimeout     = time.Second
	maxQueryTimeout     = 5 * time.Minute
)

type Config struct {
	SQLPlusPath  string
	QueryTimeout time.Duration
	OutputDir    string
	connectSpec  string
}

func loadConfigFromEnv() (Config, error) {
	timeout := defaultQueryTimeout
	if raw := strings.TrimSpace(os.Getenv("ORACLE_QUERY_TIMEOUT")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, errors.New("ORACLE_QUERY_TIMEOUT must be a valid duration")
		}
		timeout = parsed
	}

	cfg := Config{
		SQLPlusPath:  strings.TrimSpace(os.Getenv("ORACLE_SQLPLUS")),
		QueryTimeout: timeout,
		OutputDir:    strings.TrimSpace(os.Getenv("ORACLE_OUTPUT_DIR")),
		connectSpec:  os.Getenv("ORACLE_CONNECT"),
	}
	if cfg.SQLPlusPath == "" {
		cfg.SQLPlusPath = "sqlplus"
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "."
	}
	return cfg, cfg.validate()
}

func (cfg Config) validate() error {
	if strings.TrimSpace(cfg.connectSpec) == "" {
		return errors.New("ORACLE_CONNECT is required")
	}
	if strings.ContainsAny(cfg.connectSpec, "\r\n\x00") {
		return errors.New("ORACLE_CONNECT must be a single-line connection specification")
	}
	if cfg.QueryTimeout < minQueryTimeout || cfg.QueryTimeout > maxQueryTimeout {
		return fmt.Errorf("ORACLE_QUERY_TIMEOUT must be between %s and %s", minQueryTimeout, maxQueryTimeout)
	}
	if strings.TrimSpace(cfg.SQLPlusPath) == "" {
		return errors.New("ORACLE_SQLPLUS must not be empty")
	}

	info, err := os.Stat(filepath.Clean(cfg.OutputDir))
	if err != nil {
		return errors.New("ORACLE_OUTPUT_DIR is not accessible")
	}
	if !info.IsDir() {
		return errors.New("ORACLE_OUTPUT_DIR must identify a directory")
	}
	return nil
}
