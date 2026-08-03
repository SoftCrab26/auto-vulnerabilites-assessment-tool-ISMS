package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// Fixed per-query timeout. Users do not need to set ORACLE_QUERY_TIMEOUT.
	defaultQueryTimeout = 180 * time.Second
)

type Config struct {
	SQLPlusPath  string
	QueryTimeout time.Duration
	OutputDir    string
	connectSpec  string
}

func loadConfigFromEnv() (Config, error) {
	cfg := Config{
		SQLPlusPath:  strings.TrimSpace(os.Getenv("ORACLE_SQLPLUS")),
		QueryTimeout: defaultQueryTimeout,
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
