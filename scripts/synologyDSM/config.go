package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultCommandTimeout = 5 * time.Second
	minCommandTimeout     = time.Second
	maxCommandTimeout     = time.Minute
)

type Config struct {
	OutputDir      string
	CommandTimeout time.Duration
}

func loadConfig() (Config, error) {
	outputDir := os.Getenv("DSM_OUTPUT_DIR")
	if outputDir == "" {
		outputDir = "."
	}

	timeout := defaultCommandTimeout
	if value := os.Getenv("DSM_COMMAND_TIMEOUT"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("parse DSM_COMMAND_TIMEOUT: %w", err)
		}
		timeout = parsed
	}
	if timeout < minCommandTimeout || timeout > maxCommandTimeout {
		return Config{}, fmt.Errorf("DSM_COMMAND_TIMEOUT must be between %s and %s", minCommandTimeout, maxCommandTimeout)
	}

	info, err := os.Stat(outputDir)
	if err != nil {
		return Config{}, fmt.Errorf("validate DSM_OUTPUT_DIR: %w", err)
	}
	if !info.IsDir() {
		return Config{}, fmt.Errorf("DSM_OUTPUT_DIR is not a directory: %s", outputDir)
	}
	absoluteDir, err := filepath.Abs(outputDir)
	if err != nil {
		return Config{}, fmt.Errorf("resolve DSM_OUTPUT_DIR: %w", err)
	}

	return Config{OutputDir: absoluteDir, CommandTimeout: timeout}, nil
}
