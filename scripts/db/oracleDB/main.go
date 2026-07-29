package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "oracle scanner error:", redactOracleError(err.Error(), ""))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		return err
	}

	runner := newSQLPlusRunner(cfg)
	metadata, metadataErr := collectDBMetadata(context.Background(), runner)
	scanCtx := ScanContext{Runner: runner, Metadata: metadata, MetadataErr: metadataErr}

	generatedAt := time.Now().UTC()
	nameSource := metadata.UniqueName
	if nameSource == "" {
		nameSource, _ = os.Hostname()
	}
	baseName := fmt.Sprintf("oracle_%s_%s", sanitizeFileComponent(nameSource), generatedAt.Format("20060102T150405.000000000Z"))

	logPath := filepath.Join(cfg.OutputDir, baseName+".stdout.log")
	logFile, err := openOutputFile(logPath)
	if err != nil {
		return errors.New("could not create stdout log")
	}
	defer logFile.Close()
	out := io.MultiWriter(os.Stdout, logFile)

	fmt.Fprintln(out, "Oracle vulnerability scanner: running checks D-01 through D-26.")
	if metadataErr != nil {
		fmt.Fprintln(out, "Metadata collection: Error -", redactOracleError(metadataErr.Error(), ""))
	} else {
		fmt.Fprintf(out, "Database: %s (%s), version %s, role %s, open mode %s\n",
			metadata.Name, metadata.UniqueName, metadata.Version, metadata.DatabaseRole, metadata.OpenMode)
	}

	results := runChecks(scanCtx)
	for _, result := range results {
		fmt.Fprintf(out, "%s: %s - %s\n", result.Code, result.Status, result.ProcessedConfig)
		if result.ErrMsg != "" {
			fmt.Fprintln(out, "  Error:", result.ErrMsg)
		}
	}

	report := ScanReport{
		Engine:      "ORACLE",
		Metadata:    metadata,
		GeneratedAt: generatedAt,
		Results:     results,
	}
	jsonPath := filepath.Join(cfg.OutputDir, baseName+".json")
	if err := writeReport(jsonPath, report); err != nil {
		return errors.New("could not write JSON report")
	}

	fmt.Fprintln(out, "JSON saved to:", jsonPath)
	fmt.Fprintln(out, "STDOUT saved to:", logPath)
	return nil
}

func runChecks(ctx ScanContext) []CheckResult {
	return []CheckResult{
		checkD01(ctx),
		checkD02(ctx),
		checkD03(ctx),
		checkD04(ctx),
		checkD05(ctx),
		checkD06(ctx),
		checkD07(ctx),
		checkD08(ctx),
		checkD09(ctx),
		checkD10(ctx),
		checkD11(ctx),
		checkD12(ctx),
		checkD13(ctx),
		checkD14(ctx),
		checkD15(ctx),
		checkD16(ctx),
		checkD17(ctx),
		checkD18(ctx),
		checkD19(ctx),
		checkD20(ctx),
		checkD21(ctx),
		checkD22(ctx),
		checkD23(ctx),
		checkD24(ctx),
		checkD25(ctx),
		checkD26(ctx),
	}
}

func openOutputFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return file, nil
}

func writeReport(path string, report ScanReport) error {
	file, err := openOutputFile(path)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	success = true
	return nil
}
