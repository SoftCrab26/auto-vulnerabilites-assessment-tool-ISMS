package main

import (
	"bytes"
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

	generatedAt := time.Now().UTC()
	runner := newSQLPlusRunner(cfg)

	// Buffer early progress until the final output basename (DB unique name) is known.
	var bootBuf bytes.Buffer
	runner.setLog(&bootBuf)

	fmt.Fprintln(&bootBuf)
	fmt.Fprintln(&bootBuf, "================================")
	fmt.Fprintln(&bootBuf, "[*] Collecting database metadata...")
	fmt.Fprintln(&bootBuf, "================================")
	metadata, metadataErr := collectDBMetadata(context.Background(), runner)
	if metadataErr != nil {
		fmt.Fprintln(&bootBuf, "[ERROR] metadata:", redactOracleError(metadataErr.Error(), ""))
	} else {
		fmt.Fprintln(&bootBuf, "[OK] Metadata collection complete")
		fmt.Fprintf(&bootBuf, "  NAME: %s\n", metadata.Name)
		fmt.Fprintf(&bootBuf, "  UNIQUE_NAME: %s\n", metadata.UniqueName)
		fmt.Fprintf(&bootBuf, "  VERSION: %s\n", metadata.Version)
		fmt.Fprintf(&bootBuf, "  ROLE: %s\n", metadata.DatabaseRole)
		fmt.Fprintf(&bootBuf, "  OPEN_MODE: %s\n", metadata.OpenMode)
		if isOracle12cOrNewer(metadata.Version) {
			fmt.Fprintln(&bootBuf, "  SQL_MODE: 12c+")
		} else {
			fmt.Fprintln(&bootBuf, "  SQL_MODE: 11g")
		}
	}

	nameSource := metadata.UniqueName
	if nameSource == "" {
		nameSource, _ = os.Hostname()
	}
	if nameSource == "" {
		nameSource = "unknown"
	}
	baseName := fmt.Sprintf("oracle_%s_%s", sanitizeFileComponent(nameSource), generatedAt.Format("20060102T150405.000000000Z"))

	logPath := filepath.Join(cfg.OutputDir, baseName+".stdout.log")
	logFile, err := openOutputFile(logPath)
	if err != nil {
		return errors.New("could not create stdout log")
	}
	defer logFile.Close()
	out := io.MultiWriter(os.Stdout, logFile)
	if _, err := io.Copy(out, &bootBuf); err != nil {
		return err
	}
	runner.setLog(out)

	scanCtx := ScanContext{Runner: runner, Metadata: metadata, MetadataErr: metadataErr}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "================================")
	fmt.Fprintln(out, "[*] Running checks D-01 through D-26...")
	fmt.Fprintln(out, "================================")
	results := runChecks(scanCtx, out)

	fmt.Fprintln(out)
	fmt.Fprintln(out, "================================")
	fmt.Fprintln(out, "[FINAL RESULT]")
	fmt.Fprintln(out, "================================")
	printFinalResults(out, results)

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

func printFinalResults(out io.Writer, results []CheckResult) {
	for _, result := range results {
		fmt.Fprintln(out, "--------------------------------")
		fmt.Fprintln(out, "CODE:", result.Code)
		fmt.Fprintln(out, "STATUS:", result.Status)
		fmt.Fprintln(out, "DESCRIPTION:", result.Description)
		fmt.Fprintln(out, "PROCESSED:", result.ProcessedConfig)

		if result.VulnerableConfig != "" {
			fmt.Fprintln(out, "VULNERABLE CONFIG:")
			fmt.Fprintln(out, result.VulnerableConfig)
		}
		if result.RawConfig != "" {
			fmt.Fprintln(out, "RAW CONFIG:")
			fmt.Fprintln(out, result.RawConfig)
		}
		if result.ErrMsg != "" {
			fmt.Fprintln(out, "ERROR:", result.ErrMsg)
		}
	}
}

func runChecks(ctx ScanContext, out io.Writer) []CheckResult {
	checks := []struct {
		code string
		fn   func(ScanContext) CheckResult
	}{
		{"D-01", checkD01},
		{"D-02", checkD02},
		{"D-03", checkD03},
		{"D-04", checkD04},
		{"D-05", checkD05},
		{"D-06", checkD06},
		{"D-07", checkD07},
		{"D-08", checkD08},
		{"D-09", checkD09},
		{"D-10", checkD10},
		{"D-11", checkD11},
		{"D-12", checkD12},
		{"D-13", checkD13},
		{"D-14", checkD14},
		{"D-15", checkD15},
		{"D-16", checkD16},
		{"D-17", checkD17},
		{"D-18", checkD18},
		{"D-19", checkD19},
		{"D-20", checkD20},
		{"D-21", checkD21},
		{"D-22", checkD22},
		{"D-23", checkD23},
		{"D-24", checkD24},
		{"D-25", checkD25},
		{"D-26", checkD26},
	}

	results := make([]CheckResult, 0, len(checks))
	for _, check := range checks {
		fmt.Fprintln(out, "--------------------------------")
		fmt.Fprintln(out, "[CHECK]", check.code)
		result := check.fn(ctx)
		results = append(results, result)
		fmt.Fprintln(out, "[DONE]", check.code)
	}
	return results
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
