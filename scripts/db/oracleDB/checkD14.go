package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const d14Description = "Oracle network configuration and password-file directories must not be group- or world-writable."

var d14Mitre = MitreAttack{
	Tactic:      "Defense Evasion",
	Techniques:  []string{"T1222"},
	Mitigations: []string{"M1022"},
}

type D14PathEvidence struct {
	Path   string
	Status string
	Mode   os.FileMode
}

type D14Input struct {
	OracleHome string
	Paths      []D14PathEvidence
	RawRows    [][]string
}

func checkD14(ctx ScanContext) CheckResult {
	result := evalD14(loadD14Input())
	result.Code = "D-14"
	result.Description = d14Description
	result.MitreAttack = d14Mitre
	return result
}

func loadD14Input() D14Input {
	home := strings.TrimSpace(os.Getenv("ORACLE_HOME"))
	input := D14Input{OracleHome: home}
	if home == "" {
		return input
	}
	paths := []string{
		filepath.Join(home, "network", "admin", "sqlnet.ora"),
		filepath.Join(home, "network", "admin", "listener.ora"),
		filepath.Join(home, "network", "admin", "tnsnames.ora"),
		filepath.Join(home, "dbs"),
	}
	for _, path := range paths {
		evidence := D14PathEvidence{Path: path}
		info, err := os.Stat(path)
		switch {
		case os.IsNotExist(err):
			evidence.Status = "absent"
		case err != nil:
			evidence.Status = "unavailable"
		default:
			evidence.Status = "present"
			evidence.Mode = info.Mode().Perm()
		}
		input.Paths = append(input.Paths, evidence)
	}
	input.RawRows = d14RawRows(input.Paths)
	return input
}

func d14RawRows(paths []D14PathEvidence) [][]string {
	rows := make([][]string, 0, len(paths))
	for _, path := range paths {
		rows = append(rows, []string{path.Path, path.Status, pathModeCell(path.Status, path.Mode)})
	}
	return rows
}

func pathModeCell(status string, mode os.FileMode) string {
	if status == "present" {
		return fmt.Sprintf("%04o", mode.Perm())
	}
	return "-"
}

func evalD14(input D14Input) CheckResult {
	rawRows := input.RawRows
	if rawRows == nil {
		rawRows = d14RawRows(input.Paths)
	}
	headers := []string{"PATH", "STATUS", "MODE"}
	if sanitizeEvidence(input.OracleHome) == "" {
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       formatSQLTable(headers, nil),
			ProcessedConfig: formatProcessedRaw(nil),
		}
	}
	var writable []string
	found := 0
	for _, path := range input.Paths {
		if path.Status == "present" {
			found++
			mode := path.Mode.Perm()
			if mode&0o022 != 0 {
				writable = append(writable, fmt.Sprintf("%s mode=%04o", sanitizeEvidence(path.Path), mode))
			}
		}
	}
	sort.Strings(writable)
	rawConfig := formatSQLTable(headers, rawRows)
	processed := formatProcessedRaw(rawRows)
	if len(writable) > 0 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        rawConfig,
			VulnerableConfig: strings.Join(writable, ", "),
			ProcessedConfig:  processed,
		}
	}
	if found == 0 {
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       rawConfig,
			ProcessedConfig: processed,
		}
	}
	return CheckResult{
		Status:          StatusGood,
		RawConfig:       rawConfig,
		ProcessedConfig: processed,
	}
}
