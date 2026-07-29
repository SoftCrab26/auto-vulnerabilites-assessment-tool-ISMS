package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	d15Description = "Oracle listener log and trace locations must not be group- or world-writable."
	d15MaxEntries  = 128
	d15MaxDepth    = 4
)

var d15Mitre = MitreAttack{
	Tactic:      "Defense Evasion",
	Techniques:  []string{"T1070"},
	Mitigations: []string{"M1022"},
}

type D15PathEvidence struct {
	Path   string
	Status string
	Mode   os.FileMode
}

type D15Input struct {
	OracleBase string
	OracleHome string
	Paths      []D15PathEvidence
	Truncated  bool
}

func checkD15(ctx ScanContext) CheckResult {
	result := evalD15(loadD15Input())
	result.Code = "D-15"
	result.Description = d15Description
	result.MitreAttack = d15Mitre
	return result
}

func loadD15Input() D15Input {
	input := D15Input{
		OracleBase: strings.TrimSpace(os.Getenv("ORACLE_BASE")),
		OracleHome: strings.TrimSpace(os.Getenv("ORACLE_HOME")),
	}
	fixed := make([]string, 0, 5)
	if input.OracleHome != "" {
		fixed = append(fixed,
			filepath.Join(input.OracleHome, "network", "log"),
			filepath.Join(input.OracleHome, "network", "log", "listener.log"),
			filepath.Join(input.OracleHome, "network", "trace"),
			filepath.Join(input.OracleHome, "network", "trace", "listener.trc"),
		)
	}
	for _, path := range fixed {
		input.Paths = append(input.Paths, statD15Path(path))
	}
	if input.OracleBase != "" {
		root := filepath.Join(input.OracleBase, "diag", "tnslsnr")
		rootEvidence := statD15Path(root)
		input.Paths = append(input.Paths, rootEvidence)
		if rootEvidence.Status == "present" {
			visited := 0
			scanD15Directory(root, 0, &visited, &input)
		}
	}
	return input
}

func statD15Path(path string) D15PathEvidence {
	evidence := D15PathEvidence{Path: path}
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
	return evidence
}

func scanD15Directory(path string, depth int, visited *int, input *D15Input) {
	if depth >= d15MaxDepth || *visited >= d15MaxEntries {
		input.Truncated = true
		return
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		input.Paths = append(input.Paths, D15PathEvidence{Path: path, Status: "directory_unavailable"})
		return
	}
	for _, entry := range entries {
		if *visited >= d15MaxEntries {
			input.Truncated = true
			return
		}
		*visited++
		child := filepath.Join(path, entry.Name())
		input.Paths = append(input.Paths, statD15Path(child))
		if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			scanD15Directory(child, depth+1, visited, input)
		}
	}
}

func evalD15(input D15Input) CheckResult {
	var evidence, writable []string
	found := 0
	for _, path := range input.Paths {
		item := sanitizeEvidence(path.Path) + "=" + sanitizeEvidence(path.Status)
		if path.Status == "present" {
			found++
			mode := path.Mode.Perm()
			item += fmt.Sprintf("(mode=%04o)", mode)
			if mode&0o022 != 0 {
				writable = append(writable, fmt.Sprintf("%s mode=%04o", sanitizeEvidence(path.Path), mode))
			}
		}
		evidence = append(evidence, item)
	}
	sort.Strings(evidence)
	sort.Strings(writable)
	env := fmt.Sprintf("ORACLE_BASE=%s; ORACLE_HOME=%s",
		envStatus(input.OracleBase), envStatus(input.OracleHome))
	raw := env
	if len(evidence) > 0 {
		raw += "; " + strings.Join(evidence, ", ")
	}
	if input.Truncated {
		raw += "; bounded_scan=truncated"
	}
	if len(writable) > 0 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        raw,
			VulnerableConfig: strings.Join(writable, ", "),
			ProcessedConfig:  "listener_log_or_trace_path_group_or_other_writable=true",
		}
	}
	if found == 0 {
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       raw,
			ProcessedConfig: "review=listener log and trace locations were unavailable; identify active listener diagnostics paths and verify ownership and permissions",
		}
	}
	return CheckResult{
		Status:          StatusGood,
		RawConfig:       raw,
		ProcessedConfig: "inspected_listener_log_and_trace_paths_group_or_other_writable=false",
	}
}

func envStatus(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unset"
	}
	return sanitizeEvidence(value)
}
