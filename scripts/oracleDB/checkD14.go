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
	return input
}

func evalD14(input D14Input) CheckResult {
	home := sanitizeEvidence(input.OracleHome)
	if home == "" {
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       "ORACLE_HOME=unset; checked_paths=not_resolved",
			ProcessedConfig: "review=set or identify ORACLE_HOME and inspect sqlnet.ora, listener.ora, tnsnames.ora, and the password-file directory permissions",
		}
	}
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
	raw := "ORACLE_HOME=" + home + "; " + strings.Join(evidence, ", ")
	if len(writable) > 0 {
		return CheckResult{
			Status:           StatusVulnerable,
			RawConfig:        raw,
			VulnerableConfig: strings.Join(writable, ", "),
			ProcessedConfig:  "group_or_other_writable_paths=true",
		}
	}
	if found == 0 {
		return CheckResult{
			Status:          StatusManual,
			RawConfig:       raw,
			ProcessedConfig: "review=ORACLE_HOME was available but no fixed configuration or password-directory path could be inspected",
		}
	}
	return CheckResult{
		Status:          StatusGood,
		RawConfig:       raw,
		ProcessedConfig: "inspected_paths_group_or_other_writable=false",
	}
}
