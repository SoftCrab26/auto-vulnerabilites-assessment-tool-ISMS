package main

import (
	"os"
	"path/filepath"
	"strings"
)

type U05Input struct {
	PathEnv string
}

func checkU05() CheckResult {
	const code = "U-05"

	const description = "PATH should not contain insecure or relative entries."
	mitreAttack := MitreAttack{
		tactic:      "Stealth; Execution",
		techniques:  []string{"T1574.007"}, // Hijack Execution Flow: PATH interception by PATH Environment Variable
		mitigations: []string{"M1047"},     // Audit
	}
	input := loadU05Input()
	result := evalU05(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return result
}

func loadU05Input() U05Input {
	return U05Input{PathEnv: os.Getenv("PATH")}
}

func evalU05(input U05Input) CheckResult {
	pathEnv := input.PathEnv
	pathParts := strings.Split(pathEnv, ":")
	issues := []string{}

	for _, part := range pathParts {
		if part == "" {
			issues = append(issues, "empty path entry")
			continue
		}
		if part == "." || strings.HasPrefix(part, "./") || strings.Contains(part, "..") {
			issues = append(issues, "relative path: "+part)
		}
		if filepath.IsAbs(part) {
			info, err := os.Stat(part)
			if err == nil && info.IsDir() {
				perm := info.Mode().Perm()
				if perm&0002 != 0 {
					issues = append(issues, "world-writable PATH dir: "+part)
				}
			}
		}
	}

	configPaths := []string{"/etc/profile"}
	home, err := os.UserHomeDir()
	if err == nil {
		configPaths = append(configPaths, filepath.Join(home, ".bash_profile"), filepath.Join(home, ".profile"))
	}

	var configContents []string
	for _, path := range configPaths {
		if data, err := os.ReadFile(path); err == nil {
			configContents = append(configContents, "# "+path+"\n"+string(data))
		}
	}

	status := StatusGood
	if len(issues) > 0 {
		status = StatusVulnerable
	}

	vulnerableConfig := ""
	if status == StatusVulnerable {
		reasons := []string{}
		for _, issue := range issues {
			reasons = append(reasons, "문제점. "+issue)
		}
		vulnerableConfig = buildVulnerableConfig(
			"PATH="+pathEnv,
			"issues="+strings.Join(issues, ", "),
			strings.Join(reasons, "\n"),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        strings.Join(configContents, "\n"),
		ProcessedConfig:  buildProcessedConfig("PATH=" + pathEnv + "\n issues=" + strings.Join(issues, ", ")),
		VulnerableConfig: vulnerableConfig,
	}
}
