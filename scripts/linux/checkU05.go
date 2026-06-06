package main

import (
	"os"
	"path/filepath"
	"strings"
)

func checkU05() CheckResult {
	pathEnv := os.Getenv("PATH")
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

	return CheckResult{
		Code:            "U-05",
		Status:          status,
		Description:     "PATH should not contain insecure or relative entries.",
		RawConfig:       strings.Join(configContents, "\n"),
		ProcessedConfig: "PATH=" + pathEnv + " issues=" + strings.Join(issues, ", "),
	}
}
