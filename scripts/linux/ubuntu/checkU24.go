package main

import (
	"os"
	"strconv"
	"strings"
)

type U24Input struct {
	HomeFiles []string
}

func checkU24(ctx ScanContext) CheckResult {
	const code = "U-24"
	const description = "User/system environment variable files (.bash_profile, .bashrc, .profile) should be owned by root or the user with no other write permission."
	mitreAttack := MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1552"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU24Input()

	result := evalU24(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU24Input() (U24Input, []string) {
	// Common environment files for root and typical users
	paths := []string{
		"/root/.bash_profile",
		"/root/.bashrc",
		"/root/.profile",
		"/etc/profile",
		"/etc/bashrc",
	}
	return U24Input{HomeFiles: paths}, nil
}

func evalU24(input U24Input) CheckResult {
	var problems []string

	for _, path := range input.HomeFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&0022 != 0 {
			problems = append(problems, path+" perm="+strconv.FormatUint(uint64(perm), 8))
		}
		ownerOut := strings.ToLower(run("stat -c %U " + path + " 2>/dev/null || echo unknown"))
		if !strings.Contains(ownerOut, "root") && !strings.Contains(ownerOut, "bin") {
			problems = append(problems, path+" owner="+strings.TrimSpace(ownerOut))
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(problems) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			strings.Join(problems, "\n"),
			"문제점1. 환경변수 파일의 소유자 또는 권한이 올바르지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig("env_file_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
