package main

import (
	"os"
	"strconv"
	"strings"
)

type U31Input struct {
	Passwd string
}

func checkU31(ctx ScanContext) CheckResult {
	const code = "U-31"
	const description = "Home directories should be owned by the corresponding user and not writable by others."
	mitreAttack := MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1552"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU31Input()

	result := evalU31(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU31Input() (U31Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U31Input{}, errs
	}
	return U31Input{Passwd: files[0].Content}, errs
}

func evalU31(input U31Input) CheckResult {
	content := input.Passwd
	var problems []string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 6 {
			username := fields[0]
			home := fields[5]
			if home == "" || home == "/" || strings.HasPrefix(home, "/root") {
				continue
			}
			info, err := os.Stat(home)
			if err != nil {
				continue
			}
			perm := info.Mode().Perm()
			if perm&0022 != 0 {
				problems = append(problems, home+" (other write)")
			}
			ownerOut := strings.ToLower(run("stat -c %U " + home + " 2>/dev/null || echo unknown"))
			if !strings.Contains(ownerOut, strings.ToLower(username)) && !strings.Contains(ownerOut, "root") {
				problems = append(problems, home+" owner mismatch")
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(problems) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			strings.Join(problems, "\n"),
			"문제점1. 홈 디렉토리 소유자 또는 타 사용자 쓰기 권한이 올바르지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig("home_dir_check=done", "issues="+strconv.Itoa(len(problems))),
		VulnerableConfig: vulnerableConfig,
	}
}
