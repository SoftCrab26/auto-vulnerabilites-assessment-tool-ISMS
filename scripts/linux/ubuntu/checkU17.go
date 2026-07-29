package main

import (
	"os"
	"strings"
)

type U17Input struct {
	ScriptPaths []string
}

func checkU17(ctx ScanContext) CheckResult {
	const code = "U-17"
	const description = "System startup scripts should be owned by root and not writable by general users."
	mitreAttack := MitreAttack{
		tactic:      "Persistence",
		techniques:  []string{"T1037"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU17Input()

	result := evalU17(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU17Input() (U17Input, []string) {
	paths := []string{
		"/etc/rc.local",
		"/etc/rc.d/rc.local",
		"/etc/init.d",
	}
	return U17Input{ScriptPaths: paths}, nil
}

func evalU17(input U17Input) CheckResult {
	var problems []string
	var checked []string

	for _, base := range input.ScriptPaths {
		info, err := os.Stat(base)
		if err != nil {
			continue
		}
		checked = append(checked, base)

		if info.IsDir() {
			// For init.d directory, check a few common scripts
			entries, _ := os.ReadDir(base)
			for i, entry := range entries {
				if i > 5 {
					break // limit
				}
				if !entry.IsDir() {
					full := base + "/" + entry.Name()
					pinfo, perr := os.Stat(full)
					if perr == nil {
						perm := pinfo.Mode().Perm()
						if perm&0022 != 0 {
							problems = append(problems, full+" (perm too open)")
						}
					}
				}
			}
		} else {
			perm := info.Mode().Perm()
			if perm&0022 != 0 {
				problems = append(problems, base+" (perm too open)")
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(problems) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"startup_script_issues="+strings.Join(problems, ";"),
			"문제점1. 시스템 시작 스크립트의 권한이 root 소유 + 일반사용자 쓰기 금지가 아닙니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        strings.Join(checked, "\n"),
		ProcessedConfig:  buildProcessedConfig("startup_script_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
