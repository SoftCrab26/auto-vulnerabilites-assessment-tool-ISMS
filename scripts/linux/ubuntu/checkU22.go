package main

import (
	"os"
	"strconv"
	"strings"
)

type U22Input struct {
	ServicesPath string
}

func checkU22(ctx ScanContext) CheckResult {
	const code = "U-22"
	const description = "/etc/services should be owned by root/bin/sys with permission 644 or less."
	mitreAttack := MitreAttack{
		Tactic:      "Discovery",
		Techniques:  []string{"T1082"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU22Input()

	result := evalU22(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU22Input() (U22Input, []string) {
	return U22Input{ServicesPath: "/etc/services"}, nil
}

func evalU22(input U22Input) CheckResult {
	path := input.ServicesPath
	info, err := os.Stat(path)
	if err != nil {
		return CheckResult{
			Status: StatusError,
			ErrMsg: err.Error(),
		}
	}

	perm := info.Mode().Perm()
	permOct := strconv.FormatUint(uint64(perm), 8)

	status := StatusGood
	vulnerableConfig := ""

	if perm&0022 != 0 {
		status = StatusVulnerable
	}

	ownerOut := strings.ToLower(strings.TrimSpace(run("stat -c %U " + path + " 2>/dev/null || echo unknown")))
	allowedOwners := []string{"root", "bin", "sys"}
	isAllowedOwner := false
	for _, o := range allowedOwners {
		if strings.Contains(ownerOut, o) {
			isAllowedOwner = true
			break
		}
	}

	if !isAllowedOwner {
		status = StatusVulnerable
	}

	if status == StatusVulnerable {
		reason := "문제점1. /etc/services 파일의 소유자(root/bin/sys) 또는 권한(644 이하)이 올바르지 않습니다."
		vulnerableConfig = buildVulnerableConfig(
			path+" perm="+permOct+" owner="+ownerOut,
			reason,
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        "",
		ProcessedConfig:  buildProcessedConfig(path + " perm=" + permOct + " owner=" + ownerOut),
		VulnerableConfig: vulnerableConfig,
	}
}
