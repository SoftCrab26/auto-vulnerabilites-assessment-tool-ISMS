package main

import (
	"strings"
)

type U44Input struct {
	Found   []string
	Runtime RuntimeData
}

func checkU44(ctx ScanContext) CheckResult {
	const code = "U-44"
	const description = "tftp, talk, ntalk services should be disabled."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU44Input(ctx)

	result := evalU44(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU44Input(ctx ScanContext) (U44Input, []string) {
	return U44Input{
		Found:   activeServiceLabels(ctx.Services, "tftp", "talk"),
		Runtime: ctx.Runtime,
	}, nil
}

func evalU44(input U44Input) CheckResult {
	portActive := input.Runtime.HasAnyPort("69", "517", "518")

	status := StatusGood
	vulnerableConfig := ""
	if len(input.Found) > 0 || portActive {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"tftp_talk_found="+strings.Join(input.Found, ","),
			"문제점1. tftp, talk, ntalk 서비스가 활성화되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        strings.Join(input.Found, "\n"),
		ProcessedConfig:  buildProcessedConfig("tftp_talk_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
