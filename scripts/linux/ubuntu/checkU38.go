package main

import (
	"strings"
)

type U38Input struct {
	Dos     Service
	Runtime RuntimeData
}

func checkU38(ctx ScanContext) CheckResult {
	const code = "U-38"
	const description = "DoS-vulnerable services (echo, discard, daytime, chargen) should be disabled."
	mitreAttack := MitreAttack{
		Tactic:      "Impact",
		Techniques:  []string{"T1499"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU38Input(ctx)

	result := evalU38(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU38Input(ctx ScanContext) (U38Input, []string) {
	return U38Input{
		Dos:     ctx.Services["dos"],
		Runtime: ctx.Runtime,
	}, nil
}

func evalU38(input U38Input) CheckResult {
	dos := input.Dos
	portActive := input.Runtime.HasAnyPort("7", "9", "13", "19")

	status := StatusGood
	vulnerableConfig := ""
	if dos.IsActive() || portActive {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(dos),
			"문제점1. DoS 공격에 취약한 서비스가 활성화되어 있습니다.",
		)
	}

	rawConfig := formatServiceStatus(dos)
	if portActive {
		rawConfig += "\nports=" + strings.Join(dos.ListeningPorts, ",")
	}

	return CheckResult{
		Status:           status,
		RawConfig:        rawConfig,
		ProcessedConfig:  buildProcessedConfig("dos_service_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
