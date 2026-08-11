package main

import (
	"strings"
)

type U48Input struct {
	SendmailMC string
}

func checkU48(ctx ScanContext) CheckResult {
	const code = "U-48"
	const description = "expn, vrfy 명령어를 제한해야 합니다."
	mitreAttack := MitreAttack{
		Tactic:      "Discovery",
		Techniques:  []string{"T1082"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU48Input()

	result := evalU48(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU48Input() (U48Input, []string) {
	files, errs := collectFiles("/etc/mail/sendmail.mc")
	if len(files) == 0 {
		return U48Input{}, errs
	}
	return U48Input{SendmailMC: files[0].Content}, errs
}

func evalU48(input U48Input) CheckResult {
	content := input.SendmailMC
	hasNoExpnVrfy := strings.Contains(content, "noexpn") || strings.Contains(content, "novrfy")

	status := StatusGood
	vulnerableConfig := ""
	if !hasNoExpnVrfy && strings.TrimSpace(content) != "" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"expn_vrfy=NOT_RESTRICTED",
			"문제점1. expn, vrfy 명령어 제한이 설정되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("expn_vrfy_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
