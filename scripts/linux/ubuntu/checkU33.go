package main

import (
	"strings"
)

type U33Input struct{}

func checkU33(ctx ScanContext) CheckResult {
	const code = "U-33"
	const description = "Unnecessary or suspicious hidden files and directories should be removed."
	mitreAttack := MitreAttack{
		Tactic:      "Defense Evasion",
		Techniques:  []string{"T1036"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU33Input()

	result := evalU33(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU33Input() (U33Input, []string) {
	return U33Input{}, nil
}

func evalU33(input U33Input) CheckResult {
	// Search for suspicious hidden files (limited)
	findOutput := run("find /root /home -name '.*' -type f 2>/dev/null | grep -E '(\\.ssh|\\.bash_history|\\.viminfo|\\.netrc|\\.forward)' | head -10")

	status := StatusGood
	vulnerableConfig := ""

	if strings.TrimSpace(findOutput) != "" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"suspicious_hidden_files:\n"+findOutput,
			"문제점1. 의심스러운 숨겨진 파일이 존재합니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        findOutput,
		ProcessedConfig:  buildProcessedConfig("hidden_file_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
