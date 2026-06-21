package main

type U64Input struct{}

func checkU64(ctx ScanContext) CheckResult {
	const code = "U-64"
	const description = "Periodic security patches and vendor recommendations should be applied."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1190"},
		mitigations: []string{"M1051"},
	}

	input, errs := loadU64Input()

	result := evalU64(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU64Input() (U64Input, []string) {
	return U64Input{}, nil
}

func evalU64(input U64Input) CheckResult {
	osInfo := run("uname -a")
	osRelease := run("cat /etc/os-release 2>/dev/null")

	return CheckResult{
		Status:           StatusInterview,
		RawConfig:        osInfo + "\n" + osRelease,
		ProcessedConfig:  buildProcessedConfig("patch_check=interview"),
		VulnerableConfig: "문제점1. 주기적 보안 패치 및 벤더 권고사항 적용 여부를 수동으로 확인해야 합니다.",
	}
}
