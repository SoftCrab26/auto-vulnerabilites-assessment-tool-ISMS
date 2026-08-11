package main

type U58Input struct {
	SNMP Service
}

func checkU58(ctx ScanContext) CheckResult {
	const code = "U-58"
	const description = "SNMP service should not be running if not necessary."
	mitreAttack := MitreAttack{
		Tactic:      "Discovery",
		Techniques:  []string{"T1082"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU58Input(ctx)

	result := evalU58(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU58Input(ctx ScanContext) (U58Input, []string) {
	return U58Input{SNMP: ctx.Services["snmp"]}, nil
}

func evalU58(input U58Input) CheckResult {
	snmp := input.SNMP
	status := StatusGood
	vulnerableConfig := ""

	if snmp.IsActive() {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(snmp),
			"문제점1. SNMP 서비스가 사용 중입니다. 불필요한 경우 비활성화하세요.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        formatServiceStatus(snmp),
		ProcessedConfig:  buildProcessedConfig("snmp_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
