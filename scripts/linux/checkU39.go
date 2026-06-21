package main

type U39Input struct {
	NFS Service
}

func checkU39(ctx ScanContext) CheckResult {
	const code = "U-39"
	const description = "Unnecessary NFS services should be disabled."
	mitreAttack := MitreAttack{
		tactic:      "Initial Access",
		techniques:  []string{"T1021"},
		mitigations: []string{"M1022"},
	}

	input, errs := loadU39Input(ctx)

	result := evalU39(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU39Input(ctx ScanContext) (U39Input, []string) {
	return U39Input{NFS: ctx.Services["nfs"]}, nil
}

func evalU39(input U39Input) CheckResult {
	nfs := input.NFS
	status := StatusGood
	vulnerableConfig := ""

	if nfs.IsActive() {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			formatServiceStatus(nfs),
			"문제점1. 불필요한 NFS 관련 데몬이 활성화되어 있습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        formatServiceStatus(nfs),
		ProcessedConfig:  buildProcessedConfig("nfs_check=done"),
		VulnerableConfig: vulnerableConfig,
	}
}
