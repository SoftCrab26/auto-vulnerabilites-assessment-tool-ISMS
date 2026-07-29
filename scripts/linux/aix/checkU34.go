package main

import "strings"

type U34Input struct {
	Finger            Service
	EvidenceAvailable bool
}

func checkU34(ctx ScanContext) CheckResult {
	const code = "U-34"
	const description = "Finger service should be disabled."
	mitre := MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	input, errs := loadU34Input(ctx)
	result := evalU34(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU34Input(ctx ScanContext) (U34Input, []string) {
	return U34Input{Finger: ctx.Services["finger"], EvidenceAvailable: serviceEvidenceAvailable(ctx)}, nil
}

func evalU34(input U34Input) CheckResult {
	raw := formatServiceStatus(input.Finger)
	if input.Finger.IsActive() {
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: "finger=active", VulnerableConfig: raw}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "finger=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "finger=disabled"}
}

func serviceEvidenceAvailable(ctx ScanContext) bool {
	runtime := ctx.Runtime
	return strings.TrimSpace(runtime.ProcessList) != "" ||
		strings.TrimSpace(runtime.SRCList) != "" ||
		strings.TrimSpace(runtime.InetdConfig) != "" ||
		strings.TrimSpace(runtime.PortList) != ""
}
