package main

import "strings"

type U44Input struct {
	TFTP              Service
	Talk              Service
	InetdConfig       string
	EvidenceAvailable bool
}

func checkU44(ctx ScanContext) CheckResult {
	const code = "U-44"
	const description = "tftp, talk, and ntalk services should be disabled."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU44Input(ctx)
	result := evalU44(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU44Input(ctx ScanContext) (U44Input, []string) {
	return U44Input{
		TFTP:              ctx.Services["tftp"],
		Talk:              ctx.Services["talk"],
		InetdConfig:       ctx.Runtime.InetdConfig,
		EvidenceAvailable: serviceEvidenceAvailable(ctx),
	}, nil
}

func evalU44(input U44Input) CheckResult {
	active := activeServiceLabels(map[string]Service{"tftp": input.TFTP, "talk": input.Talk}, "tftp", "talk")
	raw := buildLabeledRawConfig([]FileResult{{Path: "service_evidence", Content: strings.Join(active, "\n")}, {Path: "/etc/inetd.conf", Content: input.InetdConfig}})
	if len(active) > 0 {
		return CheckResult{Status: StatusVulnerable, RawConfig: raw, ProcessedConfig: "tftp_talk_ntalk=active", VulnerableConfig: strings.Join(active, "\n")}
	}
	if !input.EvidenceAvailable {
		return CheckResult{Status: StatusInterview, RawConfig: raw, ProcessedConfig: "tftp_talk_ntalk=evidence_unavailable"}
	}
	return CheckResult{Status: StatusGood, RawConfig: raw, ProcessedConfig: "tftp_talk_ntalk=disabled"}
}
