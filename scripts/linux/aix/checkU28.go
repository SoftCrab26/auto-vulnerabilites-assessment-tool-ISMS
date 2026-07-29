package main

import "strings"

type U28Input struct {
	PortACL          string
	InetdConfig      string
	FirewallEvidence string
}

func checkU28(ctx ScanContext) CheckResult {
	const code = "U-28"
	const description = "Specific IP and port access restrictions should be configured."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	input, errs := loadU28Input(ctx)
	result := evalU28(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU28Input(ctx ScanContext) (U28Input, []string) {
	files, errs := collectFiles("/etc/security/portacl", "/etc/inetd.conf")
	input := U28Input{InetdConfig: ctx.Runtime.InetdConfig}
	for _, file := range files {
		switch file.Path {
		case "/etc/security/portacl":
			input.PortACL = file.Content
		case "/etc/inetd.conf":
			input.InetdConfig = file.Content
		}
	}
	for _, version := range []string{"4", "6"} {
		firewall, err := runProgram("lsfilt", "-v", version, "-O")
		if err != nil {
			errs = append(errs, "lsfilt IPv"+version+": "+err.Error())
			continue
		}
		input.FirewallEvidence += "[IPv" + version + "]\n" + firewall + "\n"
	}
	return input, errs
}

func evalU28(input U28Input) CheckResult {
	raw := buildLabeledRawConfig([]FileResult{
		{Path: "/etc/security/portacl", Content: input.PortACL},
		{Path: "/etc/inetd.conf", Content: input.InetdConfig},
		{Path: "lsfilt -v 4 -O", Content: input.FirewallEvidence},
	})
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       raw,
		ProcessedConfig: buildProcessedConfig("portacl_present="+boolText(strings.TrimSpace(input.PortACL) != ""), "firewall_evidence_present="+boolText(strings.TrimSpace(input.FirewallEvidence) != "")),
	}
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
