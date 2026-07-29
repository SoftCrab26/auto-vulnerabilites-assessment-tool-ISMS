package main

import "strings"

type U51Input struct {
	DNS       Service
	NamedConf string
	Found     bool
}

func checkU51(ctx ScanContext) CheckResult {
	input, errs := loadU51Input(ctx)
	result := evalU51(input)
	result.Code = "U-51"
	result.Description = "Disable or restrict DNS dynamic updates."
	result.MitreAttack = MitreAttack{Tactic: "Impact", Techniques: []string{"T1565"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU51Input(ctx ScanContext) (U51Input, []string) {
	file, errs := collectFirstExisting("/etc/named.conf", "/etc/named.boot")
	return U51Input{DNS: ctx.Services["dns"], NamedConf: file.Content, Found: file.Path != ""}, errs
}

func evalU51(input U51Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.NamedConf) == "" {
		return missingServiceConfig(input.DNS, "named.conf")
	}
	values := namedDirectiveValues(input.NamedConf, "allow-update")
	unrestricted := false
	for _, value := range values {
		if aclIsUnrestricted(value) {
			unrestricted = true
			break
		}
	}
	label := "none_or_restricted"
	if len(values) == 1 && strings.EqualFold(strings.Trim(strings.TrimSpace(values[0]), ";"), "none") {
		label = "none"
	}
	result := CheckResult{Status: StatusGood, RawConfig: input.NamedConf, ProcessedConfig: "allow-update=" + label}
	if unrestricted {
		result.Status = StatusVulnerable
		result.ProcessedConfig = "allow-update=unrestricted"
		result.VulnerableConfig = "allow-update permits unrestricted dynamic updates."
	}
	return result
}
