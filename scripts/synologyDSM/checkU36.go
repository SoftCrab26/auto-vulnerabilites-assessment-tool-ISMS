package main

import "strings"

type U36Input struct {
	Active   []string
	Evidence string
	Complete bool
}

func checkU36(ctx ScanContext) CheckResult {
	input, errs := loadU36Input(ctx)
	result := evalU36(input)
	result.Code = "U-36"
	result.Description = "rsh, rexec, and rlogin services should be disabled."
	return resultWithErrors(result, errs)
}

func loadU36Input(ctx ScanContext) (U36Input, []string) {
	input := U36Input{Complete: true, Evidence: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList}
	for _, service := range ctx.Services {
		name := strings.ToLower(service.Name)
		if service.IsActive && (name == "rsh" || name == "rexec" || name == "rlogin") {
			input.Active = append(input.Active, name)
		}
	}
	ports := listeningPorts(ctx.Runtime.PortList)
	for port, name := range map[int]string{512: "rexec", 513: "rlogin", 514: "rsh"} {
		if ports[port] {
			input.Active = append(input.Active, name)
		}
	}
	for _, name := range []string{"rshd", "rexecd", "rlogind"} {
		if containsAnyWord(ctx.Runtime.ProcessList, []string{name}) {
			input.Active = append(input.Active, name)
		}
	}
	for _, err := range ctx.Runtime.Errors {
		if strings.Contains(strings.ToLower(err), "process collection") || strings.Contains(strings.ToLower(err), "port collection") {
			input.Complete = false
		}
	}
	return input, nil
}

func evalU36(input U36Input) CheckResult {
	active := dsmU36Unique(input.Active)
	if len(active) > 0 {
		return CheckResult{Status: Vulnerable, RawConfig: input.Evidence, ProcessedConfig: "r_services=active", VulnerableConfig: strings.Join(active, ",")}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "r_services=evidence_incomplete"}
	}
	return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "r_services=inactive"}
}

func dsmU36Unique(values []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
