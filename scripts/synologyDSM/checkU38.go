package main

import (
	"strconv"
	"strings"
)

type U38Input struct {
	Active   []string
	Evidence string
	Complete bool
}

func checkU38(ctx ScanContext) CheckResult {
	input, errs := loadU38Input(ctx)
	result := evalU38(input)
	result.Code = "U-38"
	result.Description = "echo, discard, daytime, and chargen services should be disabled."
	return resultWithErrors(result, errs)
}

func loadU38Input(ctx ScanContext) (U38Input, []string) {
	input := U38Input{Complete: true, Evidence: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList}
	for _, service := range ctx.Services {
		name := strings.ToLower(service.Name)
		if service.IsActive && (name == "echo" || name == "discard" || name == "daytime" || name == "chargen") {
			input.Active = append(input.Active, name)
		}
	}
	ports := listeningPorts(ctx.Runtime.PortList)
	for port, name := range map[int]string{7: "echo", 9: "discard", 13: "daytime", 19: "chargen"} {
		if ports[port] {
			input.Active = append(input.Active, name+"("+strconv.Itoa(port)+")")
		}
	}
	for _, err := range ctx.Runtime.Errors {
		if strings.Contains(strings.ToLower(err), "process collection") || strings.Contains(strings.ToLower(err), "port collection") {
			input.Complete = false
		}
	}
	return input, nil
}

func evalU38(input U38Input) CheckResult {
	active := dsmU38Unique(input.Active)
	if len(active) > 0 {
		return CheckResult{Status: Vulnerable, RawConfig: input.Evidence, ProcessedConfig: "legacy_dos_services=active", VulnerableConfig: strings.Join(active, ",")}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "legacy_dos_services=evidence_incomplete"}
	}
	return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "legacy_dos_services=inactive"}
}

func dsmU38Unique(values []string) []string {
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
