package main

import "strings"

type U34Input struct {
	Active   bool
	Evidence string
	Complete bool
}

func checkU34(ctx ScanContext) CheckResult {
	input, errs := loadU34Input(ctx)
	result := evalU34(input)
	result.Code = "U-34"
	result.Description = "Finger service should be disabled."
	return resultWithErrors(result, errs)
}

func loadU34Input(ctx ScanContext) (U34Input, []string) {
	input := U34Input{Complete: dsmU34RuntimeComplete(ctx.Runtime)}
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "finger") {
			input.Active = input.Active || service.IsActive
		}
	}
	ports := listeningPorts(ctx.Runtime.PortList)
	input.Active = input.Active || ports[79] || containsAnyWord(ctx.Runtime.ProcessList, []string{"fingerd", "in.fingerd"})
	input.Evidence = "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList
	return input, nil
}

func evalU34(input U34Input) CheckResult {
	if input.Active {
		return CheckResult{Status: Vulnerable, RawConfig: input.Evidence, ProcessedConfig: "finger=active", VulnerableConfig: "Finger service evidence is active."}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "finger=evidence_incomplete"}
	}
	return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "finger=inactive"}
}

func dsmU34RuntimeComplete(runtime RuntimeData) bool {
	for _, item := range runtime.Errors {
		lower := strings.ToLower(item)
		if strings.Contains(lower, "process collection") || strings.Contains(lower, "port collection") {
			return false
		}
	}
	return true
}
