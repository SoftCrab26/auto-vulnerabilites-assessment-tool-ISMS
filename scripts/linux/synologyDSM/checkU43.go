package main

import "strings"

type U43Input struct {
	Active   bool
	Evidence string
	Complete bool
}

func checkU43(ctx ScanContext) CheckResult {
	input, errs := loadU43Input(ctx)
	result := evalU43(input)
	result.Code = "U-43"
	result.Description = "NIS/NIS+ services should be disabled."
	return resultWithErrors(result, errs)
}

func loadU43Input(ctx ScanContext) (U43Input, []string) {
	input := U43Input{Complete: true, Evidence: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList + "\n[packages]\n" + ctx.Runtime.PackageList}
	for _, service := range ctx.Services {
		name := strings.ToLower(service.Name)
		if service.IsActive && (name == "nis" || name == "nis+" || name == "ypbind" || name == "ypserv") {
			input.Active = true
		}
	}
	input.Active = input.Active || containsAnyWord(ctx.Runtime.ProcessList, []string{"ypbind", "ypserv", "ypxfrd", "rpc.yppasswdd", "nis_cachemgr"})
	for _, err := range ctx.Runtime.Errors {
		if strings.Contains(strings.ToLower(err), "process collection") {
			input.Complete = false
		}
	}
	return input, nil
}

func evalU43(input U43Input) CheckResult {
	if input.Active {
		return CheckResult{Status: Vulnerable, RawConfig: input.Evidence, ProcessedConfig: "nis=active", VulnerableConfig: "NIS/NIS+ runtime evidence is active."}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "nis=evidence_incomplete"}
	}
	return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "nis=inactive"}
}
