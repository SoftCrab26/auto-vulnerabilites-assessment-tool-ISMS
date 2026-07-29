package main

import "strings"

type U41Input struct {
	Active   bool
	Evidence string
	Complete bool
}

func checkU41(ctx ScanContext) CheckResult {
	input, errs := loadU41Input(ctx)
	result := evalU41(input)
	result.Code = "U-41"
	result.Description = "Unnecessary automount service should be disabled."
	return resultWithErrors(result, errs)
}

func loadU41Input(ctx ScanContext) (U41Input, []string) {
	input := U41Input{Complete: true, Evidence: "[processes]\n" + ctx.Runtime.ProcessList + "\n[packages]\n" + ctx.Runtime.PackageList}
	for _, service := range ctx.Services {
		name := strings.ToLower(service.Name)
		if (name == "automount" || name == "autofs") && service.IsActive {
			input.Active = true
		}
	}
	input.Active = input.Active || containsAnyWord(ctx.Runtime.ProcessList, []string{"automount", "automountd", "autofs"})
	for _, err := range ctx.Runtime.Errors {
		if strings.Contains(strings.ToLower(err), "process collection") {
			input.Complete = false
		}
	}
	return input, nil
}

func evalU41(input U41Input) CheckResult {
	if input.Active {
		return CheckResult{Status: Vulnerable, RawConfig: input.Evidence, ProcessedConfig: "automount=active", VulnerableConfig: "automount/autofs runtime evidence is active."}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "automount=evidence_incomplete"}
	}
	return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "automount=inactive"}
}
