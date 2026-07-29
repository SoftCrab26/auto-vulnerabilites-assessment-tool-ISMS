package main

import "strings"

type U39Input struct {
	Active   bool
	Evidence string
	Complete bool
}

func checkU39(ctx ScanContext) CheckResult {
	input, errs := loadU39Input(ctx)
	result := evalU39(input)
	result.Code = "U-39"
	result.Description = "Unnecessary NFS service should be disabled."
	return resultWithErrors(result, errs)
}

func loadU39Input(ctx ScanContext) (U39Input, []string) {
	input := U39Input{Complete: true, Evidence: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList + "\n[packages]\n" + ctx.Runtime.PackageList}
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "nfs") {
			input.Active = input.Active || service.Running || service.Listening
		}
	}
	ports := listeningPorts(ctx.Runtime.PortList)
	input.Active = input.Active || ports[2049] || containsAnyWord(ctx.Runtime.ProcessList, []string{"nfsd", "rpc.mountd"})
	for _, err := range ctx.Runtime.Errors {
		lower := strings.ToLower(err)
		if strings.Contains(lower, "process collection") || strings.Contains(lower, "port collection") {
			input.Complete = false
		}
	}
	return input, nil
}

func evalU39(input U39Input) CheckResult {
	if input.Active {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "nfs=active necessity_review=true"}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "nfs=evidence_incomplete"}
	}
	return CheckResult{Status: NotApplicable, RawConfig: input.Evidence, ProcessedConfig: "nfs=inactive"}
}
