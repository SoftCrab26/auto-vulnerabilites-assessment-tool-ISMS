package main

import "strings"

type U42Input struct {
	Active   bool
	Evidence string
	Complete bool
}

func checkU42(ctx ScanContext) CheckResult {
	input, errs := loadU42Input(ctx)
	result := evalU42(input)
	result.Code = "U-42"
	result.Description = "Unnecessary RPC services should be disabled."
	return resultWithErrors(result, errs)
}

func loadU42Input(ctx ScanContext) (U42Input, []string) {
	input := U42Input{Complete: true, Evidence: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList}
	for _, service := range ctx.Services {
		name := strings.ToLower(service.Name)
		if service.IsActive && (name == "rpc" || name == "rpcbind" || name == "portmap") {
			input.Active = true
		}
	}
	input.Active = input.Active || listeningPorts(ctx.Runtime.PortList)[111] ||
		containsAnyWord(ctx.Runtime.ProcessList, []string{"rpcbind", "portmap", "rpc.statd", "rpc.mountd"})
	for _, err := range ctx.Runtime.Errors {
		lower := strings.ToLower(err)
		if strings.Contains(lower, "process collection") || strings.Contains(lower, "port collection") {
			input.Complete = false
		}
	}
	return input, nil
}

func evalU42(input U42Input) CheckResult {
	if input.Active {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "rpc=active necessity_review=true"}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "rpc=evidence_incomplete"}
	}
	return CheckResult{Status: NotApplicable, RawConfig: input.Evidence, ProcessedConfig: "rpc=inactive"}
}
