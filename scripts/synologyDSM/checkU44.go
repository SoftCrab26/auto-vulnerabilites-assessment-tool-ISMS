package main

import (
	"strconv"
	"strings"
)

type U44Input struct {
	Active   []string
	Evidence string
	Complete bool
}

func checkU44(ctx ScanContext) CheckResult {
	input, errs := loadU44Input(ctx)
	result := evalU44(input)
	result.Code = "U-44"
	result.Description = "tftp, talk, and ntalk services should be disabled."
	return resultWithErrors(result, errs)
}

func loadU44Input(ctx ScanContext) (U44Input, []string) {
	input := U44Input{Complete: true, Evidence: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList}
	for _, service := range ctx.Services {
		name := strings.ToLower(service.Name)
		if service.IsActive && (name == "tftp" || name == "talk" || name == "ntalk") {
			input.Active = append(input.Active, name)
		}
	}
	ports := listeningPorts(ctx.Runtime.PortList)
	for port, name := range map[int]string{69: "tftp", 517: "talk", 518: "ntalk"} {
		if ports[port] {
			input.Active = append(input.Active, name+"("+strconv.Itoa(port)+")")
		}
	}
	for _, name := range []string{"tftpd", "in.tftpd", "talkd", "in.talkd", "ntalkd", "in.ntalkd"} {
		if containsAnyWord(ctx.Runtime.ProcessList, []string{name}) {
			input.Active = append(input.Active, name)
		}
	}
	for _, err := range ctx.Runtime.Errors {
		lower := strings.ToLower(err)
		if strings.Contains(lower, "process collection") || strings.Contains(lower, "port collection") {
			input.Complete = false
		}
	}
	return input, nil
}

func evalU44(input U44Input) CheckResult {
	active := dsmU44Unique(input.Active)
	if len(active) > 0 {
		return CheckResult{Status: Vulnerable, RawConfig: input.Evidence, ProcessedConfig: "tftp_talk=active", VulnerableConfig: strings.Join(active, ",")}
	}
	if !input.Complete {
		return CheckResult{Status: Manual, RawConfig: input.Evidence, ProcessedConfig: "tftp_talk=evidence_incomplete"}
	}
	return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "tftp_talk=inactive"}
}

func dsmU44Unique(values []string) []string {
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
