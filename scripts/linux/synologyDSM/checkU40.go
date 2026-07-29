package main

import (
	"os"
	"strings"
)

type U40Input struct {
	NFSActive   bool
	Exports     string
	ExportsSeen bool
	Runtime     string
}

func checkU40(ctx ScanContext) CheckResult {
	input, errs := loadU40Input(ctx)
	result := evalU40(input)
	result.Code = "U-40"
	result.Description = "NFS exports should restrict clients and root privileges."
	return resultWithErrors(result, errs)
}

func loadU40Input(ctx ScanContext) (U40Input, []string) {
	input := U40Input{Runtime: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList}
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "nfs") {
			input.NFSActive = input.NFSActive || service.Running || service.Listening
		}
	}
	input.NFSActive = input.NFSActive || listeningPorts(ctx.Runtime.PortList)[2049] ||
		containsAnyWord(ctx.Runtime.ProcessList, []string{"nfsd", "rpc.mountd"})
	var errs []string
	for _, path := range []string{"/etc/exports", "/etc.defaults/exports"} {
		data, err := os.ReadFile(path)
		if err == nil {
			input.ExportsSeen = true
			input.Exports += "[" + path + "]\n" + string(data) + "\n"
		} else if !os.IsNotExist(err) {
			errs = append(errs, path+": "+err.Error())
		}
	}
	return input, errs
}

func evalU40(input U40Input) CheckResult {
	raw := input.Runtime + "\n" + input.Exports
	if !input.NFSActive {
		return CheckResult{Status: NotApplicable, RawConfig: raw, ProcessedConfig: "nfs=inactive"}
	}
	lines := dsmU40ExportLines(input.Exports)
	if !input.ExportsSeen || len(lines) == 0 {
		return CheckResult{Status: Manual, RawConfig: raw, ProcessedConfig: "nfs=active exports=evidence_unavailable"}
	}
	var unsafe []string
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "no_root_squash") || strings.Contains(line, " *") || strings.Contains(line, "\t*") {
			unsafe = append(unsafe, line)
		}
	}
	if len(unsafe) > 0 {
		return CheckResult{Status: Vulnerable, RawConfig: raw, ProcessedConfig: "nfs=active exports=unsafe", VulnerableConfig: strings.Join(unsafe, "\n")}
	}
	return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "nfs=active exports=restricted"}
}

func dsmU40ExportLines(raw string) []string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" && !strings.HasPrefix(line, "[") {
			lines = append(lines, line)
		}
	}
	return lines
}
