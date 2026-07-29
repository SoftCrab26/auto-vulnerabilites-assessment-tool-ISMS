package main

import (
	"os"
	"strings"
)

type dsmU32Home struct {
	User   string
	Path   string
	Exists bool
}

type U32Input struct {
	Passwd string
	Homes  []dsmU32Home
}

func checkU32(ctx ScanContext) CheckResult {
	input, errs := loadU32Input(ctx)
	result := evalU32(input)
	result.Code = "U-32"
	result.Description = "Home directories configured in /etc/passwd should exist."
	return resultWithErrors(result, errs)
}

func loadU32Input(_ ScanContext) (U32Input, []string) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return U32Input{}, []string{"/etc/passwd: " + err.Error()}
	}
	input := U32Input{Passwd: string(data)}
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 || fields[5] == "" || fields[5] == "/" || fields[5] == "/nonexistent" {
			continue
		}
		info, statErr := os.Stat(fields[5])
		if statErr != nil && !os.IsNotExist(statErr) {
			return input, []string{fields[5] + ": " + statErr.Error()}
		}
		input.Homes = append(input.Homes, dsmU32Home{User: fields[0], Path: fields[5], Exists: statErr == nil && info.IsDir()})
	}
	return input, nil
}

func evalU32(input U32Input) CheckResult {
	if strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: Error, ProcessedConfig: "passwd=evidence_unavailable", ErrMsg: "/etc/passwd evidence is required"}
	}
	var raw, missing []string
	for _, home := range input.Homes {
		line := home.User + " -> " + home.Path
		raw = append(raw, line)
		if !home.Exists {
			missing = append(missing, line)
		}
	}
	if len(missing) > 0 {
		return CheckResult{Status: Vulnerable, RawConfig: strings.Join(raw, "\n"), ProcessedConfig: "home_existence=failed", VulnerableConfig: strings.Join(missing, "\n")}
	}
	return CheckResult{Status: Good, RawConfig: strings.Join(raw, "\n"), ProcessedConfig: "home_existence=passed"}
}
