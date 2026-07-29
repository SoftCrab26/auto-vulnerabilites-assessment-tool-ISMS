package main

import (
	"strconv"
	"strings"
)

type U12Input struct {
	Profiles []FileResult
}

func checkU12(ctx ScanContext) CheckResult {
	input, errs := loadU12Input()
	result := evalU12(input)
	result.Code = "U-12"
	result.Description = "AIX interactive session timeout must be set to 600 seconds or less."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1028"}}
	return resultWithErrors(result, errs)
}

func loadU12Input() (U12Input, []string) {
	files, errs := collectFiles("/etc/profile", "/etc/environment", "/etc/security/environ", "/root/.profile")
	return U12Input{Profiles: files}, errs
}

func evalU12(input U12Input) CheckResult {
	if len(input.Profiles) == 0 {
		return CheckResult{Status: StatusError, VulnerableConfig: "required AIX profile input is missing"}
	}
	var settings, invalid []string
	for _, file := range input.Profiles {
		for _, line := range strings.Split(file.Content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if index := strings.Index(line, "#"); index >= 0 {
				line = strings.TrimSpace(line[:index])
			}
			for _, name := range []string{"TMOUT", "TIMEOUT"} {
				if value, ok := aixTimeoutValue(line, name); ok {
					label := file.Path + ":" + name + "=" + value
					settings = append(settings, label)
					number, err := strconv.Atoi(value)
					if err != nil || number < 1 || number > 600 {
						invalid = append(invalid, label)
					}
				}
			}
		}
	}
	status := StatusGood
	problem := ""
	if len(settings) == 0 {
		status, problem = StatusVulnerable, "TMOUT/TIMEOUT is not configured"
	} else if len(invalid) > 0 {
		status, problem = StatusVulnerable, strings.Join(invalid, "\n")
	}
	return CheckResult{Status: status, RawConfig: buildLabeledRawConfig(input.Profiles), ProcessedConfig: strings.Join(settings, " "), VulnerableConfig: problem}
}

func aixTimeoutValue(line, name string) (string, bool) {
	upper := strings.ToUpper(line)
	index := strings.Index(upper, name)
	if index < 0 {
		return "", false
	}
	rest := strings.TrimSpace(line[index+len(name):])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false
	}
	return strings.Trim(fields[0], " ;\"'"), true
}
