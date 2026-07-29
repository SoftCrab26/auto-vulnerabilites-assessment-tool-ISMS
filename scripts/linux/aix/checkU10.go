package main

import (
	"sort"
	"strings"
)

type U10Input struct {
	Passwd string
}

func checkU10(ctx ScanContext) CheckResult {
	input, errs := loadU10Input()
	result := evalU10(input)
	result.Code = "U-10"
	result.Description = "Each AIX account must have a unique UID."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU10Input() (U10Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U10Input{}, errs
	}
	return U10Input{Passwd: files[0].Content}, errs
}

func evalU10(input U10Input) CheckResult {
	if input.Passwd == "" {
		return CheckResult{Status: StatusError, VulnerableConfig: "required /etc/passwd input is missing"}
	}
	byUID := map[string][]string{}
	for _, line := range strings.Split(input.Passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 3 && fields[0] != "" && fields[2] != "" {
			byUID[fields[2]] = append(byUID[fields[2]], fields[0])
		}
	}
	var duplicates []string
	for uid, users := range byUID {
		if len(users) > 1 {
			sort.Strings(users)
			duplicates = append(duplicates, uid+"("+strings.Join(users, ",")+")")
		}
	}
	sort.Strings(duplicates)
	status := StatusGood
	if len(duplicates) > 0 {
		status = StatusVulnerable
	}
	return CheckResult{Status: status, RawConfig: input.Passwd, ProcessedConfig: "duplicate_uids=" + strings.Join(duplicates, ";"), VulnerableConfig: strings.Join(duplicates, "\n")}
}
