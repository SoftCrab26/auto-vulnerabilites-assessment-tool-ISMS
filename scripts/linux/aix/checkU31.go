package main

import (
	"os"
	"strconv"
	"strings"
)

type U31Home struct {
	User   string
	Path   string
	Exists bool
	Owner  string
	Mode   os.FileMode
}

type U31Input struct {
	Passwd string
	Homes  []U31Home
}

func checkU31(ctx ScanContext) CheckResult {
	const code = "U-31"
	const description = "Home directories should be owned by the corresponding user and not writable by group or others."
	mitre := MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1552"}, Mitigations: []string{"M1022"}}
	input, errs := loadU31Input()
	result := evalU31(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	if len(errs) > 0 && result.Status == StatusGood {
		result.Status = StatusInterview
		result.ProcessedConfig = "home_metadata=incomplete"
	}
	return resultWithErrors(result, errs)
}

func loadU31Input() (U31Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U31Input{}, errs
	}
	input := U31Input{Passwd: files[0].Content}
	for _, account := range passwdHomes(input.Passwd) {
		info, err := os.Stat(account.Path)
		if os.IsNotExist(err) {
			input.Homes = append(input.Homes, account)
			continue
		}
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		owner, err := fileOwnerName(account.Path)
		if err != nil {
			errs = append(errs, err.Error())
		}
		account.Exists, account.Owner, account.Mode = true, owner, info.Mode()
		input.Homes = append(input.Homes, account)
	}
	return input, errs
}

func evalU31(input U31Input) CheckResult {
	if strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: StatusInterview, ProcessedConfig: "passwd=unavailable"}
	}
	var checked, issues []string
	for _, home := range input.Homes {
		if !home.Exists {
			continue // U-32 reports missing home directories.
		}
		item := home.User + ":" + home.Path + " owner=" + home.Owner + " mode=" + strconv.FormatUint(uint64(home.Mode.Perm()), 8)
		checked = append(checked, item)
		if home.Owner == "" {
			return CheckResult{Status: StatusInterview, RawConfig: strings.Join(checked, "\n"), ProcessedConfig: "home_metadata=incomplete"}
		}
		if !home.Mode.IsDir() || home.Owner != home.User || home.Mode.Perm()&0022 != 0 {
			issues = append(issues, item)
		}
	}
	if len(input.Homes) == 0 {
		return CheckResult{Status: StatusInterview, RawConfig: input.Passwd, ProcessedConfig: "home_metadata=unavailable"}
	}
	if len(issues) > 0 {
		return CheckResult{Status: StatusVulnerable, RawConfig: strings.Join(checked, "\n"), ProcessedConfig: "home_owner_permission=noncompliant", VulnerableConfig: strings.Join(issues, "\n")}
	}
	return CheckResult{Status: StatusGood, RawConfig: strings.Join(checked, "\n"), ProcessedConfig: "home_owner_permission=compliant"}
}

func passwdHomes(raw string) []U31Home {
	var homes []U31Home
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 6 && fields[0] != "" && fields[5] != "" && fields[5] != "/" {
			homes = append(homes, U31Home{User: fields[0], Path: fields[5]})
		}
	}
	return homes
}
