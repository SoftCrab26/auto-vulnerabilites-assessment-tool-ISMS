package main

import "strings"

type U02Input struct {
	SecurityUser string
}

func checkU02(ctx ScanContext) CheckResult {
	input, errs := loadU02Input()
	result := evalU02(input)
	result.Code = "U-02"
	result.Description = "Password length and character-class complexity must be enforced."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1110"}, Mitigations: []string{"M1027"}}
	return resultWithErrors(result, errs)
}

func loadU02Input() (U02Input, []string) {
	files, errs := collectFiles("/etc/security/user")
	if len(files) == 0 {
		return U02Input{}, errs
	}
	return U02Input{SecurityUser: files[0].Content}, errs
}

func evalU02(input U02Input) CheckResult {
	minlen := findStanzaValue(input.SecurityUser, "default", "minlen")
	minalpha := findStanzaValue(input.SecurityUser, "default", "minalpha")
	minother := findStanzaValue(input.SecurityUser, "default", "minother")
	status := StatusGood
	var problems []string
	if input.SecurityUser == "" {
		status = StatusError
		problems = append(problems, "required /etc/security/user input is missing")
	} else {
		if minlen == "NOT_FOUND" || safeAtoi(minlen) < 8 {
			problems = append(problems, "default.minlen must be at least 8")
		}
		if minalpha == "NOT_FOUND" || safeAtoi(minalpha) < 1 {
			problems = append(problems, "default.minalpha must be at least 1")
		}
		if minother == "NOT_FOUND" || safeAtoi(minother) < 1 {
			problems = append(problems, "default.minother must be at least 1")
		}
		if len(problems) > 0 {
			status = StatusVulnerable
		}
	}
	return CheckResult{
		Status: status, RawConfig: extractStanza(input.SecurityUser, "default"),
		ProcessedConfig:  buildProcessedConfig("minlen="+minlen, "minalpha="+minalpha, "minother="+minother),
		VulnerableConfig: strings.Join(problems, "\n"),
	}
}
