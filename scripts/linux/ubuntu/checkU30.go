package main

import (
	"strings"
)

type U30Input struct {
	LoginDefs string
	Profile   string
}

func checkU30(ctx ScanContext) CheckResult {
	const code = "U-30"
	const description = "UMASK should be set to 022 or greater (more restrictive)."
	mitreAttack := MitreAttack{
		Tactic:      "Defense Evasion",
		Techniques:  []string{"T1222"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU30Input()

	result := evalU30(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU30Input() (U30Input, []string) {
	files, errs1 := collectFiles("/etc/login.defs")
	profileFiles, errs2 := collectFiles("/etc/profile", "/etc/bashrc")
	errs := append(errs1, errs2...)
	var profileCombined strings.Builder
	for _, f := range profileFiles {
		profileCombined.WriteString(f.Content + "\n")
	}
	loginContent := ""
	if len(files) > 0 {
		loginContent = files[0].Content
	}
	return U30Input{
		LoginDefs: loginContent,
		Profile:   profileCombined.String(),
	}, errs
}

func evalU30(input U30Input) CheckResult {
	loginDefs := input.LoginDefs
	profile := input.Profile

	umaskValue := findConfigValue(loginDefs, "UMASK")
	if umaskValue == "NOT_FOUND" {
		// try profile
		for _, line := range strings.Split(profile, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToLower(line), "umask ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					umaskValue = parts[1]
					break
				}
			}
		}
	}

	status := StatusVulnerable
	vulnerableConfig := ""
	umaskOK := false
	if umaskValue != "NOT_FOUND" {
		val := safeAtoi(umaskValue)
		if val >= 22 { // 022 or higher like 027, 077
			umaskOK = true
			status = StatusGood
		}
	}

	if !umaskOK {
		vulnerableConfig = buildVulnerableConfig(
			"UMASK="+umaskValue,
			"문제점1. UMASK 값이 022 이상으로 설정되어 있지 않습니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        loginDefs + "\n" + profile,
		ProcessedConfig:  buildProcessedConfig("UMASK=" + umaskValue),
		VulnerableConfig: vulnerableConfig,
	}
}
