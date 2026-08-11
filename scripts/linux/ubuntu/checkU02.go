package main

import (
	"strings"
)

type U02Input struct {
	SystemAuth string
	Pwquality  string
	LoginDefs  string
}

func checkU02(ctx ScanContext) CheckResult {
	const code = "U-02"
	const description = "Password complexity must be enforced through PAM and password quality settings."
	mitreAttack := MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1110"}, // Brute Force
		Mitigations: []string{"M1027"}, // Password Policies
	}

	input, errs := loadU02Input()

	result := evalU02(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU02Input() (U02Input, []string) {
	files, errs := collectFiles(
		"/etc/pam.d/system-auth",
		"/etc/security/pwquality.conf",
		"/etc/login.defs",
	)

	if len(files) < 3 {
		return U02Input{}, errs
	}

	return U02Input{
		SystemAuth: files[0].Content,
		Pwquality:  files[1].Content,
		LoginDefs:  files[2].Content,
	}, errs
}

func evalU02(input U02Input) CheckResult {
	systemAuth := input.SystemAuth
	pwquality := input.Pwquality
	loginDefs := input.LoginDefs

	passwordModule := "NOT_FOUND"
	if strings.Contains(systemAuth, "pam_pwquality.so") {
		passwordModule = "pam_pwquality.so"
	} else if strings.Contains(systemAuth, "pam_cracklib.so") {
		passwordModule = "pam_cracklib.so"
	}

	minlen := findConfigValue(pwquality, "minlen")
	ucredit := findConfigValue(pwquality, "ucredit")
	lcredit := findConfigValue(pwquality, "lcredit")
	dcredit := findConfigValue(pwquality, "dcredit")
	ocredit := findConfigValue(pwquality, "ocredit")
	passMinLen := findConfigValue(loginDefs, "PASS_MIN_LEN")

	result := StatusVulnerable
	vulnerableConfig := ""
	if passwordModule != "NOT_FOUND" && safeAtoi(minlen) >= 8 && safeAtoi(ucredit) <= -1 && safeAtoi(lcredit) <= -1 && safeAtoi(dcredit) <= -1 && safeAtoi(ocredit) <= -1 && safeAtoi(passMinLen) >= 8 {
		result = StatusGood
	} else {
		reasons := []string{}
		if passwordModule == "NOT_FOUND" {
			reasons = append(reasons, "문제점1. PAM 패스워드 품질 모듈이 설정되어 있지 않습니다.")
		} else {
			if safeAtoi(minlen) < 8 {
				reasons = append(reasons, "문제점1. minlen 값이 8보다 작습니다.")
			}
			if safeAtoi(ucredit) > -1 {
				reasons = append(reasons, "문제점2. ucredit가 -1 이하가 아닙니다.")
			}
			if safeAtoi(lcredit) > -1 {
				reasons = append(reasons, "문제점3. lcredit가 -1 이하가 아닙니다.")
			}
			if safeAtoi(dcredit) > -1 {
				reasons = append(reasons, "문제점4. dcredit가 -1 이하가 아닙니다.")
			}
			if safeAtoi(ocredit) > -1 {
				reasons = append(reasons, "문제점5. ocredit가 -1 이하가 아닙니다.")
			}
			if safeAtoi(passMinLen) < 8 {
				reasons = append(reasons, "문제점6. PASS_MIN_LEN이 8보다 작습니다.")
			}
		}
		vulnerableConfig = buildVulnerableConfig(
			"module="+passwordModule,
			"minlen="+minlen,
			"ucredit="+ucredit,
			"lcredit="+lcredit,
			"dcredit="+dcredit,
			"ocredit="+ocredit,
			"PASS_MIN_LEN="+passMinLen,
			strings.Join(reasons, "\n"),
		)
	}

	return CheckResult{
		Status:           result,
		RawConfig:        pwquality + "\n" + loginDefs + "\n" + systemAuth,
		ProcessedConfig:  buildProcessedConfig("module="+passwordModule, "minlen="+minlen, "ucredit="+ucredit, "lcredit="+lcredit, "dcredit="+dcredit, "ocredit="+ocredit, "PASS_MIN_LEN="+passMinLen),
		VulnerableConfig: vulnerableConfig,
	}
}
