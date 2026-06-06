package main

import (
	"strconv"
	"strings"
)

func checkU02() CheckResult {
	files, errs := collectFiles(
		"/etc/pam.d/system-auth",
		"/etc/security/pwquality.conf",
		"/etc/login.defs",
	)

	if len(errs) > 0 {
		return CheckResult{
			Code:   "U-02",
			Status: StatusError,
			ErrMsg: strings.Join(errs, "; "),
		}
	}

	systemAuth := files[0].Content
	pwquality := files[1].Content
	loginDefs := files[2].Content

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

	if passwordModule != "NOT_FOUND" {
		minlenValue, _ := strconv.Atoi(minlen)
		uValue, _ := strconv.Atoi(ucredit)
		lValue, _ := strconv.Atoi(lcredit)
		dValue, _ := strconv.Atoi(dcredit)
		oValue, _ := strconv.Atoi(ocredit)
		passMinLenValue, _ := strconv.Atoi(passMinLen)

		if minlenValue >= 8 && uValue <= -1 && lValue <= -1 && dValue <= -1 && oValue <= -1 && passMinLenValue >= 8 {
			result = StatusGood
		}
	}

	return CheckResult{
		Code:        "U-02",
		Status:      result,
		Description: "Password complexity must be enforced through PAM and password quality settings.",
		RawConfig:   pwquality,
		ProcessedConfig: "module=" + passwordModule +
			" minlen=" + minlen +
			" ucredit=" + ucredit +
			" lcredit=" + lcredit +
			" dcredit=" + dcredit +
			" ocredit=" + ocredit +
			" PASS_MIN_LEN=" + passMinLen,
		ErrMsg: strings.Join(errs, "; "),
	}
}
