package main

import (
	"strings"
)

func checkU01(services map[string]Service) CheckResult {

	sshService, sshExists := services["ssh"]
	telnetService, telnetExists := services["telnet"]

	// ssh는 무조건 검사
	files, errs := collectFiles(
		"/etc/ssh/sshd_config",
	)

	// telnet 서비스가 실제 실행중일 때만 추가 검사
	if telnetExists && telnetService.Running {

		telnetFiles, telnetErrs := collectFiles(
			"/etc/pam.d/login",
			"/etc/securetty",
		)

		files = append(files, telnetFiles...)
		errs = append(errs, telnetErrs...)
	}

	if len(errs) > 0 {
		return CheckResult{
			Code:   "U-01",
			Status: StatusError,
			ErrMsg: strings.Join(errs, "; "),
		}
	}

	// sshd_config
	raw := files[0].Content

	permitRootLogin := findConfigValue(raw, "PermitRootLogin")

	result := StatusVulnerable

	// SSH root login 제한 확인
	if sshExists &&
		sshService.Running &&
		strings.ToLower(permitRootLogin) == "no" {

		result = StatusGood
	}

	return CheckResult{
		Code:            "U-01",
		Status:          result,
		RawConfig:       raw,
		Description:     "SSH root login should be disabled to prevent unauthorized access.",
		ProcessedConfig: "PermitRootLogin: " + permitRootLogin,

		ErrMsg: strings.Join(errs, "; "),
	}
}
