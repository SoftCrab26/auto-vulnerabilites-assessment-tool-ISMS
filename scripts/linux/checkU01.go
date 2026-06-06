package main

import (
	"strings"
)

type U01Input struct {
	RawSSHConfig string
	SSHService   Service
}

func checkU01(services map[string]Service) CheckResult {
	const code = "U-01"
	const description = "SSH root login should be disabled to prevent unauthorized access."

	input, errs := loadU01Input(services)
	if len(errs) > 0 {
		return errorResult(code, errs)
	}

	result := evalU01(input)
	result.Code = code
	result.Description = description
	return result
}

func loadU01Input(services map[string]Service) (U01Input, []string) {
	sshService, _ := services["ssh"]
	telnetService, telnetExists := services["telnet"]

	files, errs := collectFiles("/etc/ssh/sshd_config")
	if telnetExists && telnetService.Running {
		telnetFiles, telnetErrs := collectFiles(
			"/etc/pam.d/login",
			"/etc/securetty",
		)

		files = append(files, telnetFiles...)
		errs = append(errs, telnetErrs...)
	}

	if len(files) == 0 {
		return U01Input{}, errs
	}

	return U01Input{
		RawSSHConfig: files[0].Content,
		SSHService:   sshService,
	}, errs
}

func evalU01(input U01Input) CheckResult {
	permitRootLogin := findConfigValue(input.RawSSHConfig, "PermitRootLogin")

	result := StatusVulnerable
	vulnerableConfig := ""

	// 판단 기준: 설정 파일에 PermitRootLogin이 "no" 로 명시되어 있으면 안전으로 간주합니다.
	// 서비스 감지 여부에 의존하지 않고 config 값 자체를 우선으로 평가합니다.
	if strings.ToLower(permitRootLogin) == "no" {
		result = StatusGood
	} else {
		vulnerableConfig = buildVulnerableConfig(
			"PermitRootLogin:"+permitRootLogin,
			"문제점1. 원격에서 root 계정으로 직접 로그인할 수 있습니다.",
		)
	}

	return CheckResult{
		Status:           result,
		RawConfig:        input.RawSSHConfig,
		ProcessedConfig:  buildProcessedConfig("PermitRootLogin:" + permitRootLogin),
		VulnerableConfig: vulnerableConfig,
	}
}
