package main

import (
	"strings"
)

type U13Input struct {
	SourceFile string
	Content    string
}

func checkU13(ctx ScanContext) CheckResult {
	const code = "U-13"
	const description = "Safe password encryption algorithm (SHA-2 or stronger) should be used."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1110"},
		mitigations: []string{"M1027"},
	}

	input, errs := loadU13Input()

	result := evalU13(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU13Input() (U13Input, []string) {
	files, shadowErrs := collectFiles("/etc/shadow")
	if len(files) > 0 {
		return U13Input{SourceFile: files[0].Path, Content: files[0].Content}, nil
	}

	files, passwdErrs := collectFiles("/etc/passwd")
	if len(files) > 0 {
		return U13Input{SourceFile: files[0].Path, Content: files[0].Content}, nil
	}

	return U13Input{}, append(shadowErrs, passwdErrs...)
}

func evalU13(input U13Input) CheckResult {
	var checked []string
	var weakUsers []string

	for _, line := range strings.Split(input.Content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}

		user := fields[0]
		hash := fields[1]
		algo := classifyPasswordHash(hash)
		if algo == "locked" || algo == "delegated" {
			continue
		}

		checked = append(checked, user+"="+algo)
		if !isSafePasswordHash(algo) {
			weakUsers = append(weakUsers, user+"("+algo+")")
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(weakUsers) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"weak_users="+strings.Join(weakUsers, ","),
			"문제점1. SHA-2 미만의 암호화 알고리즘을 사용하는 계정이 있습니다: "+strings.Join(weakUsers, ", "),
		)
	} else if len(checked) == 0 && input.SourceFile == "/etc/passwd" {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"password_hashes=NOT_FOUND",
			"문제점1. /etc/passwd의 암호화 필드가 'x'로만 설정되어 있어 해시 알고리즘을 확인할 수 없습니다. /etc/shadow 확인이 필요합니다.",
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        input.Content,
		ProcessedConfig:  buildProcessedConfig("source="+input.SourceFile, "checked="+strings.Join(checked, ",")),
		VulnerableConfig: vulnerableConfig,
	}
}

func classifyPasswordHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" || hash == "*" || strings.HasPrefix(hash, "!") {
		return "locked"
	}
	if hash == "x" {
		return "delegated"
	}
	if strings.HasPrefix(hash, "$6$") {
		return "SHA512"
	}
	if strings.HasPrefix(hash, "$5$") {
		return "SHA256"
	}
	if strings.HasPrefix(hash, "$y$") {
		return "YESCRYPT"
	}
	if strings.HasPrefix(hash, "$7$") {
		return "SCRYPT"
	}
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return "BLOWFISH"
	}
	if strings.HasPrefix(hash, "$1$") {
		return "MD5"
	}
	if strings.HasPrefix(hash, "$") {
		return "UNKNOWN"
	}
	if len(hash) == 13 {
		return "DES"
	}
	return "UNKNOWN"
}

func isSafePasswordHash(algo string) bool {
	switch algo {
	case "SHA512", "SHA256", "YESCRYPT", "SCRYPT", "BLOWFISH":
		return true
	default:
		return false
	}
}
