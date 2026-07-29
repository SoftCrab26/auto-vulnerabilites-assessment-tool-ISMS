package main

import (
	"sort"
	"strings"
)

type U13Input struct {
	SecurityPasswd string
}

func checkU13(ctx ScanContext) CheckResult {
	input, errs := loadU13Input()
	result := evalU13(input)
	result.Code = "U-13"
	result.Description = "AIX password hashes must use SHA-2 or a stronger algorithm."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1110"}, Mitigations: []string{"M1027"}}
	return resultWithErrors(result, errs)
}

func loadU13Input() (U13Input, []string) {
	files, errs := collectFiles("/etc/security/passwd")
	if len(files) == 0 {
		return U13Input{}, errs
	}
	return U13Input{SecurityPasswd: files[0].Content}, errs
}

func evalU13(input U13Input) CheckResult {
	if input.SecurityPasswd == "" {
		return CheckResult{Status: StatusError, VulnerableConfig: "required /etc/security/passwd input is missing"}
	}
	classifications := aixPasswordClassifications(input.SecurityPasswd)
	if len(classifications) == 0 {
		return CheckResult{Status: StatusError, ProcessedConfig: "password_entries=NOT_FOUND", VulnerableConfig: "no password attributes could be parsed"}
	}
	var labels, weak []string
	for user, algorithm := range classifications {
		label := user + "=" + algorithm
		labels = append(labels, label)
		if algorithm != "LOCKED" && !safeAIXPasswordAlgorithm(algorithm) {
			weak = append(weak, label)
		}
	}
	sort.Strings(labels)
	sort.Strings(weak)
	status := StatusGood
	if len(weak) > 0 {
		status = StatusVulnerable
	}
	sanitized := strings.Join(labels, "\n")
	return CheckResult{
		Status: status, RawConfig: sanitized, ProcessedConfig: "password_algorithms=" + strings.Join(labels, ","),
		VulnerableConfig: strings.Join(weak, "\n"),
	}
}

func aixPasswordClassifications(raw string) map[string]string {
	result := map[string]string{}
	current := ""
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, ":") && !strings.Contains(line, "=") {
			current = strings.TrimSpace(strings.TrimSuffix(line, ":"))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if current != "" && len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "password") {
			result[current] = classifyAIXPasswordHash(strings.TrimSpace(parts[1]))
		}
	}
	return result
}

func classifyAIXPasswordHash(hash string) string {
	upper := strings.ToUpper(strings.TrimSpace(hash))
	switch {
	case upper == "" || upper == "*" || upper == "!" || upper == "NP":
		return "LOCKED"
	case strings.HasPrefix(upper, "{SSHA512}"), strings.HasPrefix(upper, "$6$"):
		return "SSHA512"
	case strings.HasPrefix(upper, "{SSHA256}"), strings.HasPrefix(upper, "$5$"):
		return "SSHA256"
	case strings.HasPrefix(upper, "{PBKDF2}"):
		return "PBKDF2"
	case strings.HasPrefix(upper, "{SSHA1}"):
		return "SSHA1"
	case strings.HasPrefix(upper, "{SMD5}"), strings.HasPrefix(upper, "$1$"):
		return "SMD5"
	case strings.HasPrefix(upper, "{CRYPT}"), len(hash) == 13:
		return "CRYPT"
	default:
		return "UNKNOWN"
	}
}

func safeAIXPasswordAlgorithm(algorithm string) bool {
	return algorithm == "SSHA512" || algorithm == "SSHA256" || algorithm == "PBKDF2"
}
