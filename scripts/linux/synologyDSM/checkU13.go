package main

import (
	"sort"
	"strings"
)

type U13Input struct {
	Shadow string
	Source string
}

func checkU13(ctx ScanContext) CheckResult {
	input, errs := loadU13Input(ctx)
	result := evalU13(input)
	result.Code = "U-13"
	result.Description = "Password hashes must use SHA-2 or a stronger supported algorithm."
	result.MitreAttack = MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1110"},
		Mitigations: []string{"M1027"},
	}
	return resultWithErrors(result, errs)
}

func loadU13Input(_ ScanContext) (U13Input, []string) {
	file, errs := collectFirstExisting(preferredDSMPaths("shadow")...)
	return U13Input{Shadow: file.Content, Source: file.Path}, errs
}

func evalU13(input U13Input) CheckResult {
	if input.Source == "" || strings.TrimSpace(input.Shadow) == "" {
		return CheckResult{Status: Error, ErrMsg: "shadow evidence is unavailable"}
	}
	var summaries, weak []string
	validRows := 0
	for _, line := range strings.Split(input.Shadow, "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		validRows++
		algorithm, lockState := dsmU13Classify(fields[1])
		summary := fields[0] + "=" + algorithm + " lock=" + lockState
		summaries = append(summaries, summary)
		if lockState == "unlocked" && !dsmU13Strong(algorithm) {
			weak = append(weak, fields[0]+"="+algorithm)
		}
	}
	if validRows == 0 {
		return CheckResult{Status: Error, ErrMsg: "shadow evidence contains no parseable account rows"}
	}
	sort.Strings(summaries)
	sort.Strings(weak)
	status := Good
	if len(weak) > 0 {
		status = Vulnerable
	}
	sanitized := "# FILE: " + input.Source + "\n" + strings.Join(summaries, "\n")
	return CheckResult{
		Status:           status,
		RawConfig:        sanitized,
		ProcessedConfig:  "accounts=" + strings.Join(summaries, ";"),
		VulnerableConfig: strings.Join(weak, "\n"),
	}
}

func dsmU13Classify(value string) (string, string) {
	value = strings.TrimSpace(value)
	lockState := "unlocked"
	if strings.HasPrefix(value, "!") || strings.HasPrefix(value, "*") {
		lockState = "locked"
		value = strings.TrimLeft(value, "!*")
	}
	switch {
	case value == "":
		if lockState == "locked" {
			return "none", lockState
		}
		return "empty", lockState
	case strings.HasPrefix(value, "$6$"):
		return "SHA512", lockState
	case strings.HasPrefix(value, "$5$"):
		return "SHA256", lockState
	case strings.HasPrefix(value, "$y$"):
		return "YESCRYPT", lockState
	case strings.HasPrefix(value, "$7$"):
		return "SCRYPT", lockState
	case strings.HasPrefix(value, "$2a$"), strings.HasPrefix(value, "$2b$"), strings.HasPrefix(value, "$2y$"):
		return "BLOWFISH", lockState
	case strings.HasPrefix(value, "$1$"):
		return "MD5", lockState
	case value == "x":
		return "delegated", lockState
	case strings.HasPrefix(value, "$"):
		return "UNKNOWN", lockState
	case len(value) == 13:
		return "DES", lockState
	default:
		return "UNKNOWN", lockState
	}
}

func dsmU13Strong(algorithm string) bool {
	switch algorithm {
	case "SHA512", "SHA256", "YESCRYPT", "SCRYPT", "BLOWFISH":
		return true
	default:
		return false
	}
}
