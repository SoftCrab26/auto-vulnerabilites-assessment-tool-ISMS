package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type U27Input struct {
	Files     []dsmU14AuditFile
	LoadError string
}

func checkU27(ScanContext) CheckResult {
	input, errs := loadU27Input()
	result := evalU27(input)
	result.Code = "U-27"
	result.Description = "hosts.equiv and user .rhosts trust files must be absent or securely configured."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU27Input() (U27Input, []string) {
	var input U27Input
	if file, err := dsmU14ReadAuditFile("/etc/hosts.equiv", true); err == nil {
		input.Files = append(input.Files, file)
	} else if !os.IsNotExist(err) {
		return input, []string{err.Error()}
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		message := fmt.Sprintf("/etc/passwd: %v", err)
		input.LoadError = message
		return input, []string{message}
	}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		if _, err := strconv.ParseUint(fields[2], 10, 32); err != nil {
			continue
		}
		home := filepath.Clean(fields[5])
		if !filepath.IsAbs(home) {
			continue
		}
		if file, err := dsmU14ReadAuditFile(filepath.Join(home, ".rhosts"), true); err == nil {
			input.Files = append(input.Files, file)
		}
	}
	return input, nil
}

func evalU27(input U27Input) CheckResult {
	if input.LoadError != "" {
		return dsmU14Error(input.LoadError)
	}
	if len(input.Files) == 0 {
		return CheckResult{Status: Good, RawConfig: "hosts.equiv and passwd-home .rhosts files absent", ProcessedConfig: "trust_files=0"}
	}
	var evidence, bad []string
	for _, file := range input.Files {
		line := dsmU14Metadata(file)
		evidence = append(evidence, line)
		if file.UID != 0 || file.Mode.Perm()&^os.FileMode(0o600) != 0 {
			bad = append(bad, line+" insecure metadata")
		}
		for _, rawLine := range strings.Split(file.Content, "\n") {
			entry := strings.TrimSpace(stripUnquotedComment(rawLine))
			if entry == "" {
				continue
			}
			safe := file.Path + ": " + dsmU14Sanitize(entry)
			evidence = append(evidence, safe)
			for _, field := range strings.Fields(entry) {
				if field == "+" || strings.HasPrefix(field, "+@") {
					bad = append(bad, safe+" wildcard trust")
					break
				}
			}
		}
	}
	status := Good
	if len(bad) > 0 {
		status = Vulnerable
	}
	return CheckResult{Status: status, RawConfig: dsmU14JoinEvidence(evidence), VulnerableConfig: dsmU14JoinEvidence(bad),
		ProcessedConfig: fmt.Sprintf("trust_files=%d issues=%d", len(input.Files), len(bad))}
}
