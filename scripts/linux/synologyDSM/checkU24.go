package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type dsmU24EnvFile struct {
	File       dsmU14AuditFile
	AllowedUID uint32
}

type U24Input struct {
	Files     []dsmU24EnvFile
	LoadError string
}

func checkU24(ScanContext) CheckResult {
	input, errs := loadU24Input()
	result := evalU24(input)
	result.Code = "U-24"
	result.Description = "User environment files must be owned by root or their user and not writable by others."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1552"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU24Input() (U24Input, []string) {
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		message := fmt.Sprintf("/etc/passwd: %v", err)
		return U24Input{LoadError: message}, []string{message}
	}
	input := U24Input{}
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid64, err := strconv.ParseUint(fields[2], 10, 32)
		home := filepath.Clean(fields[5])
		if err != nil || home == "." || !filepath.IsAbs(home) {
			continue
		}
		for _, name := range []string{".profile", ".bash_profile", ".bashrc", ".cshrc", ".login"} {
			path := filepath.Join(home, name)
			file, err := dsmU14ReadAuditFile(path, false)
			if err == nil {
				input.Files = append(input.Files, dsmU24EnvFile{File: file, AllowedUID: uint32(uid64)})
			}
		}
	}
	return input, nil
}

func evalU24(input U24Input) CheckResult {
	if input.LoadError != "" {
		return dsmU14Error(input.LoadError)
	}
	var evidence, bad []string
	for _, env := range input.Files {
		line := dsmU14Metadata(env.File) + fmt.Sprintf(" expected_uid=%d", env.AllowedUID)
		evidence = append(evidence, line)
		if (env.File.UID != 0 && env.File.UID != env.AllowedUID) || env.File.Mode.Perm()&0o002 != 0 {
			bad = append(bad, line)
		}
	}
	if len(evidence) == 0 {
		evidence = append(evidence, "no user environment files found in passwd-defined homes")
	}
	status := Good
	if len(bad) > 0 {
		status = Vulnerable
	}
	return CheckResult{Status: status, RawConfig: dsmU14JoinEvidence(evidence), VulnerableConfig: dsmU14JoinEvidence(bad),
		ProcessedConfig: fmt.Sprintf("checked=%d issues=%d", len(input.Files), len(bad))}
}
