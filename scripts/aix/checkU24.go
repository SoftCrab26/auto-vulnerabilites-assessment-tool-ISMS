package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type U24EnvFile struct {
	File         auditFile
	AllowedOwner string
	Required     bool
}

type U24Input struct {
	Files  []U24EnvFile
	Errors []string
}

func checkU24(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU24(loadU24Input())
	result.Code = "U-24"
	result.Description = "System and user environment files must have an appropriate owner and no group/other write permission."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1552"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU24Input() U24Input {
	input := U24Input{Files: []U24EnvFile{
		{File: loadAuditFile("/etc/environment", false), AllowedOwner: "root", Required: true},
		{File: loadAuditFile("/etc/profile", false), AllowedOwner: "root", Required: true},
		{File: loadAuditFile("/root/.profile", false), AllowedOwner: "root"},
	}}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		input.Errors = append(input.Errors, err.Error())
		return input
	}
	seen := map[string]bool{"/root/.profile": true}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 6 || fields[0] == "" || fields[5] == "" {
			continue
		}
		for _, name := range []string{".profile", ".kshrc", ".login", ".cshrc"} {
			path := filepath.Join(fields[5], name)
			if seen[path] {
				continue
			}
			seen[path] = true
			input.Files = append(input.Files, U24EnvFile{File: loadAuditFile(path, false), AllowedOwner: fields[0]})
		}
	}
	return input
}

func evalU24(input U24Input) CheckResult {
	var bad []auditFile
	var audited []auditFile
	var missing []string
	existing := 0
	for _, candidate := range input.Files {
		if !candidate.File.Exists {
			if candidate.Required {
				missing = append(missing, candidate.File.Path)
			}
			continue
		}
		existing++
		audited = append(audited, candidate.File)
		if !ownerAllowed(candidate.File.Owner, "root", candidate.AllowedOwner) || candidate.File.Mode.Perm()&0022 != 0 {
			bad = append(bad, candidate.File)
		}
	}
	status := StatusGood
	vulnerable := ""
	errMsg := strings.Join(input.Errors, "\n")
	if len(missing) > 0 {
		status = StatusError
		errMsg = strings.TrimSpace(errMsg + "\nrequired environment files missing: " + strings.Join(missing, ", "))
	} else if len(bad) > 0 {
		status = StatusVulnerable
		vulnerable = inventoryRaw(bad)
	}
	return CheckResult{
		Status: status, RawConfig: inventoryRaw(audited),
		ProcessedConfig:  "environment_files=" + strconv.Itoa(existing) + " issues=" + strconv.Itoa(len(bad)),
		VulnerableConfig: vulnerable, ErrMsg: errMsg,
	}
}
