package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type U17Input struct {
	Files     []auditFile
	Missing   []string
	Errors    []string
	Truncated bool
}

func checkU17(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU17(loadU17Input())
	result.Code = "U-17"
	result.Description = "AIX startup files must be owned by root and not writable by group or other users."
	result.MitreAttack = MitreAttack{Tactic: "Persistence", Techniques: []string{"T1037"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU17Input() U17Input {
	input := U17Input{}
	for _, path := range []string{"/etc/inittab", "/etc/rc.tcpip"} {
		file := loadAuditFile(path, false)
		if !file.Exists {
			input.Missing = append(input.Missing, path)
		} else {
			input.Files = append(input.Files, file)
		}
	}
	const limit = 4096
	count := 0
	err := filepath.WalkDir("/etc/rc.d", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if !os.IsNotExist(walkErr) {
				input.Errors = append(input.Errors, walkErr.Error())
			}
			return nil
		}
		count++
		if count > limit {
			input.Truncated = true
			return filepath.SkipAll
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil
		}
		input.Files = append(input.Files, loadAuditFile(path, false))
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		input.Errors = append(input.Errors, err.Error())
	}
	return input
}

func evalU17(input U17Input) CheckResult {
	var bad []auditFile
	for _, file := range input.Files {
		if !ownerAllowed(file.Owner, "root") || file.Mode.Perm()&0022 != 0 {
			bad = append(bad, file)
		}
	}
	status := StatusGood
	vulnerable := ""
	errMsg := strings.Join(input.Errors, "\n")
	if len(input.Missing) > 0 {
		status = StatusError
		errMsg = strings.TrimSpace(errMsg + "\nrequired startup files missing: " + strings.Join(input.Missing, ", "))
	} else if len(bad) > 0 {
		status = StatusVulnerable
		vulnerable = inventoryRaw(bad)
	}
	return CheckResult{
		Status: status, RawConfig: inventoryRaw(input.Files),
		ProcessedConfig:  "startup_files=" + strconv.Itoa(len(input.Files)) + " truncated=" + strconv.FormatBool(input.Truncated),
		VulnerableConfig: vulnerable, ErrMsg: errMsg,
	}
}
