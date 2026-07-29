package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type U26Input struct {
	RegularFiles []auditFile
	Errors       []string
	Truncated    bool
	DevExists    bool
}

func checkU26(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU26(loadU26Input())
	result.Code = "U-26"
	result.Description = "Regular files must not be stored in /dev."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1036"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU26Input() U26Input {
	input := U26Input{}
	if info, err := os.Stat("/dev"); err == nil && info.IsDir() {
		input.DevExists = true
	} else {
		if err != nil {
			input.Errors = append(input.Errors, err.Error())
		}
		return input
	}
	count := 0
	err := filepath.WalkDir("/dev", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			input.Errors = append(input.Errors, walkErr.Error())
			return nil
		}
		count++
		if count > 10000 {
			input.Truncated = true
			return filepath.SkipAll
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			input.Errors = append(input.Errors, err.Error())
			return nil
		}
		if info.Mode().IsRegular() {
			input.RegularFiles = append(input.RegularFiles, loadAuditFile(path, false))
		}
		return nil
	})
	if err != nil {
		input.Errors = append(input.Errors, err.Error())
	}
	return input
}

func evalU26(input U26Input) CheckResult {
	if !input.DevExists {
		return CheckResult{Status: StatusError, ErrMsg: strings.Join(input.Errors, "\n"), ProcessedConfig: "dev_exists=false"}
	}
	status := StatusGood
	vulnerable := ""
	if len(input.RegularFiles) > 0 {
		status = StatusVulnerable
		vulnerable = inventoryRaw(input.RegularFiles)
	}
	if input.Truncated && status == StatusGood {
		status = StatusInterview
	}
	return CheckResult{
		Status: status, RawConfig: inventoryRaw(input.RegularFiles),
		ProcessedConfig:  "regular_files=" + strconv.Itoa(len(input.RegularFiles)) + " truncated=" + strconv.FormatBool(input.Truncated),
		VulnerableConfig: vulnerable, ErrMsg: strings.Join(input.Errors, "\n"),
	}
}
