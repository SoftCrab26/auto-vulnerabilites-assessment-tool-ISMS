package main

import (
	"fmt"
	"os"
	"strings"
)

type U04File struct {
	Path   string
	Mode   os.FileMode
	Owner  string
	Exists bool
}

type U04Input struct {
	Files []U04File
}

func checkU04(ctx ScanContext) CheckResult {
	input, errs := loadU04Input()
	result := evalU04(input)
	result.Code = "U-04"
	result.Description = "AIX password files must be root-owned and restrict modification or disclosure."
	result.MitreAttack = MitreAttack{Tactic: "Credential Access", Techniques: []string{"T1003"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU04Input() (U04Input, []string) {
	var input U04Input
	var errs []string
	for _, path := range []string{"/etc/passwd", "/etc/security/passwd"} {
		entry := U04File{Path: path}
		info, err := os.Stat(path)
		if err != nil {
			errs = append(errs, err.Error())
			input.Files = append(input.Files, entry)
			continue
		}
		entry.Exists, entry.Mode = true, info.Mode().Perm()
		entry.Owner, err = fileOwnerName(path)
		if err != nil {
			errs = append(errs, err.Error())
		}
		input.Files = append(input.Files, entry)
	}
	return input, errs
}

func evalU04(input U04Input) CheckResult {
	if len(input.Files) != 2 {
		return CheckResult{Status: StatusError, VulnerableConfig: "required file metadata is missing"}
	}
	status := StatusGood
	var processed, problems []string
	for _, file := range input.Files {
		processed = append(processed, fmt.Sprintf("%s owner=%s mode=%04o", file.Path, file.Owner, file.Mode.Perm()))
		if !file.Exists || file.Owner == "" {
			status = StatusError
			problems = append(problems, file.Path+" metadata unavailable")
			continue
		}
		if file.Owner != "root" && file.Owner != "0" {
			status = StatusVulnerable
			problems = append(problems, file.Path+" must be owned by root")
		}
		if file.Path == "/etc/passwd" && file.Mode.Perm()&0022 != 0 {
			status = StatusVulnerable
			problems = append(problems, "/etc/passwd must not be group/other writable")
		}
		if file.Path == "/etc/security/passwd" && file.Mode.Perm()&0077 != 0 {
			status = StatusVulnerable
			problems = append(problems, "/etc/security/passwd must not grant group/other permissions")
		}
	}
	return CheckResult{Status: status, ProcessedConfig: strings.Join(processed, " | "), VulnerableConfig: strings.Join(problems, "\n")}
}
