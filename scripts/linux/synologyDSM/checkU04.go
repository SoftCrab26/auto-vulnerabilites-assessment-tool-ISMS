package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

type U04FileEvidence struct {
	Path  string
	Mode  os.FileMode
	UID   uint32
	GID   uint32
	Found bool
}

type U04Input struct {
	Files []U04FileEvidence
}

func checkU04(ctx ScanContext) CheckResult {
	input, errs := loadU04Input(ctx)
	result := evalU04(input)
	result.Code = "U-04"
	result.Description = "/etc/passwd and /etc/shadow must have secure ownership and permissions."
	result.MitreAttack = MitreAttack{
		Tactic:      "Credential Access",
		Techniques:  []string{"T1003.008"},
		Mitigations: []string{"M1026"},
	}
	return resultWithErrors(result, errs)
}

func loadU04Input(_ ScanContext) (U04Input, []string) {
	var input U04Input
	var errs []string
	for _, path := range []string{"/etc/passwd", "/etc/shadow"} {
		evidence := U04FileEvidence{Path: path}
		info, err := os.Stat(path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			input.Files = append(input.Files, evidence)
			continue
		}
		evidence.Mode = info.Mode().Perm()
		evidence.Found = true
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			evidence.UID = stat.Uid
			evidence.GID = stat.Gid
		} else {
			evidence.Found = false
			errs = append(errs, path+": ownership metadata unavailable")
		}
		input.Files = append(input.Files, evidence)
	}
	return input, errs
}

func evalU04(input U04Input) CheckResult {
	if len(input.Files) != 2 || !input.Files[0].Found || !input.Files[1].Found {
		return CheckResult{
			Status:          Error,
			RawConfig:       dsmU04Evidence(input.Files),
			ProcessedConfig: "required_file_metadata=unavailable",
			ErrMsg:          "passwd and shadow metadata are required",
		}
	}
	var problems []string
	for _, file := range input.Files {
		if file.UID != 0 {
			problems = append(problems, file.Path+" owner_uid is not 0")
		}
		switch file.Path {
		case "/etc/passwd":
			if file.Mode.Perm()&0o133 != 0 {
				problems = append(problems, "/etc/passwd has write or execute permissions beyond mode 0644")
			}
		case "/etc/shadow":
			if file.Mode.Perm()&0o137 != 0 {
				problems = append(problems, "/etc/shadow has permissions beyond mode 0640")
			}
		}
	}
	status := Good
	if len(problems) > 0 {
		status = Vulnerable
	}
	return CheckResult{
		Status:           status,
		RawConfig:        dsmU04Evidence(input.Files),
		ProcessedConfig:  "file_metadata_checked=true",
		VulnerableConfig: strings.Join(problems, "\n"),
	}
}

func dsmU04Evidence(files []U04FileEvidence) string {
	var lines []string
	for _, file := range files {
		if !file.Found {
			lines = append(lines, file.Path+" unavailable")
			continue
		}
		lines = append(lines, fmt.Sprintf("%s owner_uid=%d group_gid=%d mode=%04o",
			file.Path, file.UID, file.GID, file.Mode.Perm()))
	}
	return strings.Join(lines, "\n")
}
