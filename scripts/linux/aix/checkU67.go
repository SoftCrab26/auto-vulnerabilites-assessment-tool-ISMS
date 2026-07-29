package main

import (
	"fmt"
	"os"
	"strings"
)

type U67Path struct {
	Path  string
	Owner string
	Mode  os.FileMode
	IsDir bool
}

type U67Input struct {
	AdmDir  *U67Path
	KeyLogs []U67Path
}

func checkU67(ctx ScanContext) CheckResult {
	const code = "U-67"
	const description = "/var/adm and key AIX logs should have secure root ownership and modes."
	mitre := MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1562"}, Mitigations: []string{"M1022"}}

	input, errs := loadU67Input()
	result := evalU67(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU67Input() (U67Input, []string) {
	var input U67Input
	var errs []string
	if item, err := collectU67Path("/var/adm"); err != nil {
		errs = append(errs, err.Error())
	} else {
		input.AdmDir = &item
	}

	for _, path := range []string{
		"/var/adm/ras/syslog.caa",
		"/var/adm/ras/errlog",
		"/var/adm/wtmp",
		"/var/adm/sulog",
	} {
		item, err := collectU67Path(path)
		if err == nil {
			input.KeyLogs = append(input.KeyLogs, item)
		} else if !os.IsNotExist(err) {
			errs = append(errs, err.Error())
		}
	}
	return input, errs
}

func collectU67Path(path string) (U67Path, error) {
	info, err := os.Stat(path)
	if err != nil {
		return U67Path{}, err
	}
	owner, err := fileOwnerName(path)
	if err != nil {
		return U67Path{}, err
	}
	return U67Path{Path: path, Owner: owner, Mode: info.Mode().Perm(), IsDir: info.IsDir()}, nil
}

func evalU67(input U67Input) CheckResult {
	if input.AdmDir == nil {
		return CheckResult{Status: StatusError, ProcessedConfig: "var_adm=missing", ErrMsg: "/var/adm metadata was not collected"}
	}

	var insecure []string
	if !rootOwner(input.AdmDir.Owner) || !secureLogDirectoryMode(input.AdmDir.Mode) {
		insecure = append(insecure, fmt.Sprintf("%s owner=%s mode=%04o", input.AdmDir.Path, input.AdmDir.Owner, input.AdmDir.Mode.Perm()))
	}
	for _, item := range input.KeyLogs {
		if !rootOwner(item.Owner) || !secureLogFileMode(item.Mode) {
			insecure = append(insecure, fmt.Sprintf("%s owner=%s mode=%04o", item.Path, item.Owner, item.Mode.Perm()))
		}
	}

	status := StatusGood
	vulnerable := ""
	if len(insecure) > 0 {
		status = StatusVulnerable
		vulnerable = "Insecure log metadata:\n" + strings.Join(insecure, "\n")
	} else if len(input.KeyLogs) == 0 {
		status = StatusInterview
		vulnerable = "No key AIX log file metadata was available; verify configured log destinations manually."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("var_adm_mode=%04o key_logs_checked=%d", input.AdmDir.Mode.Perm(), len(input.KeyLogs)),
		ProcessedConfig:  fmt.Sprintf("insecure_paths=%d", len(insecure)),
		VulnerableConfig: vulnerable,
	}
}

func rootOwner(owner string) bool {
	return owner == "root" || owner == "0"
}

func secureLogDirectoryMode(mode os.FileMode) bool {
	return mode.Perm()&0022 == 0
}

func secureLogFileMode(mode os.FileMode) bool {
	mode = mode.Perm()
	return mode&0400 != 0 && mode&^0640 == 0
}
