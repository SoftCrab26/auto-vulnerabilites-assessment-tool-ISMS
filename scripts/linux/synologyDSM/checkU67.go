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
	LogDir  *U67Path
	KeyLogs []U67Path
}

func checkU67(ctx ScanContext) CheckResult {
	input, errs := loadU67Input()
	result := evalU67(input)
	result.Code = "U-67"
	result.Description = "DSM key log directories and files should have secure ownership and modes."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1562"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU67Input() (U67Input, []string) {
	var input U67Input
	var errs []string
	logDir, err := dsmU67PathMetadata("/var/log")
	if err != nil {
		errs = append(errs, err.Error())
	} else {
		input.LogDir = &logDir
	}
	for _, path := range []string{
		"/var/log/messages",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/synolog/synologd.log",
		"/var/log/synoservice.log",
	} {
		metadata, metadataErr := dsmU67PathMetadata(path)
		if os.IsNotExist(metadataErr) {
			continue
		}
		if metadataErr != nil {
			errs = append(errs, metadataErr.Error())
			continue
		}
		input.KeyLogs = append(input.KeyLogs, metadata)
	}
	return input, errs
}

func evalU67(input U67Input) CheckResult {
	if input.LogDir == nil {
		return CheckResult{Status: Error, ProcessedConfig: "log_directory_metadata=missing", ErrMsg: "/var/log owner and mode evidence was not collected"}
	}
	if len(input.KeyLogs) == 0 {
		return CheckResult{
			Status:          Error,
			RawConfig:       dsmU67Evidence(*input.LogDir),
			ProcessedConfig: "key_log_metadata=missing",
			ErrMsg:          "no DSM key log file owner and mode evidence was collected",
		}
	}

	paths := append([]U67Path{*input.LogDir}, input.KeyLogs...)
	var evidence, insecure []string
	for _, path := range paths {
		evidence = append(evidence, dsmU67Evidence(path))
		if !dsmU67Secure(path) {
			insecure = append(insecure, dsmU67Evidence(path))
		}
	}
	status := Good
	vulnerable := ""
	if len(insecure) > 0 {
		status = Vulnerable
		vulnerable = "Insecure DSM log metadata:\n" + strings.Join(insecure, "\n")
	}
	return CheckResult{
		Status:           status,
		RawConfig:        strings.Join(evidence, "\n"),
		ProcessedConfig:  fmt.Sprintf("checked_paths=%d insecure_paths=%d", len(paths), len(insecure)),
		VulnerableConfig: vulnerable,
	}
}

func dsmU67PathMetadata(path string) (U67Path, error) {
	info, err := os.Stat(path)
	if err != nil {
		return U67Path{}, err
	}
	owner, err := dsmU63Owner(info)
	if err != nil {
		return U67Path{}, fmt.Errorf("%s: %w", path, err)
	}
	return U67Path{Path: path, Owner: owner, Mode: info.Mode().Perm(), IsDir: info.IsDir()}, nil
}

func dsmU67Secure(path U67Path) bool {
	if path.Owner != "root" && path.Owner != "0" {
		return false
	}
	mode := path.Mode.Perm()
	if path.IsDir {
		return mode&0022 == 0
	}
	return mode&0022 == 0 && mode&0111 == 0 && mode&0400 != 0
}

func dsmU67Evidence(path U67Path) string {
	return fmt.Sprintf("path=%s owner=%s mode=%04o type=%s", path.Path, path.Owner, path.Mode.Perm(), dsmU67Type(path.IsDir))
}

func dsmU67Type(directory bool) string {
	if directory {
		return "directory"
	}
	return "file"
}
