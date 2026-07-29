package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

type U63Input struct {
	Path   string
	Exists bool
	Owner  string
	Mode   os.FileMode
}

func checkU63(ctx ScanContext) CheckResult {
	input, errs := loadU63Input()
	result := evalU63(input)
	result.Code = "U-63"
	result.Description = "DSM sudoers should be root-owned with mode 0440, 0640, or stricter."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1548.003"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU63Input() (U63Input, []string) {
	const path = "/etc/sudoers"
	info, err := os.Stat(path)
	if err != nil {
		return U63Input{Path: path}, []string{err.Error()}
	}
	owner, err := dsmU63Owner(info)
	if err != nil {
		return U63Input{Path: path, Exists: true, Mode: info.Mode().Perm()}, []string{err.Error()}
	}
	return U63Input{Path: path, Exists: true, Owner: owner, Mode: info.Mode().Perm()}, nil
}

func evalU63(input U63Input) CheckResult {
	if !input.Exists || input.Owner == "" {
		return CheckResult{Status: Error, ProcessedConfig: "sudoers_metadata=missing", ErrMsg: "sudoers owner and mode evidence was not collected"}
	}
	mode := input.Mode.Perm()
	ownerOK := input.Owner == "root" || input.Owner == "0"
	modeOK := dsmU63ModeSecure(mode)
	status := Good
	vulnerable := ""
	if !ownerOK || !modeOK {
		status = Vulnerable
		vulnerable = fmt.Sprintf("%s owner_root=%t mode=%04o; require root ownership and mode 0440, 0640, or stricter.", input.Path, ownerOK, mode)
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s owner=%s mode=%04o", input.Path, input.Owner, mode),
		ProcessedConfig:  fmt.Sprintf("owner_root=%t mode_secure=%t", ownerOK, modeOK),
		VulnerableConfig: vulnerable,
	}
}

func dsmU63ModeSecure(mode os.FileMode) bool {
	mode = mode.Perm()
	return mode&0400 != 0 && mode&^0640 == 0
}

func dsmU63Owner(info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("owner metadata unavailable for %s", info.Name())
	}
	if stat.Uid == 0 {
		return "root", nil
	}
	return strconv.FormatUint(uint64(stat.Uid), 10), nil
}
