package main

import (
	"fmt"
	"os"
)

type U63Input struct {
	Path   string
	Exists bool
	Owner  string
	Mode   os.FileMode
}

func checkU63(ctx ScanContext) CheckResult {
	const code = "U-63"
	const description = "/etc/sudoers should be root-owned with mode 0440, 0640, or stricter."
	mitre := MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1548.003"}, Mitigations: []string{"M1026"}}

	input, errs := loadU63Input()
	result := evalU63(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU63Input() (U63Input, []string) {
	const path = "/etc/sudoers"
	info, err := os.Stat(path)
	if err != nil {
		return U63Input{Path: path}, []string{err.Error()}
	}
	owner, err := fileOwnerName(path)
	if err != nil {
		return U63Input{Path: path, Exists: true, Mode: info.Mode().Perm()}, []string{err.Error()}
	}
	return U63Input{Path: path, Exists: true, Owner: owner, Mode: info.Mode().Perm()}, nil
}

func evalU63(input U63Input) CheckResult {
	if !input.Exists {
		return CheckResult{Status: StatusError, ProcessedConfig: "sudoers=missing", ErrMsg: "sudoers metadata was not collected"}
	}

	mode := input.Mode.Perm()
	ownerOK := input.Owner == "root" || input.Owner == "0"
	modeOK := sudoersModeSecure(mode)
	status := StatusGood
	vulnerable := ""
	if !ownerOK || !modeOK {
		status = StatusVulnerable
		vulnerable = fmt.Sprintf("%s owner_ok=%t mode=%04o; require root ownership and 0440/0640 or stricter.", input.Path, ownerOK, mode)
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s owner=%s mode=%04o", input.Path, input.Owner, mode),
		ProcessedConfig:  fmt.Sprintf("owner_root=%t mode_secure=%t", ownerOK, modeOK),
		VulnerableConfig: vulnerable,
	}
}

func sudoersModeSecure(mode os.FileMode) bool {
	mode = mode.Perm()
	return mode&0400 != 0 && mode&^0640 == 0
}
