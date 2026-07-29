package main

import (
	"fmt"
	"os"
	"syscall"
)

type U29Input struct {
	Exists bool
	Mode   os.FileMode
	UID    uint32
	Path   string
}

func checkU29(ctx ScanContext) CheckResult {
	input, errs := loadU29Input(ctx)
	result := evalU29(input)
	result.Code = "U-29"
	result.Description = "/etc/hosts.lpd should be absent or owned by root with mode 0600 or stricter."
	return resultWithErrors(result, errs)
}

func loadU29Input(_ ScanContext) (U29Input, []string) {
	input := U29Input{Path: "/etc/hosts.lpd"}
	info, err := os.Stat(input.Path)
	if os.IsNotExist(err) {
		return input, nil
	}
	if err != nil {
		return input, []string{input.Path + ": " + err.Error()}
	}
	input.Exists = true
	input.Mode = info.Mode().Perm()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		input.UID = stat.Uid
	} else {
		return input, []string{input.Path + ": owner metadata unavailable"}
	}
	return input, nil
}

func evalU29(input U29Input) CheckResult {
	if !input.Exists {
		return CheckResult{Status: NotApplicable, RawConfig: input.Path + ": absent", ProcessedConfig: "hosts_lpd=absent"}
	}
	raw := fmt.Sprintf("%s: uid=%d mode=%04o", input.Path, input.UID, input.Mode.Perm())
	if input.UID != 0 || input.Mode.Perm()&0077 != 0 {
		return CheckResult{Status: Vulnerable, RawConfig: raw, ProcessedConfig: "hosts_lpd=unsafe", VulnerableConfig: raw}
	}
	return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "hosts_lpd=safe"}
}
