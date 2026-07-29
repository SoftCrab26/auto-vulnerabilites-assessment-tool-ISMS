package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type dsmU31Home struct {
	User   string
	Path   string
	Exists bool
	Mode   os.FileMode
	UID    uint32
}

type U31Input struct {
	Passwd string
	Homes  []dsmU31Home
}

func checkU31(ctx ScanContext) CheckResult {
	input, errs := loadU31Input(ctx)
	result := evalU31(input)
	result.Code = "U-31"
	result.Description = "Home directories should belong to their users and not be writable by group or others."
	return resultWithErrors(result, errs)
}

func loadU31Input(_ ScanContext) (U31Input, []string) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return U31Input{}, []string{"/etc/passwd: " + err.Error()}
	}
	input := U31Input{Passwd: string(data)}
	var errs []string
	for _, account := range dsmU31Accounts(input.Passwd) {
		info, statErr := os.Stat(account.Path)
		if os.IsNotExist(statErr) {
			input.Homes = append(input.Homes, account)
			continue
		}
		if statErr != nil {
			errs = append(errs, account.Path+": "+statErr.Error())
			continue
		}
		account.Exists = info.IsDir()
		account.Mode = info.Mode().Perm()
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			account.UID = stat.Uid
		} else {
			errs = append(errs, account.Path+": owner metadata unavailable")
		}
		input.Homes = append(input.Homes, account)
	}
	return input, errs
}

func evalU31(input U31Input) CheckResult {
	if strings.TrimSpace(input.Passwd) == "" {
		return CheckResult{Status: Error, ProcessedConfig: "passwd=evidence_unavailable", ErrMsg: "/etc/passwd evidence is required"}
	}
	uidByUser := dsmU31UIDs(input.Passwd)
	var raw, issues []string
	for _, home := range input.Homes {
		if !home.Exists {
			continue
		}
		line := fmt.Sprintf("%s user=%s uid=%d mode=%04o", home.Path, home.User, home.UID, home.Mode)
		raw = append(raw, line)
		if home.UID != uidByUser[home.User] || home.Mode.Perm()&0022 != 0 {
			issues = append(issues, line)
		}
	}
	if len(issues) > 0 {
		return CheckResult{Status: Vulnerable, RawConfig: strings.Join(raw, "\n"), ProcessedConfig: fmt.Sprintf("homes_checked=%d", len(raw)), VulnerableConfig: strings.Join(issues, "\n")}
	}
	return CheckResult{Status: Good, RawConfig: strings.Join(raw, "\n"), ProcessedConfig: fmt.Sprintf("homes_checked=%d", len(raw))}
}

func dsmU31Accounts(passwd string) []dsmU31Home {
	var homes []dsmU31Home
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[5] != "" && fields[5] != "/" && fields[5] != "/nonexistent" {
			homes = append(homes, dsmU31Home{User: fields[0], Path: fields[5]})
		}
	}
	return homes
}

func dsmU31UIDs(passwd string) map[string]uint32 {
	result := make(map[string]uint32)
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err == nil {
			result[fields[0]] = uint32(uid)
		}
	}
	return result
}
