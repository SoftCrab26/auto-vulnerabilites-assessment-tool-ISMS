package main

import (
	"os"
	"strconv"
	"strings"
)

func checkU04() CheckResult {
	paths := []string{"/etc/passwd", "/etc/shadow"}
	var errs []string
	var processed []string

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		perm := info.Mode().Perm()
		processed = append(processed, path+" perm="+strconv.FormatUint(uint64(perm), 8))
	}

	status := StatusGood

	passwd, err1 := os.Stat("/etc/passwd")
	shadow, err2 := os.Stat("/etc/shadow")

	if err1 != nil || err2 != nil {
		status = StatusError
	}

	if err1 == nil {
		perm := passwd.Mode().Perm()
		if perm&022 != 0 {
			status = StatusVulnerable
		}
	}

	if err2 == nil {
		perm := shadow.Mode().Perm()
		if perm&0007 != 0 {
			status = StatusVulnerable
		}
	}

	return CheckResult{
		Code:            "U-04",
		Status:          status,
		Description:     "Password file permissions must prevent unauthorized access.",
		ProcessedConfig: strings.Join(processed, " | "),
		ErrMsg:          strings.Join(errs, "; "),
	}
}
