package main

import (
	"os"
	"strconv"
	"strings"
)

type U30Input struct {
	LoginDefs string
	Profiles  string
}

func checkU30(ctx ScanContext) CheckResult {
	input, errs := loadU30Input(ctx)
	result := evalU30(input)
	result.Code = "U-30"
	result.Description = "The default UMASK should be 022 or more restrictive."
	return resultWithErrors(result, errs)
}

func loadU30Input(_ ScanContext) (U30Input, []string) {
	input := U30Input{}
	var errs []string
	for _, path := range []string{"/etc/login.defs", "/etc/profile", "/etc.defaults/profile"} {
		data, err := os.ReadFile(path)
		if err == nil {
			evidence := "[" + path + "]\n" + string(data) + "\n"
			if path == "/etc/login.defs" {
				input.LoginDefs = evidence
			} else {
				input.Profiles += evidence
			}
		} else if !os.IsNotExist(err) {
			errs = append(errs, path+": "+err.Error())
		}
	}
	return input, errs
}

func evalU30(input U30Input) CheckResult {
	values := append(dsmU30Values(input.LoginDefs, true), dsmU30Values(input.Profiles, false)...)
	raw := input.LoginDefs + input.Profiles
	if len(values) == 0 {
		return CheckResult{Status: Vulnerable, RawConfig: raw, ProcessedConfig: "umask=missing", VulnerableConfig: "No default UMASK setting was found."}
	}
	for _, value := range values {
		mask, err := strconv.ParseUint(strings.TrimPrefix(value, "0"), 8, 16)
		if err != nil || mask&0022 != 0022 {
			return CheckResult{Status: Vulnerable, RawConfig: raw, ProcessedConfig: "umask=" + strings.Join(values, ","), VulnerableConfig: "Permissive or invalid UMASK: " + value}
		}
	}
	return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "umask=" + strings.Join(values, ",")}
}

func dsmU30Values(raw string, loginDefs bool) []string {
	var values []string
	for _, source := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(strings.SplitN(source, "#", 2)[0])
		if !loginDefs {
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "umask=") {
				values = append(values, strings.Trim(strings.TrimSpace(line[len("umask="):]), `"'`))
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "umask" {
			values = append(values, strings.Trim(fields[1], `"'`))
		}
	}
	return values
}
