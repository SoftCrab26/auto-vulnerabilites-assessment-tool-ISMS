package main

import (
	"os"
	"strings"
)

type U35Input struct {
	FTPActive   bool
	Runtime     string
	Config      string
	ConfigFound bool
}

func checkU35(ctx ScanContext) CheckResult {
	input, errs := loadU35Input(ctx)
	result := evalU35(input)
	result.Code = "U-35"
	result.Description = "Anonymous FTP access should be disabled."
	return resultWithErrors(result, errs)
}

func loadU35Input(ctx ScanContext) (U35Input, []string) {
	input := U35Input{Runtime: "[processes]\n" + ctx.Runtime.ProcessList + "\n[ports]\n" + ctx.Runtime.PortList + "\n[packages]\n" + ctx.Runtime.PackageList}
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "ftp") {
			input.FTPActive = input.FTPActive || service.IsActive
		}
	}
	input.FTPActive = input.FTPActive || listeningPorts(ctx.Runtime.PortList)[21] ||
		containsAnyWord(ctx.Runtime.ProcessList, []string{"ftpd", "vsftpd", "proftpd"})
	var errs []string
	for _, path := range []string{
		"/etc/vsftpd.conf",
		"/etc/vsftpd/vsftpd.conf",
		"/etc.defaults/vsftpd.conf",
		"/usr/syno/etc/packages/FTP/vsftpd.conf",
		"/usr/syno/etc/packages/FTP/ftp.conf",
	} {
		data, err := os.ReadFile(path)
		if err == nil {
			input.ConfigFound = true
			input.Config += "[" + path + "]\n" + string(data) + "\n"
		} else if !os.IsNotExist(err) {
			errs = append(errs, path+": "+err.Error())
		}
	}
	return input, errs
}

func evalU35(input U35Input) CheckResult {
	raw := input.Runtime + "\n" + input.Config
	if !input.FTPActive {
		return CheckResult{Status: NotApplicable, RawConfig: raw, ProcessedConfig: "ftp=inactive"}
	}
	if !input.ConfigFound {
		return CheckResult{Status: Manual, RawConfig: raw, ProcessedConfig: "ftp=active anonymous=evidence_unavailable"}
	}
	value, found := dsmU35AnonymousValue(input.Config)
	if !found {
		return CheckResult{Status: Manual, RawConfig: raw, ProcessedConfig: "ftp=active anonymous=evidence_unavailable"}
	}
	if value == "yes" || value == "true" || value == "1" {
		return CheckResult{Status: Vulnerable, RawConfig: raw, ProcessedConfig: "ftp=active anonymous=enabled", VulnerableConfig: "anonymous_enable=" + value}
	}
	return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "ftp=active anonymous=disabled"}
}

func dsmU35AnonymousValue(raw string) (string, bool) {
	var value string
	found := false
	for _, line := range strings.Split(raw, "\n") {
		clean := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		parts := strings.SplitN(clean, "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "anonymous_enable") {
			value = strings.ToLower(strings.Trim(strings.TrimSpace(parts[1]), `"'`))
			found = true
		}
	}
	return value, found
}
