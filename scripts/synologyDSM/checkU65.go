package main

import (
	"fmt"
	"net"
	"strings"
)

type U65Input struct {
	ConfigPath string
	Config     string
}

func checkU65(ctx ScanContext) CheckResult {
	input, errs := loadU65Input()
	result := evalU65(input)
	result.Code = "U-65"
	result.Description = "DSM should synchronize time with an external NTP server."
	result.MitreAttack = MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1070"}, Mitigations: []string{"M1029"}}
	return resultWithErrors(result, errs)
}

func loadU65Input() (U65Input, []string) {
	file, errs := collectFirstExisting(
		"/etc/ntp.conf",
		"/etc.defaults/ntp.conf",
		"/var/packages/TimeBackup/target/etc/ntp.conf",
	)
	return U65Input{ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU65(input U65Input) CheckResult {
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{Status: Error, ProcessedConfig: "ntp_config=missing", ErrMsg: "no readable DSM NTP configuration was collected"}
	}
	servers := dsmU65Servers(input.Config)
	external := 0
	for _, server := range servers {
		if dsmU65External(server) {
			external++
		}
	}
	status := Good
	vulnerable := ""
	if external == 0 {
		status = Vulnerable
		vulnerable = "No external NTP server or pool is configured."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s configured_servers=[%s]", input.ConfigPath, strings.Join(servers, ", ")),
		ProcessedConfig:  fmt.Sprintf("server_count=%d external_server_count=%d", len(servers), external),
		VulnerableConfig: vulnerable,
	}
}

func dsmU65Servers(config string) []string {
	var servers []string
	for _, line := range dsmU59ActiveLines(config) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && (strings.EqualFold(fields[0], "server") || strings.EqualFold(fields[0], "pool")) {
			servers = append(servers, strings.Trim(fields[1], "[]"))
		}
	}
	return servers
}

func dsmU65External(server string) bool {
	host := strings.ToLower(strings.TrimSpace(server))
	switch host {
	case "", "localhost", "localhost.localdomain", "0.0.0.0", "::", "::1":
		return false
	}
	if strings.HasPrefix(host, "127.127.") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	return true
}
