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
	const code = "U-65"
	const description = "An external NTP time source should be configured."
	mitre := MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1070"}, Mitigations: []string{"M1029"}}

	input, errs := loadU65Input()
	result := evalU65(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU65Input() (U65Input, []string) {
	file, errs := collectFirstExisting("/etc/ntp.conf")
	return U65Input{ConfigPath: file.Path, Config: file.Content}, errs
}

func evalU65(input U65Input) CheckResult {
	if strings.TrimSpace(input.Config) == "" {
		return CheckResult{
			Status:           StatusVulnerable,
			ProcessedConfig:  "external_ntp_servers=0",
			VulnerableConfig: "No readable /etc/ntp.conf data was available.",
		}
	}

	servers := externalNTPServers(input.Config)
	status := StatusGood
	vulnerable := ""
	if len(servers) == 0 {
		status = StatusVulnerable
		vulnerable = "No external NTP server was configured; a local reference clock alone is insufficient."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        fmt.Sprintf("path=%s external_ntp_servers=%d (server names omitted)", input.ConfigPath, len(servers)),
		ProcessedConfig:  fmt.Sprintf("external_ntp_servers=%d", len(servers)),
		VulnerableConfig: vulnerable,
	}
}

func externalNTPServers(config string) []string {
	var servers []string
	for _, line := range activeConfigLines(config) {
		fields := strings.Fields(line)
		if len(fields) < 2 || (strings.ToLower(fields[0]) != "server" && strings.ToLower(fields[0]) != "peer") {
			continue
		}
		host := strings.Trim(fields[1], "[]")
		if isExternalNTPHost(host) {
			servers = append(servers, host)
		}
	}
	return servers
}

func isExternalNTPHost(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	if lower == "" || lower == "localhost" || lower == "localhost.localdomain" ||
		lower == "local" || strings.HasPrefix(lower, "127.127.") {
		return false
	}
	if ip := net.ParseIP(lower); ip != nil {
		return !ip.IsLoopback() && !ip.IsUnspecified()
	}
	return true
}
