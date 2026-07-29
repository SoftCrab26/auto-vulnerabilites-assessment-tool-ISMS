package main

import (
	"os"
	"strings"
)

type U28Input struct {
	HostsAllow    string
	HostsDeny     string
	Firewall      string
	FirewallFound bool
}

func checkU28(ctx ScanContext) CheckResult {
	input, errs := loadU28Input(ctx)
	result := evalU28(input)
	result.Code = "U-28"
	result.Description = "Specific IP and port access restrictions should be configured."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU28Input(_ ScanContext) (U28Input, []string) {
	input := U28Input{}
	var errs []string
	for _, item := range []struct {
		path   string
		target *string
	}{
		{"/etc/hosts.allow", &input.HostsAllow},
		{"/etc/hosts.deny", &input.HostsDeny},
		{"/usr/syno/etc/firewall.conf", &input.Firewall},
		{"/etc/synofirewall.conf", &input.Firewall},
	} {
		data, err := os.ReadFile(item.path)
		if err == nil {
			*item.target += "[" + item.path + "]\n" + string(data) + "\n"
			if item.target == &input.Firewall {
				input.FirewallFound = true
			}
		} else if !os.IsNotExist(err) {
			errs = append(errs, item.path+": "+err.Error())
		}
	}
	return input, errs
}

func evalU28(input U28Input) CheckResult {
	raw := input.HostsAllow + input.HostsDeny + input.Firewall
	if dsmU28HasRule(input.HostsAllow) || dsmU28HasRule(input.HostsDeny) {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "tcp_wrappers=restricted"}
	}
	if input.FirewallFound {
		return CheckResult{
			Status:          Manual,
			RawConfig:       raw,
			ProcessedConfig: "dsm_firewall=evidence_present manual_policy_review=true",
		}
	}
	return CheckResult{
		Status:           Manual,
		RawConfig:        raw,
		ProcessedConfig:  "tcp_wrappers=not_configured dsm_firewall=evidence_unavailable",
		VulnerableConfig: "hosts.allow/hosts.deny restrictions were not found; verify DSM Firewall or an external firewall policy.",
	}
}

func dsmU28HasRule(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "[") && strings.Contains(line, ":") {
			return true
		}
	}
	return false
}
