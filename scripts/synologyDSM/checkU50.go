package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type DSMU50Input struct {
	DNSActive  bool
	ConfigPath string
	NamedConf  string
	Found      bool
}

func checkU50(ctx ScanContext) CheckResult {
	input, errs := loadU50Input(ctx)
	result := evalU50(input)
	result.Code = "U-50"
	result.Description = "DNS Zone Transfer를 허가된 호스트에만 허용해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU50Input(ctx ScanContext) (DSMU50Input, []string) {
	if !dsmU50DNSActive(ctx) {
		return DSMU50Input{}, nil
	}
	paths := []string{
		"/var/packages/DNSServer/target/etc/named.conf",
		"/var/packages/DNSServer/etc/named.conf",
		"/usr/syno/etc/named.conf",
		"/etc/named.conf",
		"/etc.defaults/named.conf",
	}
	for _, path := range paths {
		content, ok, err := dsmU50ReadBounded(path)
		if err != nil {
			return DSMU50Input{DNSActive: true}, []string{err.Error()}
		}
		if ok {
			return DSMU50Input{DNSActive: true, ConfigPath: path, NamedConf: content, Found: true}, nil
		}
	}
	return DSMU50Input{DNSActive: true}, []string{"활성 DNS 서비스의 named.conf를 찾을 수 없습니다"}
}

func evalU50(input DSMU50Input) CheckResult {
	if !input.DNSActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "dns_service=inactive"}
	}
	raw := dsmU50Raw(input)
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: raw, ProcessedConfig: "zone_transfer=unknown", ErrMsg: "활성 DNS 서비스 설정을 확인할 수 없습니다"}
	}
	effective := dsmU50EffectiveConfig(input.NamedConf)
	values := dsmU50AllowTransferValues(effective)
	restricted := len(values) > 0
	for _, value := range values {
		if dsmU50ContainsToken(value, "any") {
			restricted = false
			break
		}
	}
	if restricted {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "zone_transfer=restricted"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "zone_transfer=unrestricted",
		VulnerableConfig: "allow-transfer가 없거나 any로 설정되어 DNS Zone Transfer 대상이 제한되지 않습니다.",
	}
}

func dsmU50Raw(input DSMU50Input) string {
	if input.ConfigPath == "" {
		return input.NamedConf
	}
	return input.ConfigPath + "\n" + input.NamedConf
}

func dsmU50EffectiveConfig(raw string) string {
	blockComments := regexp.MustCompile(`(?s)/\*.*?\*/`)
	raw = blockComments.ReplaceAllString(raw, "")
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, " ")
}

func dsmU50AllowTransferValues(raw string) []string {
	pattern := regexp.MustCompile(`(?i)\ballow-transfer\s*\{([^}]*)\}`)
	matches := pattern.FindAllStringSubmatch(raw, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		values = append(values, strings.ToLower(match[1]))
	}
	return values
}

func dsmU50ContainsToken(raw, target string) bool {
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) {
		if strings.EqualFold(token, target) {
			return true
		}
	}
	return false
}

func dsmU50DNSActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"named", "dnsmasq"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"DNSServer", "DNS Server"}) ||
		ports[53]
}

func dsmU50ReadBounded(path string) (string, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 512*1024+1))
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > 512*1024 {
		return "", false, fmt.Errorf("%s: file exceeds 512 KiB", path)
	}
	return string(data), true, nil
}
