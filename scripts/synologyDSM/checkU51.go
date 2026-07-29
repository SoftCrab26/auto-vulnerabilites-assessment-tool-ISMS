package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type DSMU51Input struct {
	DNSActive  bool
	ConfigPath string
	NamedConf  string
	Found      bool
}

func checkU51(ctx ScanContext) CheckResult {
	input, errs := loadU51Input(ctx)
	result := evalU51(input)
	result.Code = "U-51"
	result.Description = "DNS 동적 업데이트를 비활성화하거나 허가된 대상에만 허용해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Impact", Techniques: []string{"T1565"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU51Input(ctx ScanContext) (DSMU51Input, []string) {
	if !dsmU51DNSActive(ctx) {
		return DSMU51Input{}, nil
	}
	paths := []string{
		"/var/packages/DNSServer/target/etc/named.conf",
		"/var/packages/DNSServer/etc/named.conf",
		"/usr/syno/etc/named.conf",
		"/etc/named.conf",
		"/etc.defaults/named.conf",
	}
	for _, path := range paths {
		content, ok, err := dsmU51ReadBounded(path)
		if err != nil {
			return DSMU51Input{DNSActive: true}, []string{err.Error()}
		}
		if ok {
			return DSMU51Input{DNSActive: true, ConfigPath: path, NamedConf: content, Found: true}, nil
		}
	}
	return DSMU51Input{DNSActive: true}, []string{"활성 DNS 서비스의 named.conf를 찾을 수 없습니다"}
}

func evalU51(input DSMU51Input) CheckResult {
	if !input.DNSActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "dns_service=inactive"}
	}
	raw := dsmU51Raw(input)
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: raw, ProcessedConfig: "dynamic_update=unknown", ErrMsg: "활성 DNS 서비스 설정을 확인할 수 없습니다"}
	}
	effective := dsmU51EffectiveConfig(input.NamedConf)
	values := dsmU51UpdateValues(effective)
	unrestricted := false
	for _, value := range values {
		if dsmU51ContainsToken(value, "any") {
			unrestricted = true
			break
		}
	}
	if !unrestricted {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "dynamic_update=disabled_or_restricted"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "dynamic_update=unrestricted",
		VulnerableConfig: "allow-update 또는 allow-update-forwarding이 any로 설정되어 있습니다.",
	}
}

func dsmU51Raw(input DSMU51Input) string {
	if input.ConfigPath == "" {
		return input.NamedConf
	}
	return input.ConfigPath + "\n" + input.NamedConf
}

func dsmU51EffectiveConfig(raw string) string {
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

func dsmU51UpdateValues(raw string) []string {
	pattern := regexp.MustCompile(`(?i)\ballow-update(?:-forwarding)?\s*\{([^}]*)\}`)
	matches := pattern.FindAllStringSubmatch(raw, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		values = append(values, strings.ToLower(match[1]))
	}
	return values
}

func dsmU51ContainsToken(raw, target string) bool {
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) {
		if strings.EqualFold(token, target) {
			return true
		}
	}
	return false
}

func dsmU51DNSActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"named", "dnsmasq"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"DNSServer", "DNS Server"}) ||
		ports[53]
}

func dsmU51ReadBounded(path string) (string, bool, error) {
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
