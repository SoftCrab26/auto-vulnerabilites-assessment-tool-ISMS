package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU48Input struct {
	MailActive bool
	ConfigPath string
	Config     string
	Found      bool
}

func checkU48(ctx ScanContext) CheckResult {
	input, errs := loadU48Input(ctx)
	result := evalU48(input)
	result.Code = "U-48"
	result.Description = "SMTP EXPN 및 VRFY 명령을 제한해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU48Input(ctx ScanContext) (DSMU48Input, []string) {
	if !dsmU48MailActive(ctx) {
		return DSMU48Input{}, nil
	}
	paths := []string{
		"/var/packages/MailServer/target/etc/main.cf",
		"/var/packages/MailPlus-Server/target/etc/postfix/main.cf",
		"/usr/syno/etc/postfix/main.cf",
		"/etc/postfix/main.cf",
		"/etc/mail/sendmail.cf",
		"/etc.defaults/mail/sendmail.cf",
	}
	for _, path := range paths {
		content, ok, err := dsmU48ReadBounded(path)
		if err != nil {
			return DSMU48Input{MailActive: true}, []string{err.Error()}
		}
		if ok {
			return DSMU48Input{MailActive: true, ConfigPath: path, Config: content, Found: true}, nil
		}
	}
	return DSMU48Input{MailActive: true}, []string{"활성 메일 서비스의 EXPN/VRFY 설정 파일을 찾을 수 없습니다"}
}

func evalU48(input DSMU48Input) CheckResult {
	if !input.MailActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "mail_service=inactive"}
	}
	raw := dsmU48Raw(input)
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: raw, ProcessedConfig: "expn_vrfy_restriction=unknown", ErrMsg: "활성 메일 서비스 설정을 확인할 수 없습니다"}
	}
	effective := strings.ToLower(dsmU48EffectiveConfig(input.Config))
	restricted := false
	if strings.Contains(strings.ToLower(input.ConfigPath), "sendmail") {
		restricted = strings.Contains(effective, "noexpn") && strings.Contains(effective, "novrfy")
	} else {
		value, ok := dsmU48Setting(effective, "disable_vrfy_command")
		restricted = ok && (value == "yes" || value == "true")
	}
	if restricted {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "expn_vrfy_restriction=enabled"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "expn_vrfy_restriction=disabled",
		VulnerableConfig: "SMTP EXPN/VRFY 사용자 정보 확인 명령이 모두 제한되어 있지 않습니다.",
	}
}

func dsmU48Raw(input DSMU48Input) string {
	if input.ConfigPath == "" {
		return input.Config
	}
	return input.ConfigPath + "\n" + input.Config
}

func dsmU48EffectiveConfig(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func dsmU48Setting(raw, key string) (string, bool) {
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), key) {
			return strings.TrimSpace(parts[1]), true
		}
	}
	return "", false
}

func dsmU48MailActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"sendmail", "postfix", "smtpd"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"MailServer", "MailPlus-Server"}) ||
		ports[25] || ports[465] || ports[587]
}

func dsmU48ReadBounded(path string) (string, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > 256*1024 {
		return "", false, fmt.Errorf("%s: file exceeds 256 KiB", path)
	}
	return string(data), true, nil
}
