package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU46Input struct {
	MailActive bool
	ConfigPath string
	Config     string
	Found      bool
}

func checkU46(ctx ScanContext) CheckResult {
	input, errs := loadU46Input(ctx)
	result := evalU46(input)
	result.Code = "U-46"
	result.Description = "일반 사용자의 sendmail/postfix 실행을 제한해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Privilege Escalation", Techniques: []string{"T1548"}, Mitigations: []string{"M1026"}}
	return resultWithErrors(result, errs)
}

func loadU46Input(ctx ScanContext) (DSMU46Input, []string) {
	active := dsmU46MailActive(ctx)
	if !active {
		return DSMU46Input{}, nil
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
		content, ok, err := dsmU46ReadBounded(path)
		if err != nil {
			return DSMU46Input{MailActive: true}, []string{err.Error()}
		}
		if ok {
			return DSMU46Input{MailActive: true, ConfigPath: path, Config: content, Found: true}, nil
		}
	}
	return DSMU46Input{MailActive: true}, []string{"활성 메일 서비스의 sendmail/postfix 설정 파일을 찾을 수 없습니다"}
}

func evalU46(input DSMU46Input) CheckResult {
	if !input.MailActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "mail_service=inactive"}
	}
	raw := dsmU46Raw(input)
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: raw, ProcessedConfig: "mail_execution_restriction=unknown", ErrMsg: "활성 메일 서비스 설정을 확인할 수 없습니다"}
	}

	config := dsmU46EffectiveConfig(input.Config)
	lower := strings.ToLower(config)
	restricted := false
	if strings.Contains(strings.ToLower(input.ConfigPath), "sendmail") {
		restricted = strings.Contains(lower, "restrictqrun")
	} else {
		value, ok := dsmU46Setting(config, "authorized_submit_users")
		restricted = ok && value != "" && value != "static:anyone" && value != "anyone"
	}
	if restricted {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "mail_execution_restriction=enabled"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "mail_execution_restriction=disabled",
		VulnerableConfig: "일반 사용자의 sendmail 실행 또는 Postfix 메일 제출 권한 제한을 확인할 수 없습니다.",
	}
}

func dsmU46Raw(input DSMU46Input) string {
	if input.ConfigPath == "" {
		return input.Config
	}
	return input.ConfigPath + "\n" + input.Config
}

func dsmU46EffectiveConfig(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func dsmU46Setting(raw, key string) (string, bool) {
	for _, line := range strings.Split(raw, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), key) {
			return strings.ToLower(strings.TrimSpace(parts[1])), true
		}
	}
	return "", false
}

func dsmU46MailActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"sendmail", "postfix", "smtpd"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"MailServer", "MailPlus-Server"}) ||
		ports[25] || ports[465] || ports[587]
}

func dsmU46ReadBounded(path string) (string, bool, error) {
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
