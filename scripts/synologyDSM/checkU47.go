package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU47Input struct {
	MailActive bool
	ConfigPath string
	Config     string
	Found      bool
}

func checkU47(ctx ScanContext) CheckResult {
	input, errs := loadU47Input(ctx)
	result := evalU47(input)
	result.Code = "U-47"
	result.Description = "스팸 메일 릴레이를 제한해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Impact", Techniques: []string{"T1566"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU47Input(ctx ScanContext) (DSMU47Input, []string) {
	active := dsmU47MailActive(ctx)
	if !active {
		return DSMU47Input{}, nil
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
		content, ok, err := dsmU47ReadBounded(path)
		if err != nil {
			return DSMU47Input{MailActive: true}, []string{err.Error()}
		}
		if ok {
			return DSMU47Input{MailActive: true, ConfigPath: path, Config: content, Found: true}, nil
		}
	}
	return DSMU47Input{MailActive: true}, []string{"활성 메일 서비스의 릴레이 설정 파일을 찾을 수 없습니다"}
}

func evalU47(input DSMU47Input) CheckResult {
	if !input.MailActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "mail_service=inactive"}
	}
	raw := dsmU47Raw(input)
	if !input.Found {
		return CheckResult{Status: Error, RawConfig: raw, ProcessedConfig: "mail_relay_restriction=unknown", ErrMsg: "활성 메일 서비스 릴레이 설정을 확인할 수 없습니다"}
	}

	effective := strings.ToLower(dsmU47EffectiveConfig(input.Config))
	restricted := false
	if strings.Contains(strings.ToLower(input.ConfigPath), "sendmail") {
		restricted = strings.Contains(effective, "access_db") ||
			strings.Contains(effective, "kaccess") ||
			strings.Contains(effective, "relay-domains")
	} else {
		restricted = strings.Contains(effective, "reject_unauth_destination") ||
			strings.Contains(effective, "defer_unauth_destination")
	}
	if restricted {
		return CheckResult{Status: Good, RawConfig: raw, ProcessedConfig: "mail_relay_restriction=enabled"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        raw,
		ProcessedConfig:  "mail_relay_restriction=disabled",
		VulnerableConfig: "허가되지 않은 외부 발신자의 메일 릴레이를 차단하는 설정을 확인할 수 없습니다.",
	}
}

func dsmU47Raw(input DSMU47Input) string {
	if input.ConfigPath == "" {
		return input.Config
	}
	return input.ConfigPath + "\n" + input.Config
}

func dsmU47EffectiveConfig(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func dsmU47MailActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"sendmail", "postfix", "smtpd"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"MailServer", "MailPlus-Server"}) ||
		ports[25] || ports[465] || ports[587]
}

func dsmU47ReadBounded(path string) (string, bool, error) {
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
