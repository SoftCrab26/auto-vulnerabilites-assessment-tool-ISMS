package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU45Input struct {
	MailActive bool
	Evidence   string
}

func checkU45(ctx ScanContext) CheckResult {
	input, errs := loadU45Input(ctx)
	result := evalU45(input)
	result.Code = "U-45"
	result.Description = "메일 서비스 버전 및 보안 패치 적용 여부를 확인해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1051"}}
	return resultWithErrors(result, errs)
}

func loadU45Input(ctx ScanContext) (DSMU45Input, []string) {
	active := dsmU45MailActive(ctx)
	if !active {
		return DSMU45Input{}, nil
	}
	paths := []string{
		"/var/packages/MailServer/INFO",
		"/var/packages/MailPlus-Server/INFO",
		"/var/packages/MailPlusServer/INFO",
	}
	var evidence []string
	for _, path := range paths {
		content, ok, err := dsmU45ReadBounded(path)
		if err != nil {
			return DSMU45Input{MailActive: true, Evidence: strings.Join(evidence, "\n")}, []string{err.Error()}
		}
		if ok {
			evidence = append(evidence, path+"\n"+content)
		}
	}
	if len(evidence) == 0 {
		evidence = append(evidence, "메일 서비스 활성 증거: 프로세스/리스닝 포트/패키지 목록")
	}
	return DSMU45Input{MailActive: true, Evidence: strings.Join(evidence, "\n\n")}, nil
}

func evalU45(input DSMU45Input) CheckResult {
	if !input.MailActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "mail_service=inactive"}
	}
	raw := strings.TrimSpace(input.Evidence)
	if raw == "" {
		raw = "메일 서비스가 활성 상태이나 패키지 버전 정보를 읽지 못했습니다."
	}
	return CheckResult{
		Status:           Manual,
		RawConfig:        raw,
		ProcessedConfig:  "mail_service=active patch_assessment=manual",
		VulnerableConfig: "메일 패키지 버전과 Synology 보안 권고의 최신 패치 적용 여부를 수동 확인하세요.",
	}
}

func dsmU45MailActive(ctx ScanContext) bool {
	if containsAnyWord(ctx.Runtime.ProcessList, []string{"sendmail", "postfix", "smtpd", "master"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"MailServer", "MailPlus-Server", "MailPlusServer"}) {
		return true
	}
	ports := listeningPorts(ctx.Runtime.PortList)
	return ports[25] || ports[465] || ports[587]
}

func dsmU45ReadBounded(path string) (string, bool, error) {
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
