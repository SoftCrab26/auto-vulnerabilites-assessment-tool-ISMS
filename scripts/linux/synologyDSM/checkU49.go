package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type DSMU49Input struct {
	DNSActive bool
	Evidence  string
}

func checkU49(ctx ScanContext) CheckResult {
	input, errs := loadU49Input(ctx)
	result := evalU49(input)
	result.Code = "U-49"
	result.Description = "DNS 서비스 버전 및 보안 패치 적용 여부를 확인해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1051"}}
	return resultWithErrors(result, errs)
}

func loadU49Input(ctx ScanContext) (DSMU49Input, []string) {
	if !dsmU49DNSActive(ctx) {
		return DSMU49Input{}, nil
	}
	paths := []string{
		"/var/packages/DNSServer/INFO",
		"/var/packages/DNSServer/target/INFO",
	}
	var evidence []string
	for _, path := range paths {
		content, ok, err := dsmU49ReadBounded(path)
		if err != nil {
			return DSMU49Input{DNSActive: true, Evidence: strings.Join(evidence, "\n")}, []string{err.Error()}
		}
		if ok {
			evidence = append(evidence, path+"\n"+content)
		}
	}
	if len(evidence) == 0 {
		evidence = append(evidence, "DNS 서비스 활성 증거: named 프로세스/53 포트/DNSServer 패키지")
	}
	return DSMU49Input{DNSActive: true, Evidence: strings.Join(evidence, "\n\n")}, nil
}

func evalU49(input DSMU49Input) CheckResult {
	if !input.DNSActive {
		return CheckResult{Status: NotApplicable, ProcessedConfig: "dns_service=inactive"}
	}
	raw := strings.TrimSpace(input.Evidence)
	if raw == "" {
		raw = "DNS 서비스가 활성 상태이나 패키지 버전 정보를 읽지 못했습니다."
	}
	return CheckResult{
		Status:           Manual,
		RawConfig:        raw,
		ProcessedConfig:  "dns_service=active patch_assessment=manual",
		VulnerableConfig: "DNS Server 패키지 버전과 Synology 보안 권고의 최신 패치 적용 여부를 수동 확인하세요.",
	}
}

func dsmU49DNSActive(ctx ScanContext) bool {
	ports := listeningPorts(ctx.Runtime.PortList)
	return containsAnyWord(ctx.Runtime.ProcessList, []string{"named", "dnsmasq"}) ||
		containsAnyWord(ctx.Runtime.PackageList, []string{"DNSServer", "DNS Server"}) ||
		ports[53]
}

func dsmU49ReadBounded(path string) (string, bool, error) {
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
