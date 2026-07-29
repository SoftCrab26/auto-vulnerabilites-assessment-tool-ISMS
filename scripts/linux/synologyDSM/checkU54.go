package main

import "strings"

type DSMU54Input struct {
	FTPActive bool
	Evidence  string
}

func checkU54(ctx ScanContext) CheckResult {
	input, errs := loadU54Input(ctx)
	result := evalU54(input)
	result.Code = "U-54"
	result.Description = "암호화되지 않은 FTP 서비스를 비활성화해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU54Input(ctx ScanContext) (DSMU54Input, []string) {
	ports := listeningPorts(ctx.Runtime.PortList)
	active := containsAnyWord(ctx.Runtime.ProcessList, []string{"ftpd", "proftpd", "vsftpd"}) || ports[20] || ports[21]
	for _, service := range ctx.Services {
		if strings.EqualFold(service.Name, "ftp") && service.IsActive {
			active = true
			break
		}
	}
	evidence := "ftp_process=false ftp_ports_20_21=false"
	if active {
		evidence = "ftp_process_or_cleartext_port_active=true"
	}
	return DSMU54Input{FTPActive: active, Evidence: evidence}, nil
}

func evalU54(input DSMU54Input) CheckResult {
	if !input.FTPActive {
		return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "cleartext_ftp=inactive"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        input.Evidence,
		ProcessedConfig:  "cleartext_ftp=active",
		VulnerableConfig: "평문 FTP 서비스가 활성화되어 있습니다. 정책 승인 여부와 무관하게 이 기준에서는 취약으로 판정합니다.",
	}
}
