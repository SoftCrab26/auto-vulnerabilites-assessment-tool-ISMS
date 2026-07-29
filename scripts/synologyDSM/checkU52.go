package main

type DSMU52Input struct {
	TelnetActive bool
	Evidence     string
}

func checkU52(ctx ScanContext) CheckResult {
	input, errs := loadU52Input(ctx)
	result := evalU52(input)
	result.Code = "U-52"
	result.Description = "Telnet 서비스를 비활성화하고 SSH를 사용해야 합니다."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1021"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU52Input(ctx ScanContext) (DSMU52Input, []string) {
	ports := listeningPorts(ctx.Runtime.PortList)
	active := containsAnyWord(ctx.Runtime.ProcessList, []string{"telnetd", "in.telnetd"}) || ports[23]
	evidence := "telnet_process=false telnet_port_23=false"
	if active {
		evidence = "telnet_process_or_port_active=true"
	}
	return DSMU52Input{TelnetActive: active, Evidence: evidence}, nil
}

func evalU52(input DSMU52Input) CheckResult {
	if !input.TelnetActive {
		return CheckResult{Status: Good, RawConfig: input.Evidence, ProcessedConfig: "telnet_service=disabled"}
	}
	return CheckResult{
		Status:           Vulnerable,
		RawConfig:        input.Evidence,
		ProcessedConfig:  "telnet_service=active",
		VulnerableConfig: "평문 Telnet 서비스가 활성화되어 있습니다. 서비스를 중지하고 SSH를 사용하세요.",
	}
}
