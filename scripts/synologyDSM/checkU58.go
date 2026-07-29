package main

import "fmt"

type U58Input struct {
	SNMP Service
}

func checkU58(ctx ScanContext) CheckResult {
	input, errs := loadU58Input(ctx)
	result := evalU58(input)
	result.Code = "U-58"
	result.Description = "SNMP service should be disabled when it is not required."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU58Input(ctx ScanContext) (U58Input, []string) {
	return U58Input{SNMP: dsmU58Service(ctx.Services, "snmp")}, nil
}

func evalU58(input U58Input) CheckResult {
	active := input.SNMP.IsActive
	result := CheckResult{
		Status:          Good,
		RawConfig:       dsmU58ServiceEvidence(input.SNMP),
		ProcessedConfig: fmt.Sprintf("snmp_active=%t", active),
	}
	if active {
		result.Status = Vulnerable
		result.VulnerableConfig = "SNMP service is active; disable it unless a documented requirement exists."
	}
	return result
}

func dsmU58Service(services []Service, name string) Service {
	for _, service := range services {
		if service.Name == name {
			return service
		}
	}
	return Service{Name: name}
}

func dsmU58ServiceEvidence(service Service) string {
	return fmt.Sprintf("service=%s running=%t listening=%t active=%t", service.Name, service.Running, service.Listening, service.IsActive)
}
