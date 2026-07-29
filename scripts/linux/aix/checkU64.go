package main

import (
	"fmt"
	"strings"
)

type U64Input struct {
	OSLevel         string
	InstfixEvidence string
}

func checkU64(ctx ScanContext) CheckResult {
	const code = "U-64"
	const description = "Security fixes and vendor recommendations should be reviewed and applied."
	mitre := MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1190"}, Mitigations: []string{"M1051"}}

	input, errs := loadU64Input()
	result := evalU64(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU64Input() (U64Input, []string) {
	var input U64Input
	var errs []string
	if output, err := runProgram("oslevel", "-s"); err != nil {
		errs = append(errs, err.Error())
	} else {
		input.OSLevel = output
	}
	if output, err := runProgram("instfix", "-i"); err != nil {
		errs = append(errs, err.Error())
	} else {
		input.InstfixEvidence = output
	}
	return input, errs
}

func evalU64(input U64Input) CheckResult {
	evidence := []string{}
	if strings.TrimSpace(input.OSLevel) != "" {
		evidence = append(evidence, "oslevel -s:\n"+input.OSLevel)
	}
	if strings.TrimSpace(input.InstfixEvidence) != "" {
		evidence = append(evidence, "instfix -i:\n"+input.InstfixEvidence)
	}
	return CheckResult{
		Status:           StatusInterview,
		RawConfig:        strings.Join(evidence, "\n"),
		ProcessedConfig:  fmt.Sprintf("oslevel_evidence=%t instfix_evidence=%t", input.OSLevel != "", input.InstfixEvidence != ""),
		VulnerableConfig: "Review IBM security advisories and patch policy against the collected oslevel and instfix evidence.",
	}
}
