package main

import (
	"fmt"
	"strings"
)

type U64Input struct {
	Version        string
	MajorVersion   string
	MinorVersion   string
	BuildNumber    string
	SmallFixNumber string
}

func checkU64(ctx ScanContext) CheckResult {
	input, errs := loadU64Input(ctx)
	result := evalU64(input)
	result.Code = "U-64"
	result.Description = "DSM security updates and vendor-recommended patches should be current."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1190"}, Mitigations: []string{"M1051"}}
	return resultWithErrors(result, errs)
}

func loadU64Input(ctx ScanContext) (U64Input, []string) {
	metadata := ctx.Metadata
	return U64Input{
		Version:        metadata.Version,
		MajorVersion:   metadata.MajorVersion,
		MinorVersion:   metadata.MinorVersion,
		BuildNumber:    metadata.BuildNumber,
		SmallFixNumber: metadata.SmallFixNumber,
	}, nil
}

func evalU64(input U64Input) CheckResult {
	if strings.TrimSpace(input.Version) == "" ||
		strings.TrimSpace(input.BuildNumber) == "" ||
		strings.TrimSpace(input.SmallFixNumber) == "" {
		return CheckResult{
			Status:          Error,
			RawConfig:       dsmU64MetadataEvidence(input),
			ProcessedConfig: "dsm_update_metadata=insufficient",
			ErrMsg:          "DSM version, build, and small-fix metadata are required for patch review",
		}
	}
	return CheckResult{
		Status:          Manual,
		RawConfig:       dsmU64MetadataEvidence(input),
		ProcessedConfig: "compare_version_build_and_smallfix_with_current_Synology_DSM_6.2_security_advisories=true update_command_executed=false",
	}
}

func dsmU64MetadataEvidence(input U64Input) string {
	return fmt.Sprintf(
		"version=%s major=%s minor=%s build=%s smallfix=%s",
		dsmU64Value(input.Version),
		dsmU64Value(input.MajorVersion),
		dsmU64Value(input.MinorVersion),
		dsmU64Value(input.BuildNumber),
		dsmU64Value(input.SmallFixNumber),
	)
}

func dsmU64Value(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "missing"
	}
	return value
}
