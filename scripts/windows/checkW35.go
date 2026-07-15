package main

import "strings"

type W35Input struct {
	Defender string
	Products string
}

func checkW35(ctx ScanContext) CheckResult {
	const code = "W-35"
	const description = "Antivirus software should be installed and have current updates."
	mitreAttack := MitreAttack{tactic: "Execution", techniques: []string{"T1204"}, mitigations: []string{"M1049"}}

	input, errs := loadW35Input()
	result := evalW35(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitreAttack
	return resultWithErrors(result, errs)
}

func loadW35Input() (W35Input, []string) {
	defenderCommand := `$s=Get-MpComputerStatus; Write-Output ('ANTIVIRUS_ENABLED=' + [string]$s.AntivirusEnabled); Write-Output ('SIGNATURE_AGE_DAYS=' + [string]$s.AntivirusSignatureAge); Write-Output ('SIGNATURE_LAST_UPDATED=' + [string]$s.AntivirusSignatureLastUpdated)`
	productCommand := `Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { Write-Output ($_.displayName + '|PRODUCT_STATE=' + [string]$_.productState + '|PATH=' + [string]$_.pathToSignedProductExe) }`
	defenderResults, defenderErrs := collectCommands(defenderCommand)
	productResults, productErrs := collectCommands(productCommand)
	errs := append(defenderErrs, productErrs...)
	return W35Input{Defender: firstCommandOutput(defenderResults), Products: firstCommandOutput(productResults)}, errs
}

func evalW35(input W35Input) CheckResult {
	enabled, enabledKnown := parseBool(findConfigValue(input.Defender, "ANTIVIRUS_ENABLED"))
	hasProducts := strings.TrimSpace(input.Products) != ""
	status := StatusInterview
	vulnerable := ""
	if enabledKnown && !enabled && !hasProducts {
		status = StatusVulnerable
		vulnerable = buildVulnerableConfig("defender_enabled=false", "antivirus_products=none_detected")
	}

	raw := buildVulnerableConfig("DEFENDER", input.Defender, "SECURITY_CENTER_PRODUCTS", input.Products)
	processed := buildProcessedConfig("defender_enabled="+strconvFormatBool(enabled), "signature_age_days="+findConfigValue(input.Defender, "SIGNATURE_AGE_DAYS"), "third_party_product_detected="+strconvFormatBool(hasProducts), "update_freshness=interview_required")
	return CheckResult{Status: status, RawConfig: raw, ProcessedConfig: processed, VulnerableConfig: vulnerable}
}
