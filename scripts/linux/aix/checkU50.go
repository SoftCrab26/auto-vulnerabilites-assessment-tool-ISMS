package main

import (
	"regexp"
	"strings"
)

type U50Input struct {
	DNS       Service
	NamedConf string
	Found     bool
}

func checkU50(ctx ScanContext) CheckResult {
	input, errs := loadU50Input(ctx)
	result := evalU50(input)
	result.Code = "U-50"
	result.Description = "Restrict DNS zone transfers to authorized hosts."
	result.MitreAttack = MitreAttack{Tactic: "Discovery", Techniques: []string{"T1082"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU50Input(ctx ScanContext) (U50Input, []string) {
	file, errs := collectFirstExisting("/etc/named.conf", "/etc/named.boot")
	return U50Input{DNS: ctx.Services["dns"], NamedConf: file.Content, Found: file.Path != ""}, errs
}

func evalU50(input U50Input) CheckResult {
	if !input.Found && strings.TrimSpace(input.NamedConf) == "" {
		return missingServiceConfig(input.DNS, "named.conf")
	}
	values := namedDirectiveValues(input.NamedConf, "allow-transfer")
	restricted := len(values) > 0
	for _, value := range values {
		if aclIsUnrestricted(value) {
			restricted = false
			break
		}
	}
	result := CheckResult{Status: StatusGood, RawConfig: input.NamedConf, ProcessedConfig: "allow-transfer=restricted"}
	if !restricted {
		result.Status = StatusVulnerable
		result.ProcessedConfig = "allow-transfer=unrestricted_or_missing"
		result.VulnerableConfig = "allow-transfer is missing or permits any host."
	}
	return result
}

func namedDirectiveValues(raw, directive string) []string {
	content := activeConfigText(raw)
	pattern := regexp.MustCompile(`(?is)\b` + regexp.QuoteMeta(strings.ToLower(directive)) + `\s*\{([^}]*)\}`)
	matches := pattern.FindAllStringSubmatch(content, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		values = append(values, strings.TrimSpace(match[1]))
	}
	return values
}

func aclIsUnrestricted(value string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if token == "any" || token == "0.0.0.0/0" || token == "::/0" {
			return true
		}
	}
	return false
}
