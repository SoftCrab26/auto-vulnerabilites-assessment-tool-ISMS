package main

import (
	"strconv"
	"strings"
)

type U14Input struct {
	ProfileContent string
}

func checkU14(ctx ScanContext) CheckResult {
	const code = "U-14"
	const description = "PATH environment variable should not contain '.' at the beginning or middle."
	mitreAttack := MitreAttack{
		Tactic:      "Execution",
		Techniques:  []string{"T1059"},
		Mitigations: []string{"M1022"},
	}

	input, errs := loadU14Input()

	result := evalU14(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU14Input() (U14Input, []string) {
	paths := []string{"/etc/profile", "/root/.profile", "/root/.cshrc"}
	var files []FileResult
	for _, path := range paths {
		found, _ := collectFiles(path)
		files = append(files, found...)
	}
	if len(files) == 0 {
		return U14Input{}, []string{"PATH inspection files not found (/etc/profile, /root/.profile, /root/.cshrc)"}
	}
	var combined strings.Builder
	for _, f := range files {
		combined.WriteString("# FILE: " + f.Path + "\n" + f.Content + "\n")
	}
	return U14Input{ProfileContent: combined.String()}, nil
}

func evalU14(input U14Input) CheckResult {
	content := input.ProfileContent
	hasInsecureDot := false
	var badPaths []string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "path=") || strings.Contains(lower, "export path") {
			// Extract value after =
			eqIdx := strings.Index(line, "=")
			if eqIdx > 0 {
				pathVal := strings.TrimSpace(line[eqIdx+1:])
				// remove export or quotes
				pathVal = strings.TrimPrefix(pathVal, "export ")
				pathVal = strings.Trim(pathVal, "\"'` ")
				if strings.HasPrefix(pathVal, ".") || strings.Contains(pathVal, ":.:") || strings.Contains(pathVal, ":.") || strings.Contains(pathVal, ".:") {
					hasInsecureDot = true
					badPaths = append(badPaths, pathVal)
				}
			}
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if hasInsecureDot {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"insecure_path_detected=true",
			"문제점1. PATH에 \".\" 이 맨 앞이나 중간에 포함되어 있습니다: "+strings.Join(badPaths, " | "),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("path_dot_check=done", "insecure="+strconv.FormatBool(hasInsecureDot)),
		VulnerableConfig: vulnerableConfig,
	}
}
