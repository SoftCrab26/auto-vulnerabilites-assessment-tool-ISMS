package main

import (
	"strconv"
	"strings"
)

type U10Input struct {
	Passwd string
}

func checkU10(ctx ScanContext) CheckResult {
	const code = "U-10"
	const description = "No duplicate UIDs should exist in /etc/passwd."
	mitreAttack := MitreAttack{
		tactic:      "Credential Access",
		techniques:  []string{"T1078"},
		mitigations: []string{"M1026"},
	}

	input, errs := loadU10Input()

	result := evalU10(input)
	result.Code = code
	result.Description = description
	result.MitreAttack = mitreAttack
	return resultWithErrors(result, errs)
}

func loadU10Input() (U10Input, []string) {
	files, errs := collectFiles("/etc/passwd")
	if len(files) == 0 {
		return U10Input{}, errs
	}
	return U10Input{Passwd: files[0].Content}, errs
}

func evalU10(input U10Input) CheckResult {
	content := input.Passwd
	uidMap := make(map[string][]string) // uid -> list of usernames

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			username := fields[0]
			uid := fields[2]
			uidMap[uid] = append(uidMap[uid], username)
		}
	}

	var duplicates []string
	for uid, users := range uidMap {
		if len(users) > 1 {
			duplicates = append(duplicates, uid+"("+strings.Join(users, ",")+")")
		}
	}

	status := StatusGood
	vulnerableConfig := ""
	if len(duplicates) > 0 {
		status = StatusVulnerable
		vulnerableConfig = buildVulnerableConfig(
			"duplicate_uids="+strings.Join(duplicates, ";"),
			"문제점1. 동일한 UID를 가진 계정이 존재합니다: "+strings.Join(duplicates, ", "),
		)
	}

	return CheckResult{
		Status:           status,
		RawConfig:        content,
		ProcessedConfig:  buildProcessedConfig("duplicate_uid_check=done", "duplicate_count="+strconv.Itoa(len(duplicates))),
		VulnerableConfig: vulnerableConfig,
	}
}
