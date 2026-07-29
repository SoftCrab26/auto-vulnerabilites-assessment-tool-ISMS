package main

import (
	"fmt"
	"strings"
)

type U62Input struct {
	Files []FileResult
}

func checkU62(ctx ScanContext) CheckResult {
	input, errs := loadU62Input()
	result := evalU62(input)
	result.Code = "U-62"
	result.Description = "Login, SSH, and DSM access should display an authorized-use warning banner."
	result.MitreAttack = MitreAttack{Tactic: "Initial Access", Techniques: []string{"T1078"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU62Input() (U62Input, []string) {
	files, errs := collectFiles(
		"/etc/issue",
		"/etc/issue.net",
		"/etc/motd",
		"/etc/ssh/sshd_config",
		"/etc/synoinfo.conf",
	)
	return U62Input{Files: files}, errs
}

func evalU62(input U62Input) CheckResult {
	if len(input.Files) == 0 {
		return CheckResult{Status: Error, ProcessedConfig: "banner_evidence=missing", ErrMsg: "no DSM login or SSH banner evidence was collected"}
	}

	var evidence []string
	var bannerFound bool
	for _, file := range input.Files {
		fileEvidence, found := dsmU62FileEvidence(file)
		evidence = append(evidence, fileEvidence...)
		bannerFound = bannerFound || found
	}
	status := Good
	vulnerable := ""
	if !bannerFound {
		status = Vulnerable
		vulnerable = "No enabled authorized-use warning was found for console, SSH, or DSM login."
	}
	return CheckResult{
		Status:           status,
		RawConfig:        strings.Join(evidence, "\n"),
		ProcessedConfig:  fmt.Sprintf("banner_configured=%t evidence_files=%d", bannerFound, len(input.Files)),
		VulnerableConfig: vulnerable,
	}
}

func dsmU62FileEvidence(file FileResult) ([]string, bool) {
	var evidence []string
	var found bool
	for _, line := range dsmU59ActiveLines(file.Content) {
		lower := strings.ToLower(line)
		relevant := false
		if strings.HasSuffix(file.Path, "sshd_config") {
			fields := strings.Fields(line)
			relevant = len(fields) >= 2 && strings.EqualFold(fields[0], "Banner")
			if relevant && !strings.EqualFold(fields[1], "none") {
				found = true
			}
		} else if strings.HasSuffix(file.Path, "synoinfo.conf") {
			relevant = strings.HasPrefix(lower, "login_title=") ||
				strings.HasPrefix(lower, "login_welcome=") ||
				strings.HasPrefix(lower, "login_banner=")
			if relevant {
				parts := strings.SplitN(line, "=", 2)
				found = found || (len(parts) == 2 && strings.Trim(strings.TrimSpace(parts[1]), `"'`) != "")
			}
		} else {
			relevant = strings.TrimSpace(line) != ""
			found = found || relevant
		}
		if relevant {
			evidence = append(evidence, fmt.Sprintf("path=%s evidence=%s", file.Path, dsmU62SafeLine(line)))
		}
	}
	if len(evidence) == 0 {
		evidence = append(evidence, fmt.Sprintf("path=%s banner_evidence=none", file.Path))
	}
	return evidence, found
}

func dsmU62SafeLine(line string) string {
	line = strings.Join(strings.Fields(line), " ")
	const limit = 256
	if len(line) > limit {
		return line[:limit] + "..."
	}
	return line
}
