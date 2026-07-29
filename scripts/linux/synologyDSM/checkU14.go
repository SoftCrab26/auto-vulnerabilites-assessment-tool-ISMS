package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const dsmU14EvidenceLimit = 40

type dsmU14AuditFile struct {
	Path    string
	Mode    os.FileMode
	UID     uint32
	Content string
}

type U14Input struct {
	Files []dsmU14AuditFile
}

func checkU14(ScanContext) CheckResult {
	input, errs := loadU14Input()
	result := evalU14(input)
	result.Code = "U-14"
	result.Description = "PATH must not contain the current directory."
	result.MitreAttack = MitreAttack{Tactic: "Execution", Techniques: []string{"T1059"}, Mitigations: []string{"M1022"}}
	return resultWithErrors(result, errs)
}

func loadU14Input() (U14Input, []string) {
	files, errs := dsmU14LoadPreferredRequired("profile")
	return U14Input{Files: files}, errs
}

func evalU14(input U14Input) CheckResult {
	if len(input.Files) == 0 {
		return dsmU14Error("required PATH configuration is unavailable")
	}
	var evidence, bad []string
	for _, file := range input.Files {
		for _, rawLine := range strings.Split(file.Content, "\n") {
			line := strings.TrimSpace(rawLine)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			assignment, ok := dsmU14PathAssignment(line)
			if !ok {
				continue
			}
			safe := file.Path + ": " + dsmU14Sanitize(assignment)
			evidence = append(evidence, safe)
			if dsmU14HasCurrentDirectory(assignment) {
				bad = append(bad, safe)
			}
		}
	}
	if len(evidence) == 0 {
		return dsmU14Error("no PATH assignment found in required configuration")
	}
	status := Good
	vulnerable := ""
	if len(bad) > 0 {
		status = Vulnerable
		vulnerable = strings.Join(bad, "\n")
	}
	return CheckResult{Status: status, RawConfig: dsmU14JoinEvidence(evidence), VulnerableConfig: vulnerable,
		ProcessedConfig: fmt.Sprintf("path_assignments=%d insecure=%t", len(evidence), len(bad) > 0)}
}

func dsmU14PathAssignment(line string) (string, bool) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
	index := strings.IndexByte(line, '=')
	if index < 1 || strings.TrimSpace(line[:index]) != "PATH" {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(line[index+1:]), `"'`), true
}

func dsmU14HasCurrentDirectory(value string) bool {
	for _, component := range strings.Split(value, ":") {
		component = strings.TrimSpace(component)
		if component == "" || component == "." {
			return true
		}
	}
	return false
}

func dsmU14LoadPreferredRequired(name string) ([]dsmU14AuditFile, []string) {
	for _, path := range preferredDSMPaths(name) {
		file, err := dsmU14ReadAuditFile(path, true)
		if err == nil {
			return []dsmU14AuditFile{file}, nil
		}
		if !os.IsNotExist(err) {
			return nil, []string{err.Error()}
		}
	}
	return nil, []string{"required file not found: " + strings.Join(preferredDSMPaths(name), ", ")}
}

func dsmU14ReadAuditFile(path string, withContent bool) (dsmU14AuditFile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return dsmU14AuditFile{}, fmt.Errorf("%s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return dsmU14AuditFile{}, fmt.Errorf("%s: not a regular file", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return dsmU14AuditFile{}, fmt.Errorf("%s: owner metadata unavailable", path)
	}
	file := dsmU14AuditFile{Path: path, Mode: info.Mode(), UID: stat.Uid}
	if withContent {
		data, err := os.ReadFile(path)
		if err != nil {
			return dsmU14AuditFile{}, fmt.Errorf("%s: %w", path, err)
		}
		file.Content = string(data)
	}
	return file, nil
}

func dsmU14Metadata(file dsmU14AuditFile) string {
	return fmt.Sprintf("%s uid=%d mode=%04o", file.Path, file.UID, file.Mode.Perm())
}

func dsmU14PermissionResult(file dsmU14AuditFile, allowed os.FileMode, owners ...uint32) CheckResult {
	if file.Path == "" {
		return dsmU14Error("required file metadata is unavailable")
	}
	ownerOK := false
	for _, owner := range owners {
		ownerOK = ownerOK || file.UID == owner
	}
	modeOK := file.Mode.Perm()&^allowed == 0
	status := Good
	vulnerable := ""
	if !ownerOK || !modeOK {
		status = Vulnerable
		vulnerable = dsmU14Metadata(file)
	}
	return CheckResult{Status: status, RawConfig: dsmU14Metadata(file), VulnerableConfig: vulnerable,
		ProcessedConfig: fmt.Sprintf("owner_ok=%t mode_ok=%t", ownerOK, modeOK)}
}

func dsmU14Error(message string) CheckResult {
	return CheckResult{Status: Error, ErrMsg: message}
}

func dsmU14Sanitize(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) > 240 {
		value = value[:240] + "..."
	}
	return value
}

func dsmU14JoinEvidence(lines []string) string {
	if len(lines) > dsmU14EvidenceLimit {
		lines = append(append([]string{}, lines[:dsmU14EvidenceLimit]...), "... evidence capped at "+strconv.Itoa(dsmU14EvidenceLimit))
	}
	return strings.Join(lines, "\n")
}

func dsmU14DirectFiles(root string, limit int) ([]dsmU14AuditFile, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var files []dsmU14AuditFile
	for _, entry := range entries {
		if len(files) >= limit {
			break
		}
		path := filepath.Join(root, entry.Name())
		file, err := dsmU14ReadAuditFile(path, false)
		if err == nil {
			files = append(files, file)
		}
	}
	return files, nil
}
