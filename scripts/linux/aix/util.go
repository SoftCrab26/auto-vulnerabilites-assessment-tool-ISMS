package main

import (
	"fmt"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
)

type FileResult struct {
	Path    string
	Content string
}

func collectFiles(paths ...string) ([]FileResult, []string) {
	var results []FileResult
	var errors []string

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		results = append(results, FileResult{Path: path, Content: string(data)})
	}

	return results, errors
}

func collectFirstExisting(paths ...string) (FileResult, []string) {
	var errors []string
	for _, path := range paths {
		files, errs := collectFiles(path)
		if len(files) > 0 {
			return files[0], errors
		}
		errors = append(errors, errs...)
	}
	return FileResult{}, errors
}

func findConfigValue(raw, target string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		for _, separator := range []string{"=", ":"} {
			if !strings.Contains(line, separator) {
				continue
			}
			parts := strings.SplitN(line, separator, 2)
			if strings.ToLower(strings.TrimSpace(parts[0])) == target {
				value := strings.TrimSpace(parts[1])
				if value == "" {
					return "NOT_FOUND"
				}
				return value
			}
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.ToLower(fields[0]) == target {
			return strings.Join(fields[1:], " ")
		}
	}
	return "NOT_FOUND"
}

func findStanzaValue(raw, stanza, target string) string {
	currentStanza := ""
	stanza = strings.ToLower(strings.TrimSpace(stanza))
	target = strings.ToLower(strings.TrimSpace(target))

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "*") {
			continue
		}
		if strings.HasSuffix(line, ":") && !strings.Contains(line, "=") {
			currentStanza = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, ":")))
			continue
		}
		if currentStanza != stanza {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.ToLower(strings.TrimSpace(parts[0])) == target {
			value := strings.TrimSpace(parts[1])
			if value == "" {
				return "NOT_FOUND"
			}
			return value
		}
	}
	return "NOT_FOUND"
}

func extractStanza(raw, stanza string) string {
	stanza = strings.ToLower(strings.TrimSpace(stanza))
	inTarget := false
	var lines []string

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line != "" && strings.HasSuffix(line, ":") && !strings.Contains(line, "=") {
			current := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, ":")))
			if inTarget && current != stanza {
				break
			}
			inTarget = current == stanza
		}
		if inTarget {
			lines = append(lines, rawLine)
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func fileOwnerName(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	value := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !value.IsValid() {
		return "", fmt.Errorf("owner metadata unavailable for %s", path)
	}
	uid := value.FieldByName("Uid")
	if !uid.IsValid() {
		uid = value.FieldByName("Uid64")
	}
	if !uid.IsValid() {
		return "", fmt.Errorf("owner uid unavailable for %s", path)
	}

	var id uint64
	if uid.CanUint() {
		id = uid.Uint()
	} else if uid.CanInt() && uid.Int() >= 0 {
		id = uint64(uid.Int())
	} else {
		return "", fmt.Errorf("unsupported owner uid for %s", path)
	}
	account, err := user.LookupId(strconv.FormatUint(id, 10))
	if err != nil {
		return strconv.FormatUint(id, 10), nil
	}
	return account.Username, nil
}

func resultWithErrors(result CheckResult, errs []string) CheckResult {
	if len(errs) == 0 {
		return result
	}
	if result.ErrMsg != "" {
		result.ErrMsg += "\n"
	}
	result.ErrMsg += strings.Join(errs, "\n")
	return result
}

func errorResult(code, description string, mitre MitreAttack, errs []string) CheckResult {
	return CheckResult{
		Code:        code,
		Description: description,
		Status:      StatusError,
		ErrMsg:      strings.Join(errs, "\n"),
		MitreAttack: mitre,
	}
}

func safeAtoi(value string) int {
	number, _ := strconv.Atoi(strings.TrimSpace(value))
	return number
}

func buildProcessedConfig(parts ...string) string {
	return strings.Join(parts, " ")
}

func buildVulnerableConfig(parts ...string) string {
	return strings.Join(parts, "\n")
}

func buildLabeledRawConfig(files []FileResult) string {
	var sections []string
	for _, file := range files {
		sections = append(sections, "["+file.Path+"]\n"+file.Content)
	}
	return strings.Join(sections, "\n")
}
