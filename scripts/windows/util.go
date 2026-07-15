package main

import (
	"fmt"
	"strconv"
	"strings"
)

type CommandResult struct {
	Command string
	Output  string
}

func collectCommands(commands ...string) ([]CommandResult, []string) {
	var results []CommandResult
	var errors []string

	for _, command := range commands {
		output, err := runWithError(command)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", command, err))
			continue
		}

		results = append(results, CommandResult{
			Command: command,
			Output:  output,
		})
	}

	return results, errors
}

func findConfigValue(raw string, target string) string {
	lines := strings.Split(raw, "\n")
	target = strings.ToLower(strings.TrimSpace(target))

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		for _, sep := range []string{"=", ":"} {
			if strings.Contains(line, sep) {
				parts := strings.SplitN(line, sep, 2)
				key := strings.ToLower(strings.TrimSpace(parts[0]))
				value := strings.TrimSpace(parts[1])

				if key == target {
					if value == "" {
						return "NOT_FOUND"
					}
					return value
				}
			}
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(fields[0]))
		value := strings.TrimSpace(strings.Join(fields[1:], " "))

		if key == target {
			return value
		}
	}

	return "NOT_FOUND"
}

func joinErrors(errs []string) string {
	return strings.Join(errs, "\n")
}

func errorResult(code, description string, mitre MitreAttack, errs []string) CheckResult {
	return CheckResult{
		Code:        code,
		Description: description,
		Status:      StatusError,
		ErrMsg:      joinErrors(errs),
		MitreAttack: mitre,
	}
}

func resultWithErrors(result CheckResult, errs []string) CheckResult {
	if len(errs) == 0 {
		return result
	}
	if result.ErrMsg == "" {
		result.ErrMsg = joinErrors(errs)
		return result
	}
	result.ErrMsg += "\n" + joinErrors(errs)
	return result
}

func safeAtoi(value string) int {
	i, _ := strconv.Atoi(strings.TrimSpace(value))
	return i
}

func parseBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "enabled":
		return true, true
	case "false", "0", "no", "disabled":
		return false, true
	default:
		return false, false
	}
}

func containsAnyFold(value string, targets ...string) bool {
	value = strings.ToLower(value)
	for _, target := range targets {
		if strings.Contains(value, strings.ToLower(target)) {
			return true
		}
	}
	return false
}

func firstCommandOutput(results []CommandResult) string {
	if len(results) == 0 {
		return ""
	}
	return results[0].Output
}

func commandOutput(results []CommandResult, index int) string {
	if index < 0 || index >= len(results) {
		return ""
	}
	return results[index].Output
}

func buildProcessedConfig(parts ...string) string {
	return strings.Join(parts, " ")
}

func buildVulnerableConfig(parts ...string) string {
	return strings.Join(parts, "\n")
}
