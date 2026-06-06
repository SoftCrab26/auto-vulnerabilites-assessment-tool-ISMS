package main

import (
	"os"
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

		results = append(results, FileResult{
			Path:    path,
			Content: string(data),
		})
	}

	return results, errors
}

func findConfigValue(raw string, target string) string {
	lines := strings.Split(raw, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			if key == target {
				if value == "" {
					return "NOT_FOUND"
				}

				return strings.Fields(value)[0]
			}
		}

		fields := strings.Fields(line)

		if len(fields) < 2 {
			continue
		}

		key := fields[0]
		value := fields[1]

		if key == target {
			return value
		}
	}

	return "NOT_FOUND"
}

func joinErrors(errs []string) string {
	return strings.Join(errs, "\n")
}

func errorResult(code string, errs []string) CheckResult {
	return CheckResult{
		Code:   code,
		Status: StatusError,
		ErrMsg: joinErrors(errs),
	}
}

func safeAtoi(value string) int {
	i, _ := strconv.Atoi(value)
	return i
}

func buildProcessedConfig(parts ...string) string {
	return strings.Join(parts, " ")
}

func buildVulnerableConfig(parts ...string) string {
	return strings.Join(parts, "\n")
}
