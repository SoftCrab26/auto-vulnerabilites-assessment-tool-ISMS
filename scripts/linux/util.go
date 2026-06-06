package main

import (
	"os"
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
