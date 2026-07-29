package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type FileResult struct {
	Path    string
	Content string
}

func collectFiles(paths ...string) ([]FileResult, []string) {
	files := make([]FileResult, 0, len(paths))
	var errors []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		files = append(files, FileResult{Path: path, Content: string(data)})
	}
	return files, errors
}

func collectFirstExisting(paths ...string) (FileResult, []string) {
	var errors []string
	for _, path := range paths {
		files, readErrors := collectFiles(path)
		if len(files) == 1 {
			return files[0], errors
		}
		errors = append(errors, readErrors...)
	}
	return FileResult{}, errors
}

func preferredDSMPaths(name string) []string {
	cleanName := strings.TrimPrefix(filepath.Clean("/"+name), "/")
	return []string{
		filepath.Join("/etc", cleanName),
		filepath.Join("/etc.defaults", cleanName),
	}
}

func parseKeyValues(raw string) map[string]string {
	values := make(map[string]string)
	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = stripUnquotedComment(line)
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		values[key] = value
	}
	return values
}

func stripUnquotedComment(value string) string {
	var quote rune
	escaped := false
	for index, character := range value {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if character == '\'' || character == '"' {
			if quote == 0 {
				quote = character
			} else if quote == character {
				quote = 0
			}
			continue
		}
		if character == '#' && quote == 0 {
			return strings.TrimSpace(value[:index])
		}
	}
	return strings.TrimSpace(value)
}

func buildProcessedConfig(parts ...string) string {
	return strings.Join(parts, " ")
}

func buildVulnerableConfig(parts ...string) string {
	return strings.Join(parts, "\n")
}

func resultWithErrors(result CheckResult, errors []string) CheckResult {
	if len(errors) == 0 {
		return result
	}
	if result.ErrMsg != "" {
		result.ErrMsg += "\n"
	}
	result.ErrMsg += strings.Join(errors, "\n")
	return result
}

var unsafeFilenameCharacters = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitizedFilename(value string) string {
	value = strings.TrimSpace(value)
	value = unsafeFilenameCharacters.ReplaceAllString(value, "_")
	value = strings.Trim(value, "._-")
	if value == "" {
		return "unknown"
	}
	return value
}

func localIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.IsGlobalUnicast() && ip.To4() != nil {
				return ip.String()
			}
		}
	}
	return "unknown"
}
