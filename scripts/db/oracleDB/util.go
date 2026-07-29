package main

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

var (
	credentialPattern = regexp.MustCompile(`(?i)([[:alnum:]_.#$-]+)/([^@\s]+)@`)
	passwordPattern   = regexp.MustCompile(`(?i)(password\s*=\s*)[^\s;]+`)
	oracleErrorPrefix = regexp.MustCompile(`(?i)^(ORA-|TNS-|SP2-)`)
)

func parseSQLPlusRows(output string) ([][]string, error) {
	var rows [][]string
	for _, rawLine := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if oracleErrorPrefix.MatchString(line) {
			return nil, errors.New(redactOracleError(line, ""))
		}
		if !strings.Contains(line, sqlColumnSeparator) {
			return nil, errors.New("sqlplus returned unexpected output")
		}
		columns := strings.Split(line, sqlColumnSeparator)
		for i := range columns {
			columns[i] = strings.TrimSpace(columns[i])
		}
		rows = append(rows, columns)
	}
	return rows, nil
}

func redactOracleError(message, connectSpec string) string {
	message = strings.ReplaceAll(message, "\x00", "")
	if connectSpec != "" {
		message = strings.ReplaceAll(message, connectSpec, "[REDACTED CONNECTION]")
	}
	message = credentialPattern.ReplaceAllString(message, `${1}/[REDACTED]@`)
	message = passwordPattern.ReplaceAllString(message, `${1}[REDACTED]`)

	var safeLines []string
	for _, rawLine := range strings.Split(message, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "connect ") {
			line = "connect [REDACTED]"
		}
		safeLines = append(safeLines, sanitizeEvidence(line))
	}
	safe := strings.Join(safeLines, " | ")
	if len(safe) > 1000 {
		safe = safe[:1000] + "..."
	}
	return safe
}

func sanitizeEvidence(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	return strings.TrimSpace(strings.Join(strings.Fields(value), " "))
}

func sanitizeFileComponent(value string) string {
	value = strings.ToLower(value)
	value = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, value)
	value = strings.Trim(value, "_")
	if value == "" {
		return "unknown"
	}
	if len(value) > 80 {
		return value[:80]
	}
	return value
}

func errorResult(code, description string, mitre MitreAttack, err error) CheckResult {
	message := "required Oracle evidence could not be collected"
	if err != nil {
		message = redactOracleError(err.Error(), "")
	}
	return CheckResult{
		Code:            code,
		Description:     description,
		Status:          StatusError,
		ProcessedConfig: "evaluation=error",
		ErrMsg:          message,
		MitreAttack:     mitre,
	}
}
