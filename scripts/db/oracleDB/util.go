package main

import (
	"errors"
	"fmt"
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

// rawTableCell keeps query cell text as close to sqlplus output as possible.
// Only characters that would break a single-line TSV row are normalized.
func rawTableCell(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	return value
}

// formatSQLTable renders SELECT-style evidence as a header + tab-separated rows,
// similar to looking at the raw command result rather than key=value summaries.
func formatSQLTable(headers []string, rows [][]string) string {
	var b strings.Builder
	if len(headers) > 0 {
		b.WriteString(strings.Join(headers, "\t"))
		b.WriteByte('\n')
	}
	if len(rows) == 0 {
		b.WriteString("(no rows selected)")
		return b.String()
	}
	width := len(headers)
	for i, row := range rows {
		if width == 0 {
			width = len(row)
		}
		cells := make([]string, width)
		for j := 0; j < width; j++ {
			if j < len(row) {
				cells[j] = rawTableCell(row[j])
			}
		}
		b.WriteString(strings.Join(cells, "\t"))
		if i < len(rows)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// formatProcessedRaw is a one-line console preview of raw table evidence:
// the first data row as TSV, optionally prefixed with the total row count.
// It intentionally avoids key=value judgment summaries.
func formatProcessedRaw(rows [][]string) string {
	if len(rows) == 0 {
		return "(no rows selected)"
	}
	width := len(rows[0])
	cells := make([]string, width)
	for j := 0; j < width; j++ {
		cells[j] = rawTableCell(rows[0][j])
	}
	line := strings.Join(cells, "\t")
	if len(rows) == 1 {
		return line
	}
	return fmt.Sprintf("(%d rows)\t%s", len(rows), line)
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
