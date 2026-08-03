package main

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	d13Description = "ODBC and OLE DB data-source inventory and business purpose require manual review."
	d13ReadLimit   = int64(64 * 1024)
)

var d13Mitre = MitreAttack{
	Tactic:      "Discovery",
	Techniques:  []string{"T1087"},
	Mitigations: []string{"M1018"},
}

type D13FileEvidence struct {
	Path     string
	Status   string
	Sections int
}

type D13Input struct {
	Files   []D13FileEvidence
	RawRows [][]string
}

func checkD13(ctx ScanContext) CheckResult {
	result := evalD13(loadD13Input())
	result.Code = "D-13"
	result.Description = d13Description
	result.MitreAttack = d13Mitre
	return result
}

func loadD13Input() D13Input {
	paths := []string{"/etc/odbc.ini", "/etc/odbcinst.ini", "/usr/local/etc/odbc.ini", "/usr/local/etc/odbcinst.ini"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".odbc.ini"))
	}
	seen := make(map[string]struct{})
	files := make([]D13FileEvidence, 0, len(paths))
	for _, path := range paths {
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		evidence := D13FileEvidence{Path: path}
		info, err := os.Stat(path)
		switch {
		case os.IsNotExist(err):
			evidence.Status = "absent"
		case err != nil:
			evidence.Status = "unavailable"
		case !info.Mode().IsRegular():
			evidence.Status = "not_regular"
		case info.Size() > d13ReadLimit:
			evidence.Status = "present_too_large"
		default:
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				evidence.Status = "present_unreadable"
			} else if int64(len(data)) > d13ReadLimit {
				evidence.Status = "present_too_large"
			} else {
				evidence.Status = "present_readable"
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
						evidence.Sections++
					}
				}
			}
		}
		files = append(files, evidence)
	}
	return D13Input{Files: files, RawRows: d13RawRows(files)}
}

func d13RawRows(files []D13FileEvidence) [][]string {
	rows := make([][]string, 0, len(files))
	for _, file := range files {
		rows = append(rows, []string{file.Path, file.Status})
	}
	return rows
}

func evalD13(input D13Input) CheckResult {
	rawRows := input.RawRows
	if rawRows == nil {
		rawRows = d13RawRows(input.Files)
	}
	rawConfig := formatSQLTable([]string{"PATH", "STATUS"}, rawRows)
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       rawConfig,
		ProcessedConfig: formatProcessedRaw(rawRows),
	}
}
