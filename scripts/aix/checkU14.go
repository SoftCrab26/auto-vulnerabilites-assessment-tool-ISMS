package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type auditFile struct {
	Path    string
	Content string
	Owner   string
	Mode    os.FileMode
	Exists  bool
	Err     string
}

func loadAuditFile(path string, content bool) auditFile {
	file := auditFile{Path: path}
	info, err := os.Stat(path)
	if err != nil {
		file.Err = err.Error()
		return file
	}
	file.Exists = true
	file.Mode = info.Mode()
	file.Owner, err = fileOwnerName(path)
	if err != nil {
		file.Err = err.Error()
	}
	if content && info.Mode().IsRegular() {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			file.Err = readErr.Error()
		} else {
			file.Content = string(data)
		}
	}
	return file
}

func auditFileSummary(file auditFile) string {
	if !file.Exists {
		return file.Path + " missing"
	}
	return fmt.Sprintf("%s owner=%s mode=%04o", file.Path, file.Owner, file.Mode.Perm())
}

func hasOnlyAllowedPermissions(mode, allowed os.FileMode) bool {
	return mode.Perm()&^allowed.Perm() == 0
}

func ownerAllowed(owner string, allowed ...string) bool {
	for _, candidate := range allowed {
		if owner == candidate {
			return true
		}
	}
	return false
}

func boundedRegularFiles(roots []string, limit int, match func(os.FileMode) bool) ([]auditFile, []string, bool) {
	var files []auditFile
	var errs []string
	visited := 0
	truncated := false
	for _, root := range roots {
		if visited >= limit {
			truncated = true
			break
		}
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				errs = append(errs, walkErr.Error())
				return nil
			}
			visited++
			if visited > limit {
				truncated = true
				return filepath.SkipAll
			}
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				errs = append(errs, err.Error())
				return nil
			}
			if !info.Mode().IsRegular() || !match(info.Mode()) {
				return nil
			}
			file := auditFile{Path: path, Mode: info.Mode(), Exists: true}
			file.Owner, err = fileOwnerName(path)
			if err != nil {
				file.Err = err.Error()
			}
			files = append(files, file)
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
		}
	}
	return files, errs, truncated
}

func inventoryRaw(files []auditFile) string {
	lines := make([]string, 0, len(files))
	for _, file := range files {
		lines = append(lines, auditFileSummary(file))
	}
	return strings.Join(lines, "\n")
}

type U14Input struct {
	Files []auditFile
}

func checkU14(ctx ScanContext) CheckResult {
	_ = ctx
	result := evalU14(loadU14Input())
	result.Code = "U-14"
	result.Description = "PATH must not contain the current-directory component '.'."
	result.MitreAttack = MitreAttack{Tactic: "Execution", Techniques: []string{"T1059"}, Mitigations: []string{"M1022"}}
	return result
}

func loadU14Input() U14Input {
	return U14Input{Files: []auditFile{
		loadAuditFile("/etc/environment", true),
		loadAuditFile("/etc/profile", true),
		loadAuditFile("/root/.profile", true),
	}}
}

func evalU14(input U14Input) CheckResult {
	var bad, raw, missing []string
	for index, file := range input.Files {
		if !file.Exists {
			if index < 2 {
				missing = append(missing, file.Path)
			}
			continue
		}
		raw = append(raw, "["+file.Path+"]\n"+file.Content)
		for _, line := range strings.Split(file.Content, "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			equal := strings.Index(line, "=")
			if equal < 0 || !strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line[:equal], "export ")), "PATH") {
				continue
			}
			value := strings.Trim(strings.TrimSpace(strings.SplitN(line[equal+1:], ";", 2)[0]), `"'`)
			for _, component := range strings.Split(value, ":") {
				if strings.TrimSpace(component) == "." {
					bad = append(bad, file.Path+": "+value)
					break
				}
			}
		}
	}
	status := StatusGood
	vulnerable := ""
	errMsg := ""
	if len(missing) > 0 {
		status = StatusError
		errMsg = "required PATH files missing: " + strings.Join(missing, ", ")
	} else if len(bad) > 0 {
		status = StatusVulnerable
		vulnerable = strings.Join(bad, "\n")
	}
	return CheckResult{
		Status: status, RawConfig: strings.Join(raw, "\n"),
		ProcessedConfig:  "path_files=" + strconv.Itoa(len(raw)) + " dot_entries=" + strconv.Itoa(len(bad)),
		VulnerableConfig: vulnerable, ErrMsg: errMsg,
	}
}
