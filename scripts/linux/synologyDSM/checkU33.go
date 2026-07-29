package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type U33Input struct {
	Entries   []string
	Truncated bool
}

func checkU33(ctx ScanContext) CheckResult {
	input, errs := loadU33Input(ctx)
	result := evalU33(input)
	result.Code = "U-33"
	result.Description = "Hidden files and directories should be reviewed for necessity."
	return resultWithErrors(result, errs)
}

func loadU33Input(_ ScanContext) (U33Input, []string) {
	const limit = 100
	input := U33Input{}
	var errs []string
	for _, root := range []string{"/root", "/var/services/homes"} {
		if len(input.Entries) >= limit {
			input.Truncated = true
			break
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				errs = append(errs, path+": "+err.Error())
				return nil
			}
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				input.Entries = append(input.Entries, path)
				if len(input.Entries) >= limit {
					input.Truncated = true
					return fs.SkipAll
				}
				if entry.IsDir() {
					return fs.SkipDir
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, root+": "+err.Error())
		}
	}
	return input, errs
}

func evalU33(input U33Input) CheckResult {
	processed := "hidden_entries_reviewed=" + dsmU33Count(input.Entries)
	if input.Truncated {
		processed += " truncated=true"
	}
	return CheckResult{
		Status:          Manual,
		RawConfig:       strings.Join(input.Entries, "\n"),
		ProcessedConfig: processed,
	}
}

func dsmU33Count(entries []string) string {
	const digits = "0123456789"
	n := len(entries)
	if n < 10 {
		return digits[n : n+1]
	}
	return dsmU33Count(entries[:n/10]) + digits[n%10:n%10+1]
}
