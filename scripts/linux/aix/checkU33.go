package main

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

const (
	u33MaxVisited  = 5000
	u33MaxFindings = 100
)

type U33Input struct {
	Hidden    []string
	Visited   int
	Truncated bool
}

func checkU33(ctx ScanContext) CheckResult {
	const code = "U-33"
	const description = "Unnecessary or suspicious hidden files and directories should be reviewed."
	mitre := MitreAttack{Tactic: "Defense Evasion", Techniques: []string{"T1036"}, Mitigations: []string{"M1022"}}
	input, errs := loadU33Input()
	result := evalU33(input)
	result.Code, result.Description, result.MitreAttack = code, description, mitre
	return resultWithErrors(result, errs)
}

func loadU33Input() (U33Input, []string) {
	input := U33Input{}
	var errs []string
	stop := errors.New("inventory limit reached")
	for _, root := range []string{"/home", "/root"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				errs = append(errs, walkErr.Error())
				return nil
			}
			input.Visited++
			if input.Visited > u33MaxVisited || len(input.Hidden) >= u33MaxFindings {
				input.Truncated = true
				return stop
			}
			if path != root && strings.HasPrefix(entry.Name(), ".") {
				input.Hidden = append(input.Hidden, path)
			}
			return nil
		})
		if err != nil && !errors.Is(err, stop) {
			errs = append(errs, err.Error())
		}
		if input.Truncated {
			break
		}
	}
	return input, errs
}

func evalU33(input U33Input) CheckResult {
	return CheckResult{
		Status:          StatusInterview,
		RawConfig:       strings.Join(input.Hidden, "\n"),
		ProcessedConfig: buildProcessedConfig("hidden_entries="+strconvItoa(len(input.Hidden)), "visited="+strconvItoa(input.Visited), "truncated="+boolText(input.Truncated)),
	}
}

func strconvItoa(value int) string {
	if value == 0 {
		return "0"
	}
	const digits = "0123456789"
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = digits[value%10]
		value /= 10
	}
	return string(buffer[index:])
}
