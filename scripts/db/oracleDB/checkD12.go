package main

import (
	"context"
	"errors"
	"sort"
	"strings"
)

const d12Description = "Listener password controls are legacy and version-dependent and require host-side authentication review."

var d12Mitre = MitreAttack{
	Tactic:      "Credential Access",
	Techniques:  []string{"T1552"},
	Mitigations: []string{"M1027"},
}

type D12Input struct {
	Version    string
	Parameters map[string]bool
	LoadErr    error
}

func checkD12(ctx ScanContext) CheckResult {
	result := evalD12(loadD12Input(ctx))
	result.Code = "D-12"
	result.Description = d12Description
	result.MitreAttack = d12Mitre
	return result
}

func loadD12Input(scanCtx ScanContext) D12Input {
	if scanCtx.MetadataErr != nil {
		return D12Input{LoadErr: scanCtx.MetadataErr}
	}
	const query = `SELECT 'VERSION' || '|~|' || version || '|~|' || 'AVAILABLE'
FROM v$instance
UNION ALL
SELECT 'PARAMETER' || '|~|' || name || '|~|' ||
       CASE WHEN value IS NULL OR TRIM(value) IS NULL THEN 'UNSET' ELSE 'CONFIGURED' END
FROM v$parameter
WHERE name IN ('local_listener', 'remote_listener', 'listener_networks')
ORDER BY 1;`

	rows, err := scanCtx.Runner.Query(context.Background(), query)
	if err != nil {
		return D12Input{LoadErr: err}
	}
	input := D12Input{Parameters: make(map[string]bool)}
	for _, row := range rows {
		if len(row) != 3 {
			return D12Input{LoadErr: errors.New("D-12 query returned an unexpected row shape")}
		}
		switch strings.ToUpper(strings.TrimSpace(row[0])) {
		case "VERSION":
			if input.Version != "" {
				return D12Input{LoadErr: errors.New("D-12 query returned duplicate version evidence")}
			}
			input.Version = sanitizeEvidence(row[1])
		case "PARAMETER":
			state := strings.ToUpper(strings.TrimSpace(row[2]))
			if state != "CONFIGURED" && state != "UNSET" {
				return D12Input{LoadErr: errors.New("D-12 query returned an unexpected parameter state")}
			}
			input.Parameters[strings.ToLower(strings.TrimSpace(row[1]))] = state == "CONFIGURED"
		default:
			return D12Input{LoadErr: errors.New("D-12 query returned an unexpected evidence type")}
		}
	}
	return input
}

func evalD12(input D12Input) CheckResult {
	if input.LoadErr != nil {
		return errorResult("D-12", d12Description, d12Mitre, input.LoadErr)
	}
	if strings.TrimSpace(input.Version) == "" {
		return errorResult("D-12", d12Description, d12Mitre, errors.New("listener version or parameter evidence is missing"))
	}
	evidence := []string{"database_version=" + sanitizeEvidence(input.Version)}
	for _, name := range []string{"listener_networks", "local_listener", "remote_listener"} {
		configured, ok := input.Parameters[name]
		if !ok {
			return errorResult("D-12", d12Description, d12Mitre, errors.New("listener version or parameter evidence is missing"))
		}
		state := "unset"
		if configured {
			state = "configured"
		}
		evidence = append(evidence, sanitizeEvidence(name)+"="+state)
	}
	sort.Strings(evidence)
	return CheckResult{
		Status:          StatusManual,
		RawConfig:       strings.Join(evidence, ", "),
		ProcessedConfig: "review=listener password criterion is legacy/version-dependent; inspect listener.ora and confirm current listener administration uses OS authentication with appropriately restricted file and service ownership",
	}
}
