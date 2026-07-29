package main

import (
	"errors"
	"strings"
	"testing"
)

func TestEvalD19(t *testing.T) {
	tests := []struct {
		name  string
		input D19Input
		want  Status
	}{
		{
			name: "all false is good",
			input: D19Input{Parameters: map[string]string{
				"os_roles": "FALSE", "remote_os_authent": "FALSE", "remote_os_roles": "FALSE",
			}},
			want: StatusGood,
		},
		{
			name: "any true is vulnerable",
			input: D19Input{Parameters: map[string]string{
				"os_roles": "FALSE", "remote_os_authent": "TRUE", "remote_os_roles": "FALSE",
			}},
			want: StatusVulnerable,
		},
		{
			name: "missing is error",
			input: D19Input{Parameters: map[string]string{
				"os_roles": "FALSE", "remote_os_roles": "FALSE",
			}},
			want: StatusError,
		},
		{
			name:  "query failure is error",
			input: D19Input{LoadErr: errors.New("ORA-00942: view unavailable")},
			want:  StatusError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalD19(tt.input)
			if got.Status != tt.want {
				t.Fatalf("status = %s, want %s; result=%+v", got.Status, tt.want, got)
			}
		})
	}
}

func TestEvalD19ReportsOnlySanitizedEvidence(t *testing.T) {
	result := evalD19(D19Input{Parameters: map[string]string{
		"os_roles": "FALSE", "remote_os_authent": "TRUE", "remote_os_roles": "FALSE",
	}})
	if !strings.Contains(result.VulnerableConfig, "remote_os_authent=TRUE") {
		t.Fatalf("missing vulnerable parameter evidence: %+v", result)
	}
}
