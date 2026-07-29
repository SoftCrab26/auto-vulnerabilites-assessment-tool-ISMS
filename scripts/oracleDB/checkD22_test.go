package main

import (
	"errors"
	"testing"
)

func TestEvalD22(t *testing.T) {
	tests := []struct {
		name  string
		input D22Input
		want  Status
	}{
		{name: "true is good", input: D22Input{ResourceLimit: "TRUE"}, want: StatusGood},
		{name: "false is vulnerable", input: D22Input{ResourceLimit: "FALSE"}, want: StatusVulnerable},
		{name: "missing is error", input: D22Input{}, want: StatusError},
		{name: "invalid is error", input: D22Input{ResourceLimit: "UNKNOWN"}, want: StatusError},
		{name: "query failure is error", input: D22Input{LoadErr: errors.New("query failed")}, want: StatusError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evalD22(tt.input)
			if got.Status != tt.want {
				t.Fatalf("status = %s, want %s; result=%+v", got.Status, tt.want, got)
			}
		})
	}
}
