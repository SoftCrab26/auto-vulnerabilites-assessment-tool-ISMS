package main

import (
	"strings"
	"testing"
)

func TestD16IsOracleNotApplicable(t *testing.T) {
	result := checkD16(ScanContext{})
	if result.Status != StatusNotApplicable {
		t.Fatalf("status = %s, want %s", result.Status, StatusNotApplicable)
	}
	if result.RawConfig != "engine=ORACLE; criterion=SQL_SERVER_ONLY" {
		t.Fatalf("RawConfig = %q", result.RawConfig)
	}
}

func TestEvalD17AuditObjectGrants(t *testing.T) {
	tests := []struct {
		name   string
		grants []D17Grant
		want   Status
	}{
		{name: "no grants", want: StatusGood},
		{
			name: "read grant requires review",
			grants: []D17Grant{{
				Grantee: "AUDITOR", Owner: "SYS", Object: "AUD$", Privilege: "SELECT",
			}},
			want: StatusManual,
		},
		{
			name: "write grant is vulnerable",
			grants: []D17Grant{{
				Grantee: "APP", Owner: "SYS", Object: "FGA_LOG$", Privilege: "DELETE",
			}},
			want: StatusVulnerable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalD17(D17Input{Grants: tt.grants}); got.Status != tt.want {
				t.Fatalf("status = %s, want %s; result=%+v", got.Status, tt.want, got)
			}
		})
	}
}

func TestEvalD18PublicGrants(t *testing.T) {
	tests := []struct {
		name   string
		grants []D18Grant
		want   Status
	}{
		{name: "no grants", want: StatusGood},
		{
			name: "ordinary grant requires review",
			grants: []D18Grant{{
				Kind: "OBJECT", Owner: "APP", Object: "LOOKUP", Privilege: "SELECT",
			}},
			want: StatusManual,
		},
		{
			name: "DBA role is dangerous",
			grants: []D18Grant{{
				Kind: "ROLE", Owner: "-", Object: "-", Privilege: "DBA",
			}},
			want: StatusVulnerable,
		},
		{
			name: "powerful package is dangerous",
			grants: []D18Grant{{
				Kind: "OBJECT", Owner: "SYS", Object: "DBMS_SCHEDULER", Privilege: "EXECUTE",
			}},
			want: StatusVulnerable,
		},
		{
			name: "ANY privilege is dangerous",
			grants: []D18Grant{{
				Kind: "SYSTEM", Owner: "-", Object: "-", Privilege: "CREATE ANY TABLE",
			}},
			want: StatusVulnerable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalD18(D18Input{Grants: tt.grants}); got.Status != tt.want {
				t.Fatalf("status = %s, want %s; result=%+v", got.Status, tt.want, got)
			}
		})
	}
}

func TestEvalD20ObjectOwners(t *testing.T) {
	manual := evalD20(D20Input{
		Owners: []D20Owner{{
			Owner: "APP_OWNER", ObjectCount: 12, OracleMaintained: "N", AccountStatus: "OPEN",
		}},
		RawRows: [][]string{{"APP_OWNER", "12", "N", "OPEN"}},
	})
	if manual.Status != StatusManual || !strings.Contains(manual.RawConfig, "APP_OWNER\t12\tN\tOPEN") {
		t.Fatalf("custom owner result = %+v", manual)
	}

	vulnerable := evalD20(D20Input{
		Owners: []D20Owner{{
			Owner: "HR", ObjectCount: 34, OracleMaintained: "N", AccountStatus: "OPEN",
		}},
		RawRows: [][]string{{"HR", "34", "N", "OPEN"}},
	})
	if vulnerable.Status != StatusVulnerable {
		t.Fatalf("open sample schema status = %s, want %s", vulnerable.Status, StatusVulnerable)
	}
}

func TestEvalD21DelegableGrants(t *testing.T) {
	tests := []struct {
		name   string
		grants []D21Grant
		want   Status
	}{
		{name: "no grants", want: StatusGood},
		{
			name: "specific delegation requires approval review",
			grants: []D21Grant{{
				Kind: "OBJECT", Grantee: "APP_ADMIN", Owner: "APP", Object: "ORDERS", Privilege: "SELECT",
			}},
			want: StatusManual,
		},
		{
			name: "PUBLIC delegation is broad",
			grants: []D21Grant{{
				Kind: "OBJECT", Grantee: "PUBLIC", Owner: "APP", Object: "ORDERS", Privilege: "SELECT",
			}},
			want: StatusVulnerable,
		},
		{
			name: "ANY delegation is broad",
			grants: []D21Grant{{
				Kind: "SYSTEM", Grantee: "APP_ADMIN", Owner: "-", Object: "-", Privilege: "SELECT ANY TABLE",
			}},
			want: StatusVulnerable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalD21(D21Input{Grants: tt.grants}); got.Status != tt.want {
				t.Fatalf("status = %s, want %s; result=%+v", got.Status, tt.want, got)
			}
		})
	}
}

func TestManualEvidenceIsSanitized(t *testing.T) {
	result := evalD21(D21Input{
		Grants: []D21Grant{{
			Kind: "OBJECT", Grantee: "APP\nADMIN", Owner: "APP", Object: "ORDERS", Privilege: "SELECT",
		}},
		RawRows: [][]string{{"OBJECT", "APP\nADMIN", "APP", "ORDERS", "SELECT"}},
	})
	if result.Status != StatusManual {
		t.Fatalf("status = %s, want %s", result.Status, StatusManual)
	}
	if strings.Contains(result.RawConfig, "APP\nADMIN") {
		t.Fatalf("RawConfig was not sanitized: %q", result.RawConfig)
	}
	if !strings.Contains(result.RawConfig, "APP ADMIN") {
		t.Fatalf("RawConfig missing normalized grantee: %q", result.RawConfig)
	}
}
