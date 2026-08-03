package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type focusedRunner struct {
	rows  [][]string
	err   error
	query string
}

func (r *focusedRunner) Query(_ context.Context, query string) ([][]string, error) {
	r.query = query
	return r.rows, r.err
}

func TestD08ThroughD15Evaluations(t *testing.T) {
	t.Run("D08 legacy verifier", func(t *testing.T) {
		got := evalD08(D08Input{
			Accounts: []D08Account{
				{Username: "APP", PasswordVersions: "11G 12C"},
				{Username: "LEGACY", PasswordVersions: "10G 11G"},
			},
			RawRows: [][]string{
				{"APP", "11G 12C"},
				{"LEGACY", "10G 11G"},
			},
		})
		if got.Status != StatusVulnerable || !strings.Contains(got.VulnerableConfig, "LEGACY=10G") {
			t.Fatalf("unexpected D-08 result: %+v", got)
		}
		if evalD08(D08Input{}).Status != StatusError {
			t.Fatal("empty D-08 evidence must be Error")
		}
	})

	t.Run("D09 profile resolution", func(t *testing.T) {
		good := evalD09(D09Input{Profiles: []D09Profile{{Profile: "APP", Declared: "5", Resolved: "5"}}})
		if good.Status != StatusGood {
			t.Fatalf("finite D-09 value should be Good: %+v", good)
		}
		manual := evalD09(D09Input{
			Profiles: []D09Profile{{Profile: "APP", Declared: "DEFAULT", Resolved: "DEFAULT"}},
			RawRows:  [][]string{{"APP", "DEFAULT", "DEFAULT"}},
		})
		if manual.Status != StatusManual || manual.RawConfig == "" || !strings.Contains(manual.ProcessedConfig, "APP") {
			t.Fatalf("unresolved D-09 DEFAULT should be Manual with evidence: %+v", manual)
		}
		vulnerable := evalD09(D09Input{Profiles: []D09Profile{{Profile: "APP", Declared: "UNLIMITED", Resolved: "UNLIMITED"}}})
		if vulnerable.Status != StatusVulnerable {
			t.Fatalf("UNLIMITED D-09 value should be Vulnerable: %+v", vulnerable)
		}
	})

	t.Run("D10 manual review", func(t *testing.T) {
		got := evalD10(D10Input{
			Parameters: map[string]bool{
				"local_listener": true, "remote_listener": false, "listener_networks": true,
			},
			RawRows: [][]string{
				{"local_listener", "CONFIGURED"},
				{"remote_listener", "UNSET"},
				{"listener_networks", "CONFIGURED"},
			},
		})
		if got.Status != StatusManual || got.RawConfig == "" || !strings.Contains(got.ProcessedConfig, "local_listener") {
			t.Fatalf("D-10 should require manual review with evidence: %+v", got)
		}
		if strings.Contains(got.RawConfig, "(") || strings.Contains(got.RawConfig, "HOST=") {
			t.Fatalf("D-10 exposed a connect specification: %+v", got)
		}
	})

	t.Run("D11 risky grants", func(t *testing.T) {
		if evalD11(D11Input{}).Status != StatusGood {
			t.Fatal("no D-11 grants should be Good")
		}
		got := evalD11(D11Input{
			Grants: []D11Grant{{
				Owner: "SYS", Object: "SENSITIVE_VIEW", Grantee: "PUBLIC", Privilege: "SELECT",
			}},
			RawRows: [][]string{{"SYS", "SENSITIVE_VIEW", "PUBLIC", "SELECT"}},
		})
		if got.Status != StatusVulnerable || got.VulnerableConfig == "" {
			t.Fatalf("risky D-11 grant should be Vulnerable: %+v", got)
		}
	})

	t.Run("D12 version dependent", func(t *testing.T) {
		got := evalD12(D12Input{
			Version: "19.0.0.0.0",
			Parameters: map[string]bool{
				"local_listener": true, "remote_listener": false, "listener_networks": false,
			},
			RawRows: [][]string{
				{"VERSION", "19.0.0.0.0", "AVAILABLE"},
				{"PARAMETER", "local_listener", "CONFIGURED"},
				{"PARAMETER", "remote_listener", "UNSET"},
				{"PARAMETER", "listener_networks", "UNSET"},
			},
		})
		if got.Status != StatusManual || got.RawConfig == "" ||
			!strings.Contains(got.ProcessedConfig, "19.0.0.0.0") {
			t.Fatalf("D-12 should provide manual-review evidence: %+v", got)
		}
	})

	t.Run("D13 inventory purpose review", func(t *testing.T) {
		got := evalD13(D13Input{
			Files: []D13FileEvidence{
				{Path: "/etc/odbc.ini", Status: "present_readable", Sections: 2},
				{Path: "/etc/odbcinst.ini", Status: "absent"},
			},
			RawRows: [][]string{
				{"/etc/odbc.ini", "present_readable"},
				{"/etc/odbcinst.ini", "absent"},
			},
		})
		if got.Status != StatusManual || !strings.Contains(got.RawConfig, "PATH\tSTATUS") ||
			!strings.Contains(got.RawConfig, "present_readable") ||
			!strings.Contains(got.ProcessedConfig, "/etc/odbc.ini") {
			t.Fatalf("D-13 should be Manual with inventory evidence: %+v", got)
		}
	})

	t.Run("D14 fixed path permissions", func(t *testing.T) {
		vulnerable := evalD14(D14Input{
			OracleHome: "/oracle",
			Paths: []D14PathEvidence{
				{Path: "/oracle/network/admin/sqlnet.ora", Status: "present", Mode: 0o664},
			},
			RawRows: [][]string{{"/oracle/network/admin/sqlnet.ora", "present", "0664"}},
		})
		if vulnerable.Status != StatusVulnerable {
			t.Fatalf("writable D-14 path should be Vulnerable: %+v", vulnerable)
		}
		good := evalD14(D14Input{
			OracleHome: "/oracle",
			Paths: []D14PathEvidence{
				{Path: "/oracle/network/admin/sqlnet.ora", Status: "present", Mode: 0o640},
			},
			RawRows: [][]string{{"/oracle/network/admin/sqlnet.ora", "present", "0640"}},
		})
		if good.Status != StatusGood {
			t.Fatalf("secure D-14 evidence should be Good: %+v", good)
		}
		if evalD14(D14Input{}).Status != StatusManual {
			t.Fatal("missing ORACLE_HOME should make D-14 Manual")
		}
	})

	t.Run("D15 listener diagnostics permissions", func(t *testing.T) {
		vulnerable := evalD15(D15Input{
			OracleBase: "/oracle/base",
			Paths: []D15PathEvidence{
				{Path: "/oracle/base/diag/tnslsnr/host/listener/trace/listener.log", Status: "present", Mode: 0o666},
			},
			RawRows: [][]string{{"/oracle/base/diag/tnslsnr/host/listener/trace/listener.log", "present", "0666"}},
		})
		if vulnerable.Status != StatusVulnerable {
			t.Fatalf("writable D-15 path should be Vulnerable: %+v", vulnerable)
		}
		good := evalD15(D15Input{
			OracleHome: "/oracle",
			Paths: []D15PathEvidence{
				{Path: "/oracle/network/log/listener.log", Status: "present", Mode: 0o640},
			},
			RawRows: [][]string{{"/oracle/network/log/listener.log", "present", "0640"}},
		})
		if good.Status != StatusGood {
			t.Fatalf("secure D-15 evidence should be Good: %+v", good)
		}
		if evalD15(D15Input{}).Status != StatusManual {
			t.Fatal("unavailable D-15 evidence should be Manual")
		}
	})
}

func TestD08QueryCollectsVersionsNotVerifierValues(t *testing.T) {
	runner := &focusedRunner{rows: [][]string{{"APP", "11G 12C"}}}
	input := loadD08Input(ScanContext{Runner: runner})
	if input.LoadErr != nil {
		t.Fatalf("loadD08Input returned error: %v", input.LoadErr)
	}
	query := strings.ToUpper(runner.query)
	if !strings.Contains(query, "PASSWORD_VERSIONS") || strings.Contains(query, "PASSWORD_HASH") ||
		strings.Contains(query, "SPARE4") || strings.Contains(query, "DBA_USERS.PASSWORD") {
		t.Fatalf("D-08 query may expose verifier material: %s", runner.query)
	}
}

func TestD08ThroughD12QueryFailuresAreErrors(t *testing.T) {
	failure := errors.New("query failed")
	tests := []struct {
		name string
		got  CheckResult
	}{
		{"D08", evalD08(D08Input{LoadErr: failure})},
		{"D09", evalD09(D09Input{LoadErr: failure})},
		{"D10", evalD10(D10Input{LoadErr: failure})},
		{"D11", evalD11(D11Input{LoadErr: failure})},
		{"D12", evalD12(D12Input{LoadErr: failure})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got.Status != StatusError {
				t.Fatalf("query failure status = %s, want Error", test.got.Status)
			}
		})
	}
}
