package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type d01D07Runner struct {
	rows  [][]string
	err   error
	query string
}

func (r *d01D07Runner) Query(_ context.Context, query string) ([][]string, error) {
	r.query = query
	return r.rows, r.err
}

func TestEvalD01ThroughD07(t *testing.T) {
	tests := []struct {
		name       string
		eval       func() CheckResult
		want       Status
		manualRaw  bool
		wantConfig string
	}{
		{"D01 no default passwords", func() CheckResult { return evalD01(D01Input{}) }, StatusGood, false, "(no rows selected)"},
		{"D01 default password", func() CheckResult {
			return evalD01(D01Input{
				Accounts: []string{"username=SCOTT, account_status=OPEN"},
				RawRows:  [][]string{{"SCOTT", "OPEN"}},
			})
		}, StatusVulnerable, false, "SCOTT"},
		{"D01 query error", func() CheckResult {
			return evalD01(D01Input{LoadErr: errors.New("query failed")})
		}, StatusError, false, ""},
		{"D02 open sample account", func() CheckResult {
			return evalD02(D02Input{
				Accounts: []D02Account{{Username: "HR", AccountStatus: "OPEN", OracleMaintained: "N"}},
				RawRows:  [][]string{{"HR", "OPEN", "N"}},
			})
		}, StatusVulnerable, false, "HR"},
		{"D02 inventory needs purpose review", func() CheckResult {
			return evalD02(D02Input{
				Accounts: []D02Account{{Username: "APP", AccountStatus: "OPEN", OracleMaintained: "N"}},
				RawRows:  [][]string{{"APP", "OPEN", "N"}},
			})
		}, StatusManual, true, "APP"},
		{"D02 missing inventory", func() CheckResult { return evalD02(D02Input{}) }, StatusError, false, ""},
		{"D03 disabled lifetime", func() CheckResult {
			return evalD03(D03Input{
				Settings: []D03Setting{{Profile: "DEFAULT", Resource: "PASSWORD_LIFE_TIME", Limit: "UNLIMITED"}},
				RawRows:  [][]string{{"DEFAULT", "PASSWORD_LIFE_TIME", "UNLIMITED"}},
			})
		}, StatusVulnerable, false, "UNLIMITED"},
		{"D03 thresholds need policy", func() CheckResult {
			return evalD03(D03Input{
				Settings: []D03Setting{{Profile: "DEFAULT", Resource: "PASSWORD_LIFE_TIME", Limit: "90"}},
				RawRows:  [][]string{{"DEFAULT", "PASSWORD_LIFE_TIME", "90"}},
			})
		}, StatusManual, true, "90"},
		{"D03 missing settings", func() CheckResult { return evalD03(D03Input{}) }, StatusError, false, ""},
		{"D04 grants need allowed list", func() CheckResult {
			return evalD04(D04Input{
				Grants:  []D04Grant{{Source: "DBA_ROLE_PRIVS", Grantee: "ADMIN1", Privilege: "DBA"}},
				RawRows: [][]string{{"DBA_ROLE_PRIVS", "ADMIN1", "DBA"}},
			})
		}, StatusManual, true, "ADMIN1"},
		{"D04 missing grants", func() CheckResult { return evalD04(D04Input{}) }, StatusError, false, ""},
		{"D05 both unlimited", func() CheckResult {
			return evalD05(D05Input{
				Profiles: []D05Profile{{Name: "DEFAULT", ReuseMax: "UNLIMITED", ReuseTime: "UNLIMITED"}},
				RawRows:  [][]string{{"DEFAULT", "UNLIMITED", "UNLIMITED"}},
			})
		}, StatusVulnerable, false, "effective_password_reuse_max=UNLIMITED"},
		{"D05 one finite restriction", func() CheckResult {
			return evalD05(D05Input{
				Profiles: []D05Profile{{Name: "DEFAULT", ReuseMax: "5", ReuseTime: "UNLIMITED"}},
				RawRows:  [][]string{{"DEFAULT", "5", "UNLIMITED"}},
			})
		}, StatusGood, false, ""},
		{"D05 resolved default inheritance", func() CheckResult {
			return evalD05(D05Input{
				Profiles: []D05Profile{
					{Name: "DEFAULT", ReuseMax: "5", ReuseTime: "UNLIMITED"},
					{Name: "APP", ReuseMax: "DEFAULT", ReuseTime: "DEFAULT"},
				},
				RawRows: [][]string{
					{"DEFAULT", "5", "UNLIMITED"},
					{"APP", "DEFAULT", "DEFAULT"},
				},
			})
		}, StatusGood, false, ""},
		{"D05 unresolved default inheritance", func() CheckResult {
			return evalD05(D05Input{
				Profiles: []D05Profile{{Name: "APP", ReuseMax: "DEFAULT", ReuseTime: "DEFAULT"}},
				RawRows:  [][]string{{"APP", "DEFAULT", "DEFAULT"}},
			})
		}, StatusManual, true, "DEFAULT"},
		{"D05 missing profiles", func() CheckResult { return evalD05(D05Input{}) }, StatusError, false, ""},
		{"D06 account ownership review", func() CheckResult {
			return evalD06(D06Input{
				Accounts: []D06Account{{
					Username: "APP", AccountStatus: "OPEN", LastLogin: "2026-07-29T01:02:03 +00:00",
					Profile: "DEFAULT", AuthenticationType: "PASSWORD",
				}},
				RawRows: [][]string{{"APP", "OPEN", "2026-07-29T01:02:03 +00:00", "DEFAULT", "PASSWORD"}},
			})
		}, StatusManual, true, "APP"},
		{"D06 missing inventory", func() CheckResult { return evalD06(D06Input{}) }, StatusError, false, ""},
		{"D07 root process", func() CheckResult {
			return evalD07(D07Input{
				Processes: []D07Process{{OSUser: "root", Program: "oracle"}},
				RawRows:   [][]string{{"root", "oracle"}},
			})
		}, StatusVulnerable, false, "root"},
		{"D07 host corroboration", func() CheckResult {
			return evalD07(D07Input{
				Processes: []D07Process{{OSUser: "oracle", Program: "oracle"}},
				RawRows:   [][]string{{"oracle", "oracle"}},
			})
		}, StatusManual, true, "oracle"},
		{"D07 missing processes", func() CheckResult { return evalD07(D07Input{}) }, StatusError, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.eval()
			if got.Status != tt.want {
				t.Fatalf("status = %s, want %s; result=%+v", got.Status, tt.want, got)
			}
			if tt.manualRaw && strings.TrimSpace(got.RawConfig) == "" {
				t.Fatalf("manual result has no actual evidence: %+v", got)
			}
			if tt.wantConfig != "" && !strings.Contains(got.RawConfig+got.VulnerableConfig, tt.wantConfig) {
				t.Fatalf("result does not contain %q: %+v", tt.wantConfig, got)
			}
		})
	}
}

func TestD01ThroughD07QueriesAreDelimitedAndSecretFree(t *testing.T) {
	tests := []struct {
		name string
		rows [][]string
		load func(ScanContext)
	}{
		{"D01", nil, func(ctx ScanContext) { _ = loadD01Input(ctx) }},
		{"D02", [][]string{{"APP", "OPEN", "N"}}, func(ctx ScanContext) { _ = loadD02Input(ctx) }},
		{"D03", [][]string{{"DEFAULT", "PASSWORD_LIFE_TIME", "90"}}, func(ctx ScanContext) { _ = loadD03Input(ctx) }},
		{"D04", [][]string{{"DBA_ROLE_PRIVS", "ADMIN1", "DBA"}}, func(ctx ScanContext) { _ = loadD04Input(ctx) }},
		{"D05", [][]string{{"DEFAULT", "5", "UNLIMITED"}}, func(ctx ScanContext) { _ = loadD05Input(ctx) }},
		{"D06", [][]string{{"APP", "OPEN", "NEVER", "DEFAULT", "PASSWORD"}}, func(ctx ScanContext) { _ = loadD06Input(ctx) }},
		{"D07", [][]string{{"oracle", "oracle"}}, func(ctx ScanContext) { _ = loadD07Input(ctx) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &d01D07Runner{rows: tt.rows}
			tt.load(ScanContext{Runner: runner})
			lowerQuery := strings.ToLower(runner.query)
			if !strings.Contains(runner.query, sqlColumnSeparator) {
				t.Fatalf("query does not emit delimited columns: %s", runner.query)
			}
			for _, forbidden := range []string{"password_hash", "spare4", "verifier", "connect "} {
				if strings.Contains(lowerQuery, forbidden) {
					t.Fatalf("query contains forbidden secret-bearing term %q: %s", forbidden, runner.query)
				}
			}
		})
	}
}

func TestD01ThroughD07EvidenceSanitizationAndErrorRedaction(t *testing.T) {
	manual := evalD02(D02Input{
		Accounts: []D02Account{{
			Username: "APP\nUSER", AccountStatus: "OPEN\t", OracleMaintained: "N",
		}},
		RawRows: [][]string{{"APP\nUSER", "OPEN\t", "N"}},
	})
	if manual.Status != StatusManual {
		t.Fatalf("manual evidence was not sanitized: %+v", manual)
	}
	if strings.Contains(manual.RawConfig, "APP\nUSER") || strings.Contains(manual.RawConfig, "OPEN\t") {
		t.Fatalf("control characters leaked into table cells: %+v", manual)
	}
	if !strings.Contains(manual.RawConfig, "APP USER") {
		t.Fatalf("expected normalized table cell in RawConfig: %+v", manual)
	}

	result := evalD07(D07Input{LoadErr: errors.New("connect app/SuperSecret@prod\npassword=AnotherSecret")})
	serialized := result.ErrMsg + result.RawConfig + result.VulnerableConfig
	if strings.Contains(serialized, "SuperSecret") || strings.Contains(serialized, "AnotherSecret") {
		t.Fatalf("secret leaked in result: %+v", result)
	}
}
