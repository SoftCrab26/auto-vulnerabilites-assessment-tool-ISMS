package main

import (
	"errors"
	"strings"
	"testing"
)

func TestEvalD23AndD24AreOracleNotApplicable(t *testing.T) {
	tests := []struct {
		name string
		got  CheckResult
	}{
		{name: "D-23 xp_cmdshell", got: evalD23(loadD23Input(ScanContext{}))},
		{name: "D-24 registry procedure", got: evalD24(loadD24Input(ScanContext{}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got.Status != StatusNotApplicable {
				t.Fatalf("status = %s, want %s; result=%+v", tt.got.Status, StatusNotApplicable, tt.got)
			}
			if !strings.Contains(tt.got.RawConfig, "engine=Oracle") ||
				!strings.Contains(tt.got.RawConfig, "criterion=") {
				t.Fatalf("RawConfig must state engine and criterion: %+v", tt.got)
			}
		})
	}
}

func TestEvalD25ManualEvidenceAndNoCurrencyClaim(t *testing.T) {
	result := evalD25(D25Input{
		Version: "19.24.0.0.0 /private/build/version.txt",
		Patches: []D25Patch{{
			PatchID:     "36582781",
			Action:      "APPLY",
			Status:      "SUCCESS",
			ActionTime:  "2026-07-20T11:12:13",
			Description: "Database Release Update source /opt/oracle/build/secret",
		}},
		RawRows: [][]string{
			{"36582781", "APPLY", "SUCCESS", "2026-07-20T11:12:13", "Database Release Update source /opt/oracle/build/secret"},
		},
	})
	if result.Status != StatusManual {
		t.Fatalf("status = %s, want %s; result=%+v", result.Status, StatusManual, result)
	}
	for _, evidence := range []string{
		"PATCH_ID\tACTION\tSTATUS\tACTION_TIME\tDESCRIPTION",
		"36582781",
		"APPLY",
		"SUCCESS",
		"2026-07-20T11:12:13",
		"Database Release Update source",
	} {
		if !strings.Contains(result.RawConfig, evidence) {
			t.Errorf("RawConfig missing %q: %s", evidence, result.RawConfig)
		}
	}
	if !strings.Contains(result.ProcessedConfig, "36582781") {
		t.Fatalf("ProcessedConfig lacks patch evidence preview: %s", result.ProcessedConfig)
	}
	if strings.Contains(strings.ToLower(result.ProcessedConfig), "latest=true") {
		t.Fatalf("ProcessedConfig claimed patch currency: %s", result.ProcessedConfig)
	}
}

func TestEvalD25FailedLatestPatchIsVulnerable(t *testing.T) {
	result := evalD25(D25Input{
		Version: "19.24.0.0.0",
		Patches: []D25Patch{
			{
				PatchID:     "36582781",
				Action:      "APPLY",
				Status:      "FAILED",
				ActionTime:  "2026-07-20T11:12:13",
				Description: "Database Release Update",
			},
			{
				PatchID:     "35926646",
				Action:      "APPLY",
				Status:      "SUCCESS",
				ActionTime:  "2026-04-20T11:12:13",
				Description: "Earlier Database Release Update",
			},
		},
	})
	if result.Status != StatusVulnerable {
		t.Fatalf("status = %s, want %s; result=%+v", result.Status, StatusVulnerable, result)
	}
	if result.VulnerableConfig != "latest_patch_action_status=FAILED" {
		t.Fatalf("unexpected vulnerable evidence: %+v", result)
	}
}

func TestEvalD25ErrorsOnFailedOrMalformedEvidence(t *testing.T) {
	// Query failure is still Error; empty/malformed patch rows become Manual.
	if got := evalD25(D25Input{LoadErr: errors.New("query failed")}); got.Status != StatusError {
		t.Fatalf("load error status = %s, want %s; result=%+v", got.Status, StatusError, got)
	}
	for i, input := range []D25Input{
		{Version: "19.24.0.0.0"},
		{
			Version: "19.24.0.0.0",
			Patches: []D25Patch{{
				PatchID: "not-a-number", Action: "APPLY", Status: "SUCCESS",
				ActionTime: "2026-07-20T11:12:13", Description: "Release Update",
			}},
		},
	} {
		if got := evalD25(input); got.Status != StatusManual {
			t.Errorf("case %d status = %s, want %s; result=%+v", i, got.Status, StatusManual, got)
		}
	}
}

func TestEvalD2511gHistoryWithZeroOrBlankIDIsManual(t *testing.T) {
	result := evalD25(D25Input{
		Version:    "11.2.0.4.0",
		AllowEmpty: true,
		Patches: []D25Patch{{
			PatchID: "0", Action: "APPLY", Status: "SUCCESS",
			ActionTime: "2018-01-02T03:04:05", Description: "PSU /oracle/patch",
		}},
		RawRows: [][]string{
			{"0", "APPLY", "SUCCESS", "2018-01-02T03:04:05", "PSU /oracle/patch"},
		},
	})
	if result.Status != StatusManual {
		t.Fatalf("status = %s, want %s; result=%+v", result.Status, StatusManual, result)
	}
	if !strings.Contains(result.RawConfig, "0\tAPPLY\tSUCCESS") {
		t.Fatalf("expected raw patch row in table, got %s", result.RawConfig)
	}
	if !strings.Contains(result.ProcessedConfig, "0") || !strings.Contains(result.ProcessedConfig, "APPLY") {
		t.Fatalf("missing raw patch preview: %s", result.ProcessedConfig)
	}
}

func TestEvalD26ClearlyDisabledIsVulnerable(t *testing.T) {
	result := evalD26(D26Input{
		AuditTrail:                 "NONE",
		UnifiedAuditSGAQueueSize:   "1048576",
		UnifiedAuditingOption:      "FALSE",
		UnifiedEnabledPolicyCount:  "0",
		LegacyStatementOptionCount: "0",
		LegacyPrivilegeOptionCount: "0",
		LegacyObjectOptionCount:    "0",
	})
	if result.Status != StatusVulnerable {
		t.Fatalf("status = %s, want %s; result=%+v", result.Status, StatusVulnerable, result)
	}
}

func TestEvalD26EnabledReturnsManualEvidenceOnly(t *testing.T) {
	result := evalD26(D26Input{
		AuditTrail:                 "DB, EXTENDED",
		UnifiedAuditSGAQueueSize:   "1048576",
		UnifiedAuditingOption:      "TRUE",
		UnifiedEnabledPolicyCount:  "3",
		LegacyStatementOptionCount: "4",
		LegacyPrivilegeOptionCount: "2",
		LegacyObjectOptionCount:    "7",
		RawRows: [][]string{
			{"DB, EXTENDED", "1048576", "TRUE", "3", "4", "2", "7"},
		},
	})
	if result.Status != StatusManual {
		t.Fatalf("status = %s, want %s; result=%+v", result.Status, StatusManual, result)
	}
	for _, evidence := range []string{
		"AUDIT_TRAIL\tUNIFIED_AUDIT_SGA_QUEUE_SIZE",
		"DB, EXTENDED",
		"TRUE",
		"3",
		"4",
		"2",
		"7",
	} {
		if !strings.Contains(result.RawConfig, evidence) {
			t.Errorf("RawConfig missing %q: %s", evidence, result.RawConfig)
		}
	}
	for _, forbidden := range []string{"SELECT ", "username=", "password=", "event="} {
		if strings.Contains(strings.ToLower(result.RawConfig), strings.ToLower(forbidden)) {
			t.Fatalf("RawConfig exposed forbidden audit content %q: %s", forbidden, result.RawConfig)
		}
	}
	if !strings.Contains(result.ProcessedConfig, "DB, EXTENDED") {
		t.Fatalf("missing raw audit preview: %+v", result)
	}
}

func TestEvalD26MalformedOrMissingEvidenceIsError(t *testing.T) {
	tests := []D26Input{
		{LoadErr: errors.New("query failed")},
		{
			AuditTrail: "NONE", UnifiedAuditSGAQueueSize: "",
			UnifiedAuditingOption: "FALSE", UnifiedEnabledPolicyCount: "0",
			LegacyStatementOptionCount: "0", LegacyPrivilegeOptionCount: "0", LegacyObjectOptionCount: "0",
		},
		{
			AuditTrail: "UNKNOWN", UnifiedAuditSGAQueueSize: "1",
			UnifiedAuditingOption: "FALSE", UnifiedEnabledPolicyCount: "0",
			LegacyStatementOptionCount: "0", LegacyPrivilegeOptionCount: "0", LegacyObjectOptionCount: "0",
		},
	}
	for i, input := range tests {
		if got := evalD26(input); got.Status != StatusError {
			t.Errorf("case %d status = %s, want %s; result=%+v", i, got.Status, StatusError, got)
		}
	}
}
