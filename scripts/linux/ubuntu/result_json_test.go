package main

import (
	"encoding/json"
	"testing"
)

func TestCheckResultJSONMatchesWebUISchema(t *testing.T) {
	in := CheckResult{
		RawConfig:        "raw",
		VulnerableConfig: "vuln",
		ErrMsg:           "",
		Description:      "desc",
		Status:           StatusVulnerable,
		ProcessedConfig:  "proc",
		MitreAttack: MitreAttack{
			Tactic:      "Defense Evasion",
			Techniques:  []string{"T1078", "T1133"},
			Mitigations: []string{"M1042"},
		},
		Code: "U-01",
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	for _, key := range []string{
		"RawConfig", "VulnerableConfig", "ErrMsg", "Description",
		"Status", "ProcessedConfig", "MitreAttack", "Code",
	} {
		if _, ok := obj[key]; !ok {
			t.Fatalf("missing JSON key %q in %s", key, string(raw))
		}
	}
	for _, forbidden := range []string{"OS", "Item", "os", "item"} {
		if _, ok := obj[forbidden]; ok {
			t.Fatalf("unexpected JSON key %q in %s", forbidden, string(raw))
		}
	}

	var mitre map[string]json.RawMessage
	if err := json.Unmarshal(obj["MitreAttack"], &mitre); err != nil {
		t.Fatalf("mitre: %v", err)
	}
	for _, key := range []string{"tactic", "techniques", "mitigations"} {
		if _, ok := mitre[key]; !ok {
			t.Fatalf("missing MitreAttack key %q in %s", key, string(obj["MitreAttack"]))
		}
	}

	var roundtrip CheckResult
	if err := json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	if roundtrip.Code != "U-01" || roundtrip.Status != StatusVulnerable {
		t.Fatalf("roundtrip mismatch: %+v", roundtrip)
	}
	if roundtrip.MitreAttack.Tactic != "Defense Evasion" {
		t.Fatalf("mitre tactic = %q", roundtrip.MitreAttack.Tactic)
	}
}
