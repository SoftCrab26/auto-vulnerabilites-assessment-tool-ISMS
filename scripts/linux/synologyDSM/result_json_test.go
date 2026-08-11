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
		Status:           Vulnerable,
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
	for _, forbidden := range []string{"OS", "Item", "os", "dsm", "results", "generatedAt", "code", "rawConfig"} {
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
			t.Fatalf("missing MitreAttack key %q", key)
		}
	}

	var arr []CheckResult
	arrRaw, err := json.MarshalIndent([]CheckResult{in}, "", "  ")
	if err != nil {
		t.Fatalf("array marshal: %v", err)
	}
	if err := json.Unmarshal(arrRaw, &arr); err != nil || len(arr) != 1 || arr[0].Code != "U-01" {
		t.Fatalf("array roundtrip failed: %v %v", err, string(arrRaw))
	}
}
