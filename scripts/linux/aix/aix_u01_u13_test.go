package main

import (
	"os"
	"strings"
	"testing"
)

func TestAIXU01ThroughU13Evaluators(t *testing.T) {
	passwdGood := "root:!:0:0::/:/usr/bin/ksh\nuser:!:100:100::/home/user:/usr/bin/ksh\n"
	tests := []struct {
		name string
		got  CheckResult
		want Status
	}{
		{"U01 good", evalU01(U01Input{SSHConfig: "PermitRootLogin no\n", SecurityUser: "root:\n rlogin = false\n"}), StatusGood},
		{"U01 missing rlogin", evalU01(U01Input{SSHConfig: "PermitRootLogin no\n", SecurityUser: "root:\n"}), StatusVulnerable},
		{"U02 good", evalU02(U02Input{SecurityUser: "default:\n minlen = 8\n minalpha = 1\n minother = 1\n"}), StatusGood},
		{"U02 weak", evalU02(U02Input{SecurityUser: "default:\n minlen = 7\n minalpha = 1\n minother = 1\n"}), StatusVulnerable},
		{"U03 lower bound", evalU03(U03Input{SecurityUser: "default:\n loginretries = 1\n"}), StatusGood},
		{"U03 out of range", evalU03(U03Input{SecurityUser: "default:\n loginretries = 11\n"}), StatusVulnerable},
		{"U04 good", evalU04(U04Input{Files: []U04File{{Path: "/etc/passwd", Mode: 0644, Owner: "root", Exists: true}, {Path: "/etc/security/passwd", Mode: 0600, Owner: "root", Exists: true}}}), StatusGood},
		{"U04 exposed security passwd", evalU04(U04Input{Files: []U04File{{Path: "/etc/passwd", Mode: 0644, Owner: "root", Exists: true}, {Path: "/etc/security/passwd", Mode: 0640, Owner: "root", Exists: true}}}), StatusVulnerable},
		{"U05 good", evalU05(U05Input{Passwd: passwdGood}), StatusGood},
		{"U05 duplicate root identity", evalU05(U05Input{Passwd: passwdGood + "toor:!:0:0::/:/usr/bin/ksh\n"}), StatusVulnerable},
		{"U06 restricted", evalU06(U06Input{SecurityUser: "root:\n sugroups = security\n"}), StatusGood},
		{"U06 unrestricted", evalU06(U06Input{SecurityUser: "root:\n sugroups = ALL\n"}), StatusVulnerable},
		{"U07 disabled guest", evalU07(U07Input{Passwd: "guest:!:200:200::/:/bin/false\n"}), StatusGood},
		{"U07 login guest", evalU07(U07Input{Passwd: "guest:!:200:200::/:/usr/bin/ksh\n"}), StatusVulnerable},
		{"U08 root only", evalU08(U08Input{Group: "system:!:0:root\n"}), StatusGood},
		{"U08 additional admin", evalU08(U08Input{Group: "system:!:0:root,alice\n"}), StatusInterview},
		{"U09 ambiguous unused group", evalU09(U09Input{Group: "uucp:!:5:\n", Passwd: passwdGood}), StatusInterview},
		{"U09 used group", evalU09(U09Input{Group: "uucp:!:5:\n", Passwd: passwdGood + "uucp:!:5:5::/:/bin/false\n"}), StatusGood},
		{"U10 unique", evalU10(U10Input{Passwd: passwdGood}), StatusGood},
		{"U10 duplicate", evalU10(U10Input{Passwd: passwdGood + "other:!:100:200::/:/usr/bin/ksh\n"}), StatusVulnerable},
		{"U11 disabled daemon", evalU11(U11Input{Passwd: "daemon:!:1:1::/:/bin/false\n"}), StatusGood},
		{"U11 daemon login", evalU11(U11Input{Passwd: "daemon:!:1:1::/:/usr/bin/ksh\n"}), StatusVulnerable},
		{"U12 secure", evalU12(U12Input{Profiles: []FileResult{{Path: "/etc/profile", Content: "export TMOUT=600\n"}}}), StatusGood},
		{"U12 excessive", evalU12(U12Input{Profiles: []FileResult{{Path: "/etc/profile", Content: "TMOUT=601\n"}}}), StatusVulnerable},
		{"U13 strong", evalU13(U13Input{SecurityPasswd: "root:\n password = {ssha512}secret-material\n"}), StatusGood},
		{"U13 weak", evalU13(U13Input{SecurityPasswd: "root:\n password = {smd5}secret-material\n"}), StatusVulnerable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got.Status != test.want {
				t.Fatalf("status=%v, want %v; processed=%q", test.got.Status, test.want, test.got.ProcessedConfig)
			}
		})
	}
}

func TestAIXEvaluatorsRejectMissingRequiredInput(t *testing.T) {
	tests := []struct {
		name string
		got  CheckResult
	}{
		{"U01", evalU01(U01Input{})}, {"U02", evalU02(U02Input{})}, {"U03", evalU03(U03Input{})},
		{"U04", evalU04(U04Input{})}, {"U05", evalU05(U05Input{})}, {"U06", evalU06(U06Input{})},
		{"U07", evalU07(U07Input{})}, {"U08", evalU08(U08Input{})}, {"U09", evalU09(U09Input{})},
		{"U10", evalU10(U10Input{})}, {"U11", evalU11(U11Input{})}, {"U12", evalU12(U12Input{})},
		{"U13", evalU13(U13Input{})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got.Status == StatusGood {
				t.Fatal("missing required input was reported Good")
			}
		})
	}
}

func TestU13NeverOutputsRawHashes(t *testing.T) {
	const secret = "{ssha512}do-not-leak-this-hash"
	result := evalU13(U13Input{SecurityPasswd: "alice:\n password = " + secret + "\n"})
	output := strings.Join([]string{result.RawConfig, result.ProcessedConfig, result.VulnerableConfig, result.ErrMsg}, "\n")
	if strings.Contains(output, secret) || strings.Contains(output, "do-not-leak") {
		t.Fatalf("raw password hash leaked in result: %q", output)
	}
	if !strings.Contains(output, "alice=SSHA512") {
		t.Fatalf("sanitized classification missing: %q", output)
	}
}

func TestU04UsesPermissionBitsOnly(t *testing.T) {
	result := evalU04(U04Input{Files: []U04File{
		{Path: "/etc/passwd", Mode: os.FileMode(0644), Owner: "root", Exists: true},
		{Path: "/etc/security/passwd", Mode: os.FileMode(0600), Owner: "root", Exists: true},
	}})
	if result.Status != StatusGood {
		t.Fatalf("status=%v, want Good", result.Status)
	}
}
