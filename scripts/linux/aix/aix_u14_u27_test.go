package main

import (
	"os"
	"strings"
	"testing"
)

func testAuditFile(path, owner string, mode os.FileMode, content string) auditFile {
	return auditFile{Path: path, Owner: owner, Mode: mode, Content: content, Exists: true}
}

func TestEvalU14DetectsDotPathComponent(t *testing.T) {
	input := U14Input{Files: []auditFile{
		testAuditFile("/etc/environment", "root", 0644, `PATH=/usr/bin:.:/bin`),
		testAuditFile("/etc/profile", "root", 0644, `PATH=/usr/bin:/bin`),
	}}
	if result := evalU14(input); result.Status != StatusVulnerable {
		t.Fatalf("expected vulnerable, got %v", result.Status)
	}
}

func TestEvalU14RequiresSystemFiles(t *testing.T) {
	input := U14Input{Files: []auditFile{
		{Path: "/etc/environment"},
		testAuditFile("/etc/profile", "root", 0644, `PATH=/usr/bin:/bin`),
	}}
	if result := evalU14(input); result.Status == StatusGood {
		t.Fatal("missing required PATH file must not be good")
	}
}

func TestPermissionChecksUseOwnerAndAllowedMask(t *testing.T) {
	tests := []struct {
		name string
		got  CheckResult
	}{
		{"passwd owner", evalU16(U16Input{Passwd: testAuditFile("/etc/passwd", "daemon", 0644, "")})},
		{"security passwd mode", evalU18(U18Input{SecurityPasswd: testAuditFile("/etc/security/passwd", "root", 0640, "")})},
		{"hosts executable", evalU19(U19Input{Hosts: testAuditFile("/etc/hosts", "root", 0755, "")})},
		{"inetd group readable", evalU20(U20Input{Inetd: testAuditFile("/etc/inetd.conf", "root", 0640, "")})},
		{"syslog other readable", evalU21(U21Input{Syslog: testAuditFile("/etc/syslog.conf", "root", 0644, "")})},
		{"services writable", evalU22(U22Input{Services: testAuditFile("/etc/services", "root", 0664, "")})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got.Status != StatusVulnerable {
				t.Fatalf("expected vulnerable, got %v", test.got.Status)
			}
		})
	}
}

func TestEvalU17RequiresAIXStartupFiles(t *testing.T) {
	input := U17Input{
		Files:   []auditFile{testAuditFile("/etc/inittab", "root", 0644, "")},
		Missing: []string{"/etc/rc.tcpip"},
	}
	if result := evalU17(input); result.Status != StatusError {
		t.Fatalf("expected error, got %v", result.Status)
	}
}

func TestInventoryChecksRemainInterview(t *testing.T) {
	if result := evalU15(U15Input{}); result.Status != StatusInterview {
		t.Fatalf("U-15 expected Interview, got %v", result.Status)
	}
	if result := evalU23(U23Input{}); result.Status != StatusInterview {
		t.Fatalf("U-23 expected Interview, got %v", result.Status)
	}
	if result := evalU25(U25Input{}); result.Status != StatusInterview {
		t.Fatalf("U-25 expected Interview, got %v", result.Status)
	}
}

func TestEvalU24ChecksUserOwnerAndOtherWrite(t *testing.T) {
	input := U24Input{Files: []U24EnvFile{
		{File: testAuditFile("/etc/environment", "root", 0644, ""), AllowedOwner: "root", Required: true},
		{File: testAuditFile("/etc/profile", "root", 0644, ""), AllowedOwner: "root", Required: true},
		{File: testAuditFile("/home/alice/.profile", "bob", 0646, ""), AllowedOwner: "alice"},
	}}
	if result := evalU24(input); result.Status != StatusVulnerable {
		t.Fatalf("expected vulnerable, got %v", result.Status)
	}
}

func TestEvalU26FindsRegularFiles(t *testing.T) {
	input := U26Input{
		DevExists:    true,
		RegularFiles: []auditFile{testAuditFile("/dev/.hidden", "root", 0600, "")},
	}
	if result := evalU26(input); result.Status != StatusVulnerable {
		t.Fatalf("expected vulnerable, got %v", result.Status)
	}
}

func TestEvalU27AbsentIsNotApplicable(t *testing.T) {
	if result := evalU27(U27Input{}); result.Status != StatusNotApplicable {
		t.Fatalf("expected not applicable, got %v", result.Status)
	}
}

func TestEvalU27ChecksWildcardOwnerAndMode(t *testing.T) {
	input := U27Input{
		HostsEquiv: testAuditFile("/etc/hosts.equiv", "root", 0600, "# + ignored\ntrusted-host +"),
		RootRhosts: testAuditFile("/root/.rhosts", "alice", 0644, "trusted-host root"),
	}
	result := evalU27(input)
	if result.Status != StatusVulnerable {
		t.Fatalf("expected vulnerable, got %v", result.Status)
	}
	if !strings.Contains(result.VulnerableConfig, "wildcard") {
		t.Fatal("expected wildcard trust detail")
	}
}
