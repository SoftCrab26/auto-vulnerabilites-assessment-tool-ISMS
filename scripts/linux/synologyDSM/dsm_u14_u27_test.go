package main

import (
	"os"
	"strings"
	"testing"
)

func dsmU14TestFile(path string, uid uint32, mode os.FileMode, content string) dsmU14AuditFile {
	return dsmU14AuditFile{Path: path, UID: uid, Mode: mode, Content: content}
}

func TestDSMChecksU14PathComponents(t *testing.T) {
	good := evalU14(U14Input{Files: []dsmU14AuditFile{dsmU14TestFile("/etc/profile", 0, 0o644, "PATH=/bin:/usr/bin")}})
	if good.Status != Good {
		t.Fatalf("good PATH status = %v", good.Status)
	}
	for _, value := range []string{"PATH=.:/bin", "PATH=/bin:.:/sbin", "PATH=/bin:", "PATH=:/bin"} {
		result := evalU14(U14Input{Files: []dsmU14AuditFile{dsmU14TestFile("/etc/profile", 0, 0o644, value)}})
		if result.Status != Vulnerable {
			t.Fatalf("%q status = %v, want Vulnerable", value, result.Status)
		}
	}
	if result := evalU14(U14Input{}); result.Status != Error {
		t.Fatalf("missing U14 data status = %v", result.Status)
	}
}

func TestDSMChecksU15InventoryStatuses(t *testing.T) {
	manual := evalU15(U15Input{Roots: []string{"/etc"}, Scanned: 2})
	if manual.Status != Manual || strings.TrimSpace(manual.RawConfig) == "" {
		t.Fatalf("bounded inventory = %+v", manual)
	}
	definite := evalU15(U15Input{Roots: []string{"/etc"}, Scanned: 2, Orphans: []string{"/etc/x uid=unknown"}})
	if definite.Status != Vulnerable {
		t.Fatalf("definite orphan status = %v", definite.Status)
	}
	if result := evalU15(U15Input{}); result.Status != Error {
		t.Fatalf("missing U15 data status = %v", result.Status)
	}
}

func TestDSMChecksRequiredFilePermissions(t *testing.T) {
	tests := []struct {
		name string
		got  CheckResult
		want Status
	}{
		{"passwd good", evalU16(U16Input{Passwd: dsmU14TestFile("/etc/passwd", 0, 0o644, "")}), Good},
		{"passwd owner", evalU16(U16Input{Passwd: dsmU14TestFile("/etc/passwd", 1, 0o644, "")}), Vulnerable},
		{"startup writable", evalU17(U17Input{Files: []dsmU14AuditFile{dsmU14TestFile("/etc/rc", 0, 0o664, "")}}), Vulnerable},
		{"startup missing", evalU17(U17Input{}), Error},
		{"shadow mode", evalU18(U18Input{Shadow: dsmU14TestFile("/etc/shadow", 0, 0o440, "")}), Vulnerable},
		{"hosts good", evalU19(U19Input{Hosts: dsmU14TestFile("/etc/hosts", 0, 0o644, "")}), Good},
		{"services executable", evalU22(U22Input{Services: dsmU14TestFile("/etc/services", 0, 0o744, "")}), Vulnerable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got.Status != test.want {
				t.Fatalf("status = %v, want %v", test.got.Status, test.want)
			}
		})
	}
}

func TestDSMChecksU20ApplicabilityAndPermissions(t *testing.T) {
	if result := evalU20(U20Input{}); result.Status != NotApplicable {
		t.Fatalf("absent inetd status = %v", result.Status)
	}
	file := dsmU14TestFile("/etc/inetd.conf", 0, 0o600, "")
	if result := evalU20(U20Input{Files: []dsmU14AuditFile{file}}); result.Status != NotApplicable {
		t.Fatalf("inactive inetd status = %v", result.Status)
	}
	if result := evalU20(U20Input{Files: []dsmU14AuditFile{file}, Active: true}); result.Status != Good {
		t.Fatalf("secure active inetd status = %v", result.Status)
	}
	file.Mode = 0o640
	if result := evalU20(U20Input{Files: []dsmU14AuditFile{file}, Active: true}); result.Status != Vulnerable {
		t.Fatalf("open inetd status = %v", result.Status)
	}
}

func TestDSMChecksU21RequiresLoggingConfig(t *testing.T) {
	if result := evalU21(U21Input{}); result.Status != Error {
		t.Fatalf("missing syslog config status = %v", result.Status)
	}
	file := dsmU14TestFile("/etc/syslog-ng/syslog-ng.conf", 0, 0o640, "")
	if result := evalU21(U21Input{Files: []dsmU14AuditFile{file}}); result.Status != Good {
		t.Fatalf("secure syslog config status = %v", result.Status)
	}
}

func TestDSMChecksManualInventoriesContainEvidence(t *testing.T) {
	u23 := evalU23(U23Input{Roots: []string{"/bin"}, Scanned: 3, Privileged: []dsmU14AuditFile{
		dsmU14TestFile("/bin/tool", 0, 0o4755, ""),
	}})
	u25 := evalU25(U25Input{Roots: []string{"/etc"}, Scanned: 4, WorldWritable: []dsmU14AuditFile{
		dsmU14TestFile("/etc/open", 0, 0o666, ""),
	}})
	for _, result := range []CheckResult{u23, u25} {
		if result.Status != Manual || strings.TrimSpace(result.RawConfig) == "" {
			t.Fatalf("manual inventory lacks evidence: %+v", result)
		}
	}
}

func TestDSMChecksU24UserEnvironmentPermissions(t *testing.T) {
	good := dsmU24EnvFile{File: dsmU14TestFile("/home/alice/.profile", 1000, 0o644, ""), AllowedUID: 1000}
	if result := evalU24(U24Input{Files: []dsmU24EnvFile{good}}); result.Status != Good {
		t.Fatalf("secure environment status = %v", result.Status)
	}
	good.File.Mode = 0o646
	if result := evalU24(U24Input{Files: []dsmU24EnvFile{good}}); result.Status != Vulnerable {
		t.Fatalf("world-writable environment status = %v", result.Status)
	}
}

func TestDSMChecksU26DirectRegularFiles(t *testing.T) {
	if result := evalU26(U26Input{}); result.Status != Error {
		t.Fatalf("missing /dev status = %v", result.Status)
	}
	if result := evalU26(U26Input{DevExists: true}); result.Status != Good {
		t.Fatalf("empty /dev inventory status = %v", result.Status)
	}
	file := dsmU14TestFile("/dev/plain", 0, 0o600, "")
	if result := evalU26(U26Input{DevExists: true, RegularFiles: []dsmU14AuditFile{file}}); result.Status != Vulnerable {
		t.Fatalf("regular /dev file status = %v", result.Status)
	}
}

func TestDSMChecksU27TrustFiles(t *testing.T) {
	if result := evalU27(U27Input{}); result.Status != Good {
		t.Fatalf("absent trust files status = %v", result.Status)
	}
	file := dsmU14TestFile("/root/.rhosts", 0, 0o600, "# + ignored\ntrusted +")
	result := evalU27(U27Input{Files: []dsmU14AuditFile{file}})
	if result.Status != Vulnerable || !strings.Contains(result.VulnerableConfig, "wildcard") {
		t.Fatalf("wildcard trust result = %+v", result)
	}
}
