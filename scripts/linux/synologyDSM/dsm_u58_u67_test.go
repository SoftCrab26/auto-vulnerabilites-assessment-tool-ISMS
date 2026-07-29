package main

import (
	"os"
	"strings"
	"testing"
)

func dsmTestActiveSNMP() Service {
	return Service{Name: "snmp", Running: true, IsActive: true}
}

func TestDSMEvalU58SNMPState(t *testing.T) {
	if got := evalU58(U58Input{SNMP: Service{Name: "snmp"}}); got.Status != Good {
		t.Fatalf("inactive status = %v, want Good", got.Status)
	}
	if got := evalU58(U58Input{SNMP: dsmTestActiveSNMP()}); got.Status != Vulnerable {
		t.Fatalf("active status = %v, want Vulnerable", got.Status)
	}
}

func TestDSMEvalU59RequiresAuthenticatedV3AndRedactsSecrets(t *testing.T) {
	const secret = "SuperSecretAuthenticationKey"
	tests := []struct {
		name   string
		input  U59Input
		status Status
	}{
		{name: "inactive", input: U59Input{}, status: NotApplicable},
		{name: "missing", input: U59Input{SNMP: dsmTestActiveSNMP()}, status: Error},
		{name: "v2", input: U59Input{SNMP: dsmTestActiveSNMP(), Config: "rocommunity public"}, status: Vulnerable},
		{name: "v3 auth", input: U59Input{
			SNMP: dsmTestActiveSNMP(), ConfigPath: "/etc/snmp/snmpd.conf",
			Config: "createUser monitor SHA " + secret + "\nrouser monitor authPriv",
		}, status: Good},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := evalU59(test.input)
			if got.Status != test.status {
				t.Fatalf("status = %v, want %v; result=%+v", got.Status, test.status, got)
			}
			if strings.Contains(got.RawConfig+got.ProcessedConfig+got.VulnerableConfig+got.ErrMsg, secret) {
				t.Fatal("SNMPv3 authentication material was exposed")
			}
		})
	}
}

func TestDSMEvalU60ClassifiesAndRedactsCommunities(t *testing.T) {
	const strong = "StrongCommunity-2026"
	for _, test := range []struct {
		name      string
		community string
		status    Status
	}{
		{name: "public", community: "public", status: Vulnerable},
		{name: "private", community: "private", status: Vulnerable},
		{name: "default", community: "default", status: Vulnerable},
		{name: "strong", community: strong, status: Good},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := evalU60(U60Input{
				SNMP: dsmTestActiveSNMP(), ConfigPath: "/etc/snmp/snmpd.conf",
				Config: "rocommunity " + test.community + " 10.0.0.0/24",
			})
			if got.Status != test.status {
				t.Fatalf("status = %v, want %v; result=%+v", got.Status, test.status, got)
			}
			output := got.RawConfig + got.ProcessedConfig + got.VulnerableConfig + got.ErrMsg
			if strings.Contains(output, test.community) {
				t.Fatalf("community %q was exposed: %s", test.community, output)
			}
			if !strings.Contains(output, "[REDACTED]") {
				t.Fatalf("redacted label missing: %s", output)
			}
		})
	}
}

func TestDSMEvalU61RequiresSourceACLAndView(t *testing.T) {
	good := "rocommunity RedactedValue 10.20.0.0/24 restricted\nview restricted included .1.3.6.1.2.1"
	if got := evalU61(U61Input{SNMP: dsmTestActiveSNMP(), Config: good}); got.Status != Good {
		t.Fatalf("restricted config status = %v, want Good; result=%+v", got.Status, got)
	}
	for _, config := range []string{
		"rocommunity RedactedValue 0.0.0.0/0 restricted",
		"rocommunity RedactedValue 10.20.0.0/24",
	} {
		if got := evalU61(U61Input{SNMP: dsmTestActiveSNMP(), Config: config}); got.Status != Vulnerable {
			t.Fatalf("incomplete config %q status = %v, want Vulnerable", config, got.Status)
		}
	}
	if got := evalU61(U61Input{}); got.Status != NotApplicable {
		t.Fatalf("inactive status = %v, want NotApplicable", got.Status)
	}
}

func TestDSMEvalU62BannerEvidence(t *testing.T) {
	for _, input := range []U62Input{
		{Files: []FileResult{{Path: "/etc/issue", Content: "Authorized users only"}}},
		{Files: []FileResult{{Path: "/etc/ssh/sshd_config", Content: "Banner /etc/issue.net"}}},
		{Files: []FileResult{{Path: "/etc/synoinfo.conf", Content: `login_welcome="Authorized access only"`}}},
	} {
		if got := evalU62(input); got.Status != Good {
			t.Fatalf("banner status = %v, want Good; result=%+v", got.Status, got)
		}
	}
	if got := evalU62(U62Input{}); got.Status != Error {
		t.Fatalf("missing evidence status = %v, want Error", got.Status)
	}
	if got := evalU62(U62Input{Files: []FileResult{{Path: "/etc/ssh/sshd_config", Content: "Banner none"}}}); got.Status != Vulnerable {
		t.Fatalf("disabled SSH banner status = %v, want Vulnerable", got.Status)
	}
}

func TestDSMEvalU63SudoersOwnerAndMode(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0440, 0600, 0640} {
		if got := evalU63(U63Input{Path: "/etc/sudoers", Exists: true, Owner: "root", Mode: mode}); got.Status != Good {
			t.Fatalf("mode %04o status = %v, want Good", mode, got.Status)
		}
	}
	for _, input := range []U63Input{
		{Path: "/etc/sudoers"},
		{Path: "/etc/sudoers", Exists: true, Owner: "user", Mode: 0440},
		{Path: "/etc/sudoers", Exists: true, Owner: "root", Mode: 0644},
	} {
		if got := evalU63(input); got.Status == Good {
			t.Fatalf("insecure input %+v marked Good", input)
		}
	}
}

func TestDSMEvalU64ReturnsManualMetadataForCurrencyReview(t *testing.T) {
	got := evalU64(U64Input{
		Version: "6.2.4", MajorVersion: "6", MinorVersion: "2",
		BuildNumber: "25556", SmallFixNumber: "8",
	})
	if got.Status != Manual {
		t.Fatalf("status = %v, want Manual; result=%+v", got.Status, got)
	}
	for _, evidence := range []string{"version=6.2.4", "build=25556", "smallfix=8"} {
		if !strings.Contains(got.RawConfig, evidence) {
			t.Errorf("RawConfig missing %q: %s", evidence, got.RawConfig)
		}
	}
	if !strings.Contains(got.ProcessedConfig, "update_command_executed=false") {
		t.Fatalf("non-mutating evidence marker missing: %s", got.ProcessedConfig)
	}
	if got := evalU64(U64Input{Version: "6.2.4"}); got.Status != Error {
		t.Fatalf("incomplete metadata status = %v, want Error", got.Status)
	}
}

func TestDSMEvalU65RequiresExternalNTP(t *testing.T) {
	for _, config := range []string{"server 127.127.1.0", "server localhost", "# server time.example.com"} {
		if got := evalU65(U65Input{Config: config}); got.Status != Vulnerable {
			t.Fatalf("config %q status = %v, want Vulnerable", config, got.Status)
		}
	}
	got := evalU65(U65Input{ConfigPath: "/etc/ntp.conf", Config: "server time.example.com iburst"})
	if got.Status != Good || !strings.Contains(got.RawConfig, "time.example.com") {
		t.Fatalf("external NTP result = %+v", got)
	}
	if got := evalU65(U65Input{}); got.Status != Error {
		t.Fatalf("missing config status = %v, want Error", got.Status)
	}
}

func TestDSMEvalU66ReturnsLoggingEvidenceForPolicyReview(t *testing.T) {
	good := U66Input{Files: []FileResult{{
		Path:    "/etc/syslog.conf",
		Content: "*.info /var/log/messages\nauthpriv.* /var/log/auth.log",
	}}}
	got := evalU66(good)
	if got.Status != Manual {
		t.Fatalf("configured logging status = %v, want Manual; result=%+v", got.Status, got)
	}
	if !strings.Contains(got.RawConfig, "*.info /var/log/messages") {
		t.Fatalf("actual nonsecret logging evidence missing: %s", got.RawConfig)
	}
	if got := evalU66(U66Input{}); got.Status != Error {
		t.Fatalf("missing config status = %v, want Error", got.Status)
	}
	if got := evalU66(U66Input{Files: []FileResult{{Path: "/etc/syslog.conf", Content: "# no routes"}}}); got.Status != Vulnerable {
		t.Fatalf("empty policy status = %v, want Vulnerable", got.Status)
	}
}

func TestDSMEvalU67ChecksLogOwnersAndModes(t *testing.T) {
	secure := U67Input{
		LogDir:  &U67Path{Path: "/var/log", Owner: "root", Mode: 0755, IsDir: true},
		KeyLogs: []U67Path{{Path: "/var/log/messages", Owner: "root", Mode: 0640}},
	}
	if got := evalU67(secure); got.Status != Good {
		t.Fatalf("secure metadata status = %v, want Good; result=%+v", got.Status, got)
	}
	insecure := secure
	insecure.KeyLogs = []U67Path{{Path: "/var/log/messages", Owner: "user", Mode: 0666}}
	if got := evalU67(insecure); got.Status != Vulnerable {
		t.Fatalf("insecure metadata status = %v, want Vulnerable", got.Status)
	}
	if got := evalU67(U67Input{}); got.Status != Error {
		t.Fatalf("missing directory status = %v, want Error", got.Status)
	}
	if got := evalU67(U67Input{LogDir: secure.LogDir}); got.Status != Error {
		t.Fatalf("missing key logs status = %v, want Error", got.Status)
	}
}
