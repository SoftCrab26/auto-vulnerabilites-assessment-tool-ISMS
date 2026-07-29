package main

import (
	"os"
	"strings"
	"testing"
)

func activeSNMP() Service {
	return Service{Name: "SNMP", Running: true, SRCMatches: []string{"snmpd"}}
}

func TestEvalU58SNMPState(t *testing.T) {
	if got := evalU58(U58Input{}); got.Status != StatusGood {
		t.Fatalf("inactive SNMP status = %v, want Good", got.Status)
	}
	if got := evalU58(U58Input{SNMP: activeSNMP()}); got.Status != StatusVulnerable {
		t.Fatalf("active SNMP status = %v, want Vulnerable", got.Status)
	}
}

func TestEvalU59RequiresSNMPv3Authentication(t *testing.T) {
	tests := []struct {
		name   string
		input  U59Input
		status Status
	}{
		{"inactive", U59Input{}, StatusNotApplicable},
		{"missing config", U59Input{SNMP: activeSNMP()}, StatusError},
		{"v2 only", U59Input{SNMP: activeSNMP(), Config: "community public"}, StatusVulnerable},
		{"v3 authenticated", U59Input{SNMP: activeSNMP(), Config: "USM_USER monitor - HMAC-SHA authPriv"}, StatusGood},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := evalU59(test.input); got.Status != test.status {
				t.Fatalf("status = %v, want %v", got.Status, test.status)
			}
		})
	}
}

func TestEvalU59RedactsAuthenticationMaterial(t *testing.T) {
	const secret = "SuperSecretAuthKey"
	got := evalU59(U59Input{
		SNMP:       activeSNMP(),
		ConfigPath: "/etc/snmpd.conf",
		Config:     "createUser monitor SHA " + secret + "\nauthuser monitor",
	})
	if strings.Contains(got.RawConfig+got.ProcessedConfig+got.VulnerableConfig, secret) {
		t.Fatal("SNMP authentication material was exposed")
	}
}

func TestParseSNMPCommunitiesUsesActualValues(t *testing.T) {
	config := `
# community public
community
community public
rocommunity StrongValue-2026 10.0.0.0/24
com2sec local 10.0.0.0/24 private
`
	values := parseSNMPCommunities(config)
	if len(values) != 3 {
		t.Fatalf("parsed %d community values, want 3", len(values))
	}
	if values[0] != "public" || values[1] != "StrongValue-2026" || values[2] != "private" {
		t.Fatalf("unexpected parsed values: %#v", values)
	}
}

func TestEvalU60DoesNotExposeCommunity(t *testing.T) {
	const secret = "StrongCommunity-2026"
	got := evalU60(U60Input{SNMP: activeSNMP(), Config: "rocommunity " + secret})
	if got.Status != StatusGood {
		t.Fatalf("strong community status = %v, want Good", got.Status)
	}
	if strings.Contains(got.RawConfig+got.ProcessedConfig+got.VulnerableConfig, secret) {
		t.Fatal("community value was exposed")
	}

	got = evalU60(U60Input{SNMP: activeSNMP(), Config: "community public"})
	if got.Status != StatusVulnerable {
		t.Fatalf("default community status = %v, want Vulnerable", got.Status)
	}
}

func TestEvalU61AcceptsAIXACLForms(t *testing.T) {
	tests := []string{
		"ACCESS group context any noAuth exact view none none",
		"VIEW restricted internet 1.3.6 included",
		"community StrongCommunity 10.20.0.0 255.255.0.0",
	}
	for _, config := range tests {
		got := evalU61(U61Input{SNMP: activeSNMP(), Config: config})
		if got.Status != StatusGood {
			t.Fatalf("config %q status = %v, want Good", config, got.Status)
		}
	}
	if got := evalU61(U61Input{SNMP: activeSNMP(), Config: "community StrongCommunity"}); got.Status != StatusVulnerable {
		t.Fatalf("unrestricted status = %v, want Vulnerable", got.Status)
	}
}

func TestEvalU62RecognizesAIXAndSSHBanner(t *testing.T) {
	tests := []U62Input{
		{Files: []FileResult{{Path: "/etc/security/login.cfg", Content: "default:\n herald = \"Authorized use only\""}}},
		{Files: []FileResult{{Path: "/etc/motd", Content: "Authorized users only"}}},
		{Files: []FileResult{{Path: "/etc/security/messages", Content: "Warning"}}},
		{Files: []FileResult{{Path: "/etc/ssh/sshd_config", Content: "Banner /etc/ssh/banner"}}},
	}
	for _, input := range tests {
		if got := evalU62(input); got.Status != StatusGood {
			t.Fatalf("banner input status = %v, want Good", got.Status)
		}
	}
	if got := evalU62(U62Input{}); got.Status != StatusError {
		t.Fatalf("missing input status = %v, want Error", got.Status)
	}
	if got := evalU62(U62Input{Files: []FileResult{{Path: "/etc/ssh/sshd_config", Content: "# Banner /tmp/banner\nBanner none"}}}); got.Status != StatusVulnerable {
		t.Fatalf("disabled banner status = %v, want Vulnerable", got.Status)
	}
}

func TestEvalU63OwnerAndMode(t *testing.T) {
	for _, mode := range []os.FileMode{0400, 0440, 0600, 0640} {
		got := evalU63(U63Input{Path: "/etc/sudoers", Exists: true, Owner: "root", Mode: mode})
		if got.Status != StatusGood {
			t.Fatalf("mode %04o status = %v, want Good", mode, got.Status)
		}
	}
	for _, input := range []U63Input{
		{Path: "/etc/sudoers"},
		{Path: "/etc/sudoers", Exists: true, Owner: "user", Mode: 0440},
		{Path: "/etc/sudoers", Exists: true, Owner: "root", Mode: 0644},
	} {
		if got := evalU63(input); got.Status == StatusGood {
			t.Fatalf("insecure input %+v was marked Good", input)
		}
	}
}

func TestEvalU64AlwaysInterviewWithEvidence(t *testing.T) {
	got := evalU64(U64Input{OSLevel: "7200-05-03-2446", InstfixEvidence: "All filesets found"})
	if got.Status != StatusInterview {
		t.Fatalf("status = %v, want Interview", got.Status)
	}
	if !strings.Contains(got.RawConfig, "7200-05-03-2446") || !strings.Contains(got.RawConfig, "All filesets found") {
		t.Fatal("oslevel or instfix evidence missing")
	}
	if got := evalU64(U64Input{}); got.Status == StatusGood {
		t.Fatal("missing patch evidence must not be Good")
	}
}

func TestEvalU65RequiresExternalNTP(t *testing.T) {
	for _, config := range []string{
		"server 127.127.1.0\nfudge 127.127.1.0 stratum 10",
		"server localhost",
		"# server time.example.com",
		"",
	} {
		if got := evalU65(U65Input{Config: config}); got.Status != StatusVulnerable {
			t.Fatalf("config %q status = %v, want Vulnerable", config, got.Status)
		}
	}
	if got := evalU65(U65Input{Config: "server time.example.com iburst"}); got.Status != StatusGood {
		t.Fatalf("external server status = %v, want Good", got.Status)
	}
}

func TestEvalU66RequiresSyslogFacilities(t *testing.T) {
	good := "*.info /var/adm/ras/syslog.caa rotate size 1m files 10"
	if got := evalU66(U66Input{Config: good}); got.Status != StatusGood {
		t.Fatalf("wildcard facilities status = %v, want Good", got.Status)
	}
	partial := "auth.info /var/adm/auth.log\nmail.info /var/adm/mail.log"
	if got := evalU66(U66Input{Config: partial}); got.Status != StatusVulnerable {
		t.Fatalf("partial facilities status = %v, want Vulnerable", got.Status)
	}
	if got := evalU66(U66Input{}); got.Status == StatusGood {
		t.Fatal("missing syslog data must not be Good")
	}
}

func TestEvalU67ChecksAdmAndKeyLogs(t *testing.T) {
	secure := U67Input{
		AdmDir:  &U67Path{Path: "/var/adm", Owner: "root", Mode: 0755, IsDir: true},
		KeyLogs: []U67Path{{Path: "/var/adm/wtmp", Owner: "root", Mode: 0640}},
	}
	if got := evalU67(secure); got.Status != StatusGood {
		t.Fatalf("secure metadata status = %v, want Good", got.Status)
	}

	insecure := secure
	insecure.KeyLogs = []U67Path{{Path: "/var/adm/wtmp", Owner: "user", Mode: 0666}}
	if got := evalU67(insecure); got.Status != StatusVulnerable {
		t.Fatalf("insecure metadata status = %v, want Vulnerable", got.Status)
	}
	if got := evalU67(U67Input{}); got.Status != StatusError {
		t.Fatalf("missing /var/adm status = %v, want Error", got.Status)
	}
	if got := evalU67(U67Input{AdmDir: secure.AdmDir}); got.Status != StatusInterview {
		t.Fatalf("missing key logs status = %v, want Interview", got.Status)
	}
}
