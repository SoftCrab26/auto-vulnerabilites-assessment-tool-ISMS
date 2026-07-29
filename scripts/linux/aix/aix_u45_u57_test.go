package main

import "testing"

func activeService() Service {
	return Service{Running: true, ProcessMatches: []string{"daemon"}}
}

func TestU45AndU49VersionChecks(t *testing.T) {
	if got := evalU45(U45Input{Mail: activeService()}).Status; got != StatusInterview {
		t.Fatalf("U-45 active mail: got %v, want Interview", got)
	}
	if got := evalU49(U49Input{}).Status; got != StatusNotApplicable {
		t.Fatalf("U-49 inactive DNS: got %v, want N/A", got)
	}
}

func TestSendmailChecks(t *testing.T) {
	mail := activeService()
	cf := "O PrivacyOptions=authwarnings,restrictqrun,noexpn,novrfy\nKaccess hash /etc/mail/access\n"
	if got := evalU46(U46Input{Mail: mail, SendmailCF: cf, Found: true}).Status; got != StatusGood {
		t.Fatalf("U-46 restricted queue: got %v", got)
	}
	if got := evalU47(U47Input{Mail: mail, SendmailCF: cf, Found: true}).Status; got != StatusGood {
		t.Fatalf("U-47 access map: got %v", got)
	}
	if got := evalU48(U48Input{Mail: mail, SendmailCF: cf, Found: true}).Status; got != StatusGood {
		t.Fatalf("U-48 noexpn/novrfy: got %v", got)
	}
	if got := evalU48(U48Input{Mail: mail, SendmailCF: "O PrivacyOptions=noexpn", Found: true}).Status; got != StatusVulnerable {
		t.Fatalf("U-48 missing novrfy: got %v", got)
	}
	if got := evalU46(U46Input{Mail: mail}).Status; got != StatusError {
		t.Fatalf("U-46 active missing config: got %v", got)
	}
	if got := evalU46(U46Input{}).Status; got != StatusNotApplicable {
		t.Fatalf("U-46 inactive missing config: got %v", got)
	}
}

func TestNamedChecks(t *testing.T) {
	dns := activeService()
	restricted := `options { allow-transfer { 192.0.2.10; }; allow-update { none; }; };`
	if got := evalU50(U50Input{DNS: dns, NamedConf: restricted, Found: true}).Status; got != StatusGood {
		t.Fatalf("U-50 restricted transfer: got %v", got)
	}
	if got := evalU50(U50Input{DNS: dns, NamedConf: `allow-transfer { any; };`, Found: true}).Status; got != StatusVulnerable {
		t.Fatalf("U-50 any transfer: got %v", got)
	}
	if got := evalU51(U51Input{DNS: dns, NamedConf: restricted, Found: true}).Status; got != StatusGood {
		t.Fatalf("U-51 update none: got %v", got)
	}
	if got := evalU51(U51Input{DNS: dns, NamedConf: `allow-update { any; };`, Found: true}).Status; got != StatusVulnerable {
		t.Fatalf("U-51 update any: got %v", got)
	}
}

func TestTelnetAndFTPServiceChecks(t *testing.T) {
	if got := evalU52(U52Input{}).Status; got != StatusGood {
		t.Fatalf("U-52 inactive telnet: got %v", got)
	}
	if got := evalU52(U52Input{Telnet: activeService()}).Status; got != StatusVulnerable {
		t.Fatalf("U-52 active telnet: got %v", got)
	}
	if got := evalU54(U54Input{}).Status; got != StatusGood {
		t.Fatalf("U-54 inactive FTP: got %v", got)
	}
	if got := evalU54(U54Input{FTP: activeService()}).Status; got != StatusVulnerable {
		t.Fatalf("U-54 active FTP: got %v", got)
	}
}

func TestFTPConfigurationChecks(t *testing.T) {
	ftp := activeService()
	if got := evalU53(U53Input{FTP: ftp, FTPConfig: "banner /etc/issue", Found: true}).Status; got != StatusGood {
		t.Fatalf("U-53 banner: got %v", got)
	}
	if got := evalU55(U55Input{Passwd: "ftp:x:14:1::/var/ftp:/usr/bin/false\n", Found: true}).Status; got != StatusGood {
		t.Fatalf("U-55 restricted shell: got %v", got)
	}
	if got := evalU55(U55Input{Passwd: "ftp:x:14:1::/var/ftp:/bin/ksh\n", Found: true}).Status; got != StatusVulnerable {
		t.Fatalf("U-55 interactive shell: got %v", got)
	}
	if got := evalU56(U56Input{FTP: ftp, AccessConfig: "ftp: 192.0.2.0/24", Found: true}).Status; got != StatusGood {
		t.Fatalf("U-56 host access: got %v", got)
	}
	if got := evalU57(U57Input{FTP: ftp, FTPUsers: "# denied users\nroot\n", Found: true}).Status; got != StatusGood {
		t.Fatalf("U-57 root blocked: got %v", got)
	}
	if got := evalU57(U57Input{FTP: ftp, FTPUsers: "daemon\n", Found: true}).Status; got != StatusVulnerable {
		t.Fatalf("U-57 root absent: got %v", got)
	}
	if got := evalU57(U57Input{}).Status; got != StatusNotApplicable {
		t.Fatalf("U-57 inactive missing config: got %v", got)
	}
}
