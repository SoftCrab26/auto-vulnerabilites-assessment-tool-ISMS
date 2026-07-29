package main

import (
	"strings"
	"testing"
)

func dsmU45U57AssertStatus(t *testing.T, name string, got, want Status) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status=%v, want %v", name, got, want)
	}
}

func TestDSMU45AndU49ManualVersionEvidence(t *testing.T) {
	mail := evalU45(DSMU45Input{MailActive: true, Evidence: `version="3.0.0"`})
	dsmU45U57AssertStatus(t, "U-45 active", mail.Status, Manual)
	if !strings.Contains(mail.RawConfig, "version") {
		t.Fatalf("U-45 manual result must retain raw version evidence: %+v", mail)
	}
	dsmU45U57AssertStatus(t, "U-45 inactive", evalU45(DSMU45Input{}).Status, NotApplicable)

	dns := evalU49(DSMU49Input{DNSActive: true, Evidence: `version="2.2.1"`})
	dsmU45U57AssertStatus(t, "U-49 active", dns.Status, Manual)
	if dns.RawConfig == "" {
		t.Fatal("U-49 manual result must include RawConfig evidence")
	}
	dsmU45U57AssertStatus(t, "U-49 inactive", evalU49(DSMU49Input{}).Status, NotApplicable)
}

func TestDSMU46ExecutionRestriction(t *testing.T) {
	dsmU45U57AssertStatus(t, "sendmail restricted",
		evalU46(DSMU46Input{MailActive: true, ConfigPath: "/etc/mail/sendmail.cf", Config: "O PrivacyOptions=restrictqrun", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "postfix restricted",
		evalU46(DSMU46Input{MailActive: true, ConfigPath: "/etc/postfix/main.cf", Config: "authorized_submit_users = root", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "postfix default anyone",
		evalU46(DSMU46Input{MailActive: true, ConfigPath: "/etc/postfix/main.cf", Config: "authorized_submit_users = static:anyone", Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "active missing config", evalU46(DSMU46Input{MailActive: true}).Status, Error)
	dsmU45U57AssertStatus(t, "inactive", evalU46(DSMU46Input{}).Status, NotApplicable)
}

func TestDSMU47RelayRestriction(t *testing.T) {
	dsmU45U57AssertStatus(t, "postfix relay restricted",
		evalU47(DSMU47Input{MailActive: true, ConfigPath: "/etc/postfix/main.cf", Config: "smtpd_relay_restrictions = reject_unauth_destination", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "sendmail access map",
		evalU47(DSMU47Input{MailActive: true, ConfigPath: "/etc/mail/sendmail.cf", Config: "Kaccess hash /etc/mail/access", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "relay unrestricted",
		evalU47(DSMU47Input{MailActive: true, ConfigPath: "/etc/postfix/main.cf", Config: "mynetworks = 0.0.0.0/0", Found: true}).Status,
		Vulnerable)
}

func TestDSMU48ExpnVrfyRestriction(t *testing.T) {
	dsmU45U57AssertStatus(t, "sendmail both disabled",
		evalU48(DSMU48Input{MailActive: true, ConfigPath: "/etc/mail/sendmail.cf", Config: "O PrivacyOptions=noexpn,novrfy", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "sendmail only expn disabled",
		evalU48(DSMU48Input{MailActive: true, ConfigPath: "/etc/mail/sendmail.cf", Config: "O PrivacyOptions=noexpn", Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "postfix vrfy disabled",
		evalU48(DSMU48Input{MailActive: true, ConfigPath: "/etc/postfix/main.cf", Config: "disable_vrfy_command = yes", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "active missing config", evalU48(DSMU48Input{MailActive: true}).Status, Error)
}

func TestDSMU50ZoneTransferRestriction(t *testing.T) {
	dsmU45U57AssertStatus(t, "specific transfer ACL",
		evalU50(DSMU50Input{DNSActive: true, NamedConf: `allow-transfer { 192.0.2.10; };`, Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "transfer denied",
		evalU50(DSMU50Input{DNSActive: true, NamedConf: `allow-transfer { none; };`, Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "transfer any",
		evalU50(DSMU50Input{DNSActive: true, NamedConf: `allow-transfer { any; };`, Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "missing directive",
		evalU50(DSMU50Input{DNSActive: true, NamedConf: `options { recursion no; };`, Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "active config unavailable", evalU50(DSMU50Input{DNSActive: true}).Status, Error)
}

func TestDSMU51DynamicUpdateRestriction(t *testing.T) {
	dsmU45U57AssertStatus(t, "update disabled",
		evalU51(DSMU51Input{DNSActive: true, NamedConf: `allow-update { none; };`, Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "update key restricted",
		evalU51(DSMU51Input{DNSActive: true, NamedConf: `allow-update { key dhcp-key; };`, Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "update any",
		evalU51(DSMU51Input{DNSActive: true, NamedConf: `allow-update { any; };`, Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "default disabled",
		evalU51(DSMU51Input{DNSActive: true, NamedConf: `options { recursion no; };`, Found: true}).Status,
		Good)
}

func TestDSMU52AndU54ServiceState(t *testing.T) {
	dsmU45U57AssertStatus(t, "telnet inactive", evalU52(DSMU52Input{}).Status, Good)
	dsmU45U57AssertStatus(t, "telnet active", evalU52(DSMU52Input{TelnetActive: true}).Status, Vulnerable)
	dsmU45U57AssertStatus(t, "cleartext FTP inactive", evalU54(DSMU54Input{}).Status, Good)
	dsmU45U57AssertStatus(t, "cleartext FTP active", evalU54(DSMU54Input{FTPActive: true}).Status, Vulnerable)
}

func TestDSMU53FTPBanner(t *testing.T) {
	dsmU45U57AssertStatus(t, "proftpd identity off",
		evalU53(DSMU53Input{FTPActive: true, FTPConfig: "ServerIdent off", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "custom banner",
		evalU53(DSMU53Input{FTPActive: true, FTPConfig: "ftpd_banner=Authorized users only", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "default banner",
		evalU53(DSMU53Input{FTPActive: true, FTPConfig: "anonymous_enable=NO", Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "active config unavailable", evalU53(DSMU53Input{FTPActive: true}).Status, Error)
	dsmU45U57AssertStatus(t, "inactive", evalU53(DSMU53Input{}).Status, NotApplicable)
}

func TestDSMU55FTPAccountShell(t *testing.T) {
	dsmU45U57AssertStatus(t, "restricted shell",
		evalU55(DSMU55Input{FTPActive: true, Passwd: "ftp:x:21:21::/var/ftp:/sbin/nologin\n", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "interactive shell",
		evalU55(DSMU55Input{FTPActive: true, Passwd: "ftp:x:21:21::/var/ftp:/bin/sh\n", Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "active passwd unavailable", evalU55(DSMU55Input{FTPActive: true}).Status, Error)
	dsmU45U57AssertStatus(t, "inactive", evalU55(DSMU55Input{}).Status, NotApplicable)
}

func TestDSMU56FTPHostAccessRestriction(t *testing.T) {
	restricted := "ftp: 192.0.2.0/24\nALL: ALL\n"
	dsmU45U57AssertStatus(t, "specific allow and default deny",
		evalU56(DSMU56Input{FTPActive: true, AccessConfig: restricted, Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "allow all",
		evalU56(DSMU56Input{FTPActive: true, AccessConfig: "ftp: ALL\n", Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "active config unavailable", evalU56(DSMU56Input{FTPActive: true}).Status, Error)
}

func TestDSMU57RootFTPDeny(t *testing.T) {
	dsmU45U57AssertStatus(t, "root denied",
		evalU57(DSMU57Input{FTPActive: true, FTPUsers: "# denied users\nroot\n", Found: true}).Status,
		Good)
	dsmU45U57AssertStatus(t, "root absent",
		evalU57(DSMU57Input{FTPActive: true, FTPUsers: "daemon\n", Found: true}).Status,
		Vulnerable)
	dsmU45U57AssertStatus(t, "active deny list unavailable", evalU57(DSMU57Input{FTPActive: true}).Status, Error)
	dsmU45U57AssertStatus(t, "inactive", evalU57(DSMU57Input{}).Status, NotApplicable)
}
