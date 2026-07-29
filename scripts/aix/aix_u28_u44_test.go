package main

import (
	"os"
	"testing"
)

func requireStatus(t *testing.T, got CheckResult, want Status) {
	t.Helper()
	if got.Status != want {
		t.Fatalf("status = %s, want %s (processed=%q)", got.Status.toString(), want.toString(), got.ProcessedConfig)
	}
}

func TestU28AlwaysRequiresInterview(t *testing.T) {
	requireStatus(t, evalU28(U28Input{PortACL: "tcp 22 root", FirewallEvidence: "filter rules"}), StatusInterview)
}

func TestU29HostsLPD(t *testing.T) {
	requireStatus(t, evalU29(U29Input{Path: "/etc/hosts.lpd"}), StatusNotApplicable)
	requireStatus(t, evalU29(U29Input{Path: "/etc/hosts.lpd", Exists: true, Owner: "root", Mode: 0600}), StatusGood)
	requireStatus(t, evalU29(U29Input{Path: "/etc/hosts.lpd", Exists: true, Owner: "daemon", Mode: 0644}), StatusVulnerable)
}

func TestU30RequiresBothSecureUmasks(t *testing.T) {
	secure := U30Input{SecurityUser: "default:\n\tumask = 027\n", Profile: "umask 022\n"}
	requireStatus(t, evalU30(secure), StatusGood)
	secure.Profile = "umask 002\n"
	requireStatus(t, evalU30(secure), StatusVulnerable)
	requireStatus(t, evalU30(U30Input{}), StatusInterview)
}

func TestU31HomeOwnershipAndPermissions(t *testing.T) {
	base := U31Input{
		Passwd: "alice:x:100:100::/home/alice:/bin/ksh",
		Homes:  []U31Home{{User: "alice", Path: "/home/alice", Exists: true, Owner: "alice", Mode: os.ModeDir | 0750}},
	}
	requireStatus(t, evalU31(base), StatusGood)
	base.Homes[0].Mode = os.ModeDir | 0775
	requireStatus(t, evalU31(base), StatusVulnerable)
}

func TestU32HomeExistence(t *testing.T) {
	input := U32Input{Passwd: "alice:x:100:100::/home/alice:/bin/ksh", Homes: []U32Home{{User: "alice", Path: "/home/alice", Exists: true}}}
	requireStatus(t, evalU32(input), StatusGood)
	input.Homes[0].Exists = false
	requireStatus(t, evalU32(input), StatusVulnerable)
}

func TestU33InventoryIsInterview(t *testing.T) {
	requireStatus(t, evalU33(U33Input{Hidden: []string{"/home/alice/.netrc"}, Visited: 10}), StatusInterview)
}

func TestU34Finger(t *testing.T) {
	requireStatus(t, evalU34(U34Input{Finger: Service{Running: true}, EvidenceAvailable: true}), StatusVulnerable)
	requireStatus(t, evalU34(U34Input{EvidenceAvailable: true}), StatusGood)
	requireStatus(t, evalU34(U34Input{}), StatusInterview)
}

func TestU35AnonymousFTPConditional(t *testing.T) {
	requireStatus(t, evalU35(U35Input{EvidenceAvailable: true}), StatusGood)
	requireStatus(t, evalU35(U35Input{FTP: Service{Running: true}, EvidenceAvailable: true}), StatusInterview)
	requireStatus(t, evalU35(U35Input{FTP: Service{Running: true}, ConfigPresent: true, FTPAccess: "anonymous enable"}), StatusVulnerable)
	requireStatus(t, evalU35(U35Input{FTP: Service{Running: true}, ConfigPresent: true, FTPAccess: "anonymous_enable=NO"}), StatusGood)
}

func TestU36RServices(t *testing.T) {
	requireStatus(t, evalU36(U36Input{RServices: Service{InetdMatches: []string{"shell"}, Running: true}, EvidenceAvailable: true}), StatusVulnerable)
	requireStatus(t, evalU36(U36Input{EvidenceAvailable: true}), StatusGood)
}

func TestU37AIXCronPermissions(t *testing.T) {
	good := U37Input{Paths: []U37Path{{Path: "/var/adm/cron/cron.allow", Exists: true, Owner: "root", Mode: 0640}}}
	requireStatus(t, evalU37(good), StatusGood)
	good.Paths[0].Mode = 0666
	requireStatus(t, evalU37(good), StatusVulnerable)
	requireStatus(t, evalU37(U37Input{}), StatusInterview)
}

func TestU38LegacyServices(t *testing.T) {
	requireStatus(t, evalU38(U38Input{Legacy: Service{Running: true}, EvidenceAvailable: true}), StatusVulnerable)
	requireStatus(t, evalU38(U38Input{EvidenceAvailable: true}), StatusGood)
}

func TestU39NFS(t *testing.T) {
	requireStatus(t, evalU39(U39Input{NFS: Service{Running: true}, EvidenceAvailable: true}), StatusInterview)
	requireStatus(t, evalU39(U39Input{EvidenceAvailable: true}), StatusGood)
}

func TestU40AIXExportsRestrictions(t *testing.T) {
	requireStatus(t, evalU40(U40Input{}), StatusNotApplicable)
	requireStatus(t, evalU40(U40Input{ConfigPresent: true, Exports: "/srv -access=host1:host2,ro"}), StatusGood)
	requireStatus(t, evalU40(U40Input{ConfigPresent: true, Exports: "/srv -ro"}), StatusVulnerable)
}

func TestU41Automount(t *testing.T) {
	requireStatus(t, evalU41(U41Input{Automount: Service{Running: true}, EvidenceAvailable: true}), StatusInterview)
	requireStatus(t, evalU41(U41Input{EvidenceAvailable: true}), StatusGood)
}

func TestU42RPC(t *testing.T) {
	requireStatus(t, evalU42(U42Input{RPC: Service{Running: true}, EvidenceAvailable: true}), StatusInterview)
	requireStatus(t, evalU42(U42Input{EvidenceAvailable: true}), StatusGood)
}

func TestU43NIS(t *testing.T) {
	requireStatus(t, evalU43(U43Input{NIS: Service{Running: true}, EvidenceAvailable: true}), StatusVulnerable)
	requireStatus(t, evalU43(U43Input{NIS: Service{Listening: true}, EvidenceAvailable: true}), StatusInterview)
	requireStatus(t, evalU43(U43Input{EvidenceAvailable: true}), StatusGood)
}

func TestU44TFTPTalk(t *testing.T) {
	requireStatus(t, evalU44(U44Input{TFTP: Service{Running: true}, EvidenceAvailable: true}), StatusVulnerable)
	requireStatus(t, evalU44(U44Input{EvidenceAvailable: true}), StatusGood)
	requireStatus(t, evalU44(U44Input{}), StatusInterview)
}
