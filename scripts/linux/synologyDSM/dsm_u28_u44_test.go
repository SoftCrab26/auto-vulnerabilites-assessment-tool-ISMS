package main

import (
	"os"
	"strings"
	"testing"
)

func TestDSMU28ThroughU44Evaluation(t *testing.T) {
	t.Run("U28 requires manual firewall policy review", func(t *testing.T) {
		result := evalU28(U28Input{FirewallFound: true, Firewall: "enabled=yes"})
		dsmU28U44WantStatus(t, result, Manual)
		if result.RawConfig != "enabled=yes" {
			t.Fatalf("RawConfig = %q", result.RawConfig)
		}
		dsmU28U44WantStatus(t, evalU28(U28Input{HostsDeny: "ALL: ALL"}), Good)
	})

	t.Run("U29 absent is not applicable and unsafe mode is vulnerable", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU29(U29Input{Path: "/etc/hosts.lpd"}), NotApplicable)
		dsmU28U44WantStatus(t, evalU29(U29Input{Exists: true, Path: "/etc/hosts.lpd", Mode: 0o644}), Vulnerable)
		dsmU28U44WantStatus(t, evalU29(U29Input{Exists: true, Path: "/etc/hosts.lpd", Mode: 0o600}), Good)
	})

	t.Run("U30 parses octal umask", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU30(U30Input{LoginDefs: "UMASK 022"}), Good)
		dsmU28U44WantStatus(t, evalU30(U30Input{Profiles: "umask 002"}), Vulnerable)
	})

	t.Run("U31 checks owner and write bits", func(t *testing.T) {
		passwd := "alice:x:1024:100:Alice:/var/services/homes/alice:/bin/sh"
		good := U31Input{Passwd: passwd, Homes: []dsmU31Home{{User: "alice", Path: "/var/services/homes/alice", Exists: true, UID: 1024, Mode: 0o750}}}
		dsmU28U44WantStatus(t, evalU31(good), Good)
		good.Homes[0].Mode = 0o777
		dsmU28U44WantStatus(t, evalU31(good), Vulnerable)
	})

	t.Run("U32 reports missing home", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU32(U32Input{Passwd: "alice:x:1:1::/home/alice:/bin/sh", Homes: []dsmU32Home{{User: "alice", Path: "/home/alice"}}}), Vulnerable)
		dsmU28U44WantStatus(t, evalU32(U32Input{Passwd: "alice:x:1:1::/home/alice:/bin/sh", Homes: []dsmU32Home{{User: "alice", Path: "/home/alice", Exists: true}}}), Good)
	})

	t.Run("U33 is bounded manual review", func(t *testing.T) {
		result := evalU33(U33Input{Entries: []string{"/root/.ssh"}, Truncated: true})
		dsmU28U44WantStatus(t, result, Manual)
		if result.RawConfig != "/root/.ssh" || !strings.Contains(result.ProcessedConfig, "truncated=true") {
			t.Fatalf("unexpected evidence: %+v", result)
		}
	})

	t.Run("U34 does not claim good without evidence", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU34(U34Input{Complete: false}), Manual)
		dsmU28U44WantStatus(t, evalU34(U34Input{Complete: true}), Good)
		dsmU28U44WantStatus(t, evalU34(U34Input{Active: true}), Vulnerable)
	})

	t.Run("U35 is conditional on FTP", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU35(U35Input{}), NotApplicable)
		dsmU28U44WantStatus(t, evalU35(U35Input{FTPActive: true}), Manual)
		dsmU28U44WantStatus(t, evalU35(U35Input{FTPActive: true, ConfigFound: true, Config: "anonymous_enable=YES"}), Vulnerable)
		dsmU28U44WantStatus(t, evalU35(U35Input{FTPActive: true, ConfigFound: true, Config: "anonymous_enable=NO"}), Good)
	})

	t.Run("U36 disables r services", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU36(U36Input{Complete: true}), Good)
		dsmU28U44WantStatus(t, evalU36(U36Input{Active: []string{"rsh"}}), Vulnerable)
		dsmU28U44WantStatus(t, evalU36(U36Input{}), Manual)
	})

	t.Run("U37 checks cron and DSM task modes", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU37(U37Input{}), Manual)
		dsmU28U44WantStatus(t, evalU37(U37Input{Paths: []dsmU37Path{{Path: "/etc/crontab", Mode: os.FileMode(0o640)}}}), Good)
		dsmU28U44WantStatus(t, evalU37(U37Input{Paths: []dsmU37Path{{Path: "/usr/syno/etc/synoschedtask.conf", Mode: os.FileMode(0o666)}}}), Vulnerable)
	})

	t.Run("U38 disables legacy DoS services", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU38(U38Input{Complete: true}), Good)
		dsmU28U44WantStatus(t, evalU38(U38Input{Active: []string{"chargen(19)"}}), Vulnerable)
	})

	t.Run("U39 active NFS is manual necessity review", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU39(U39Input{Active: true, Evidence: "nfsd"}), Manual)
		dsmU28U44WantStatus(t, evalU39(U39Input{Complete: true}), NotApplicable)
	})

	t.Run("U40 checks exports only when NFS is active", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU40(U40Input{}), NotApplicable)
		dsmU28U44WantStatus(t, evalU40(U40Input{NFSActive: true}), Manual)
		dsmU28U44WantStatus(t, evalU40(U40Input{NFSActive: true, ExportsSeen: true, Exports: "/volume1/data *(rw,no_root_squash)"}), Vulnerable)
		dsmU28U44WantStatus(t, evalU40(U40Input{NFSActive: true, ExportsSeen: true, Exports: "/volume1/data 192.0.2.0/24(ro,root_squash)"}), Good)
	})

	t.Run("U41 disables automount", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU41(U41Input{Complete: true}), Good)
		dsmU28U44WantStatus(t, evalU41(U41Input{Active: true}), Vulnerable)
	})

	t.Run("U42 active RPC is manual necessity review", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU42(U42Input{Active: true, Evidence: "rpcbind"}), Manual)
		dsmU28U44WantStatus(t, evalU42(U42Input{Complete: true}), NotApplicable)
	})

	t.Run("U43 disables NIS", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU43(U43Input{Complete: true}), Good)
		dsmU28U44WantStatus(t, evalU43(U43Input{Active: true}), Vulnerable)
	})

	t.Run("U44 disables tftp and talk", func(t *testing.T) {
		dsmU28U44WantStatus(t, evalU44(U44Input{Complete: true}), Good)
		dsmU28U44WantStatus(t, evalU44(U44Input{Active: []string{"tftp(69)"}}), Vulnerable)
		dsmU28U44WantStatus(t, evalU44(U44Input{}), Manual)
	})
}

func dsmU28U44WantStatus(t *testing.T, result CheckResult, want Status) {
	t.Helper()
	if result.Status != want {
		t.Fatalf("Status = %v, want %v; result=%+v", result.Status, want, result)
	}
}
