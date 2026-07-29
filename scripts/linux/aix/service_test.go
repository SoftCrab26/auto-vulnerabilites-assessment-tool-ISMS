package main

import "testing"

func TestParseActiveSRC(t *testing.T) {
	raw := `Subsystem         Group            PID          Status
 sshd              ssh              12345        active
 named             tcpip                         inoperative`

	active := parseActiveSRC(raw)
	if !active["sshd"] {
		t.Fatal("expected sshd to be active")
	}
	if active["named"] {
		t.Fatal("did not expect named to be active")
	}
}

func TestParseActiveInetd(t *testing.T) {
	raw := `#telnet stream tcp6 nowait root /usr/sbin/telnetd telnetd
ftp stream tcp6 nowait root /usr/sbin/ftpd ftpd
shell stream tcp6 nowait root /usr/sbin/rshd rshd`

	active := parseActiveInetd(raw)
	if active["telnet"] {
		t.Fatal("commented telnet entry must not be active")
	}
	if !active["ftp"] || !active["shell"] {
		t.Fatal("expected ftp and shell entries to be active")
	}
}

func TestRuntimeDataHasAnyPort(t *testing.T) {
	runtimeData := RuntimeData{
		PortList: "tcp4 0 0 *.22 *.* LISTEN\ntcp4 0 0 127.0.0.1.111 *.* LISTEN",
	}
	if !runtimeData.HasAnyPort("22", "111") {
		t.Fatal("expected AIX netstat ports to be detected")
	}
	if runtimeData.HasAnyPort("23") {
		t.Fatal("did not expect port 23")
	}
}
