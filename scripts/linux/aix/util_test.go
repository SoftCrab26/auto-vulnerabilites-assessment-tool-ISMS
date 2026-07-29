package main

import "testing"

func TestFindStanzaValue(t *testing.T) {
	raw := "default:\n\tloginretries = 5\n\nroot:\n\trlogin = false\n\tsugroups = system\n"

	if got := findStanzaValue(raw, "root", "rlogin"); got != "false" {
		t.Fatalf("findStanzaValue() = %q, want false", got)
	}
	if got := findStanzaValue(raw, "default", "loginretries"); got != "5" {
		t.Fatalf("findStanzaValue() = %q, want 5", got)
	}
	if got := findStanzaValue(raw, "root", "missing"); got != "NOT_FOUND" {
		t.Fatalf("findStanzaValue() = %q, want NOT_FOUND", got)
	}
}

func TestExtractStanza(t *testing.T) {
	raw := "default:\n\tlogin = true\n\nroot:\n\trlogin = false\n\tsugroups = system\n\nuser1:\n\tlogin = true\n"
	want := "root:\n\trlogin = false\n\tsugroups = system"

	if got := extractStanza(raw, "root"); got != want {
		t.Fatalf("extractStanza() = %q, want %q", got, want)
	}
}
