package main

import (
	"strings"
	"testing"
)

func TestParseSQLPlusRows(t *testing.T) {
	output := "\n os_roles |~| FALSE\r\nremote_os_roles|~|TRUE\n"
	rows, err := parseSQLPlusRows(output)
	if err != nil {
		t.Fatalf("parseSQLPlusRows returned error: %v", err)
	}
	if len(rows) != 2 || len(rows[0]) != 2 {
		t.Fatalf("unexpected rows: %#v", rows)
	}
	if rows[0][0] != "os_roles" || rows[0][1] != "FALSE" {
		t.Fatalf("unexpected first row: %#v", rows[0])
	}
}

func TestParseSQLPlusRowsRejectsUnexpectedOutput(t *testing.T) {
	if _, err := parseSQLPlusRows("Connected to Oracle Database"); err == nil {
		t.Fatal("expected unexpected output to fail")
	}
}

func TestRedactOracleError(t *testing.T) {
	secret := "audit_user/super-secret@prod"
	message := "connect " + secret + "\nORA-01017: invalid username/password; password=super-secret"
	got := redactOracleError(message, secret)

	for _, forbidden := range []string{secret, "super-secret"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redacted output contains secret %q: %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "ORA-01017") {
		t.Fatalf("redaction removed useful Oracle error code: %q", got)
	}
}
