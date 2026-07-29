package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseKeyValuesQuotedUnquotedAndComments(t *testing.T) {
	raw := strings.Join([]string{
		`# full-line comment`,
		`majorversion="6" # trailing comment`,
		`minorversion=2`,
		`description="value # retained"`,
		`single='quoted value'`,
		`empty=`,
		`invalid line`,
	}, "\n")

	values := parseKeyValues(raw)
	want := map[string]string{
		"majorversion": "6",
		"minorversion": "2",
		"description":  "value # retained",
		"single":       "quoted value",
		"empty":        "",
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("values = %#v, want %#v", values, want)
	}
}

func TestPreferredDSMPathsOrder(t *testing.T) {
	want := []string{"/etc/synoinfo.conf", "/etc.defaults/synoinfo.conf"}
	if got := preferredDSMPaths("synoinfo.conf"); !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %#v, want %#v", got, want)
	}
}

func TestCollectFirstExistingOrderAndErrors(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	fallback := filepath.Join(directory, "fallback")
	if err := os.WriteFile(fallback, []byte("fallback"), 0o600); err != nil {
		t.Fatal(err)
	}

	file, errors := collectFirstExisting(missing, fallback)
	if file.Path != fallback || file.Content != "fallback" {
		t.Fatalf("unexpected file: %+v", file)
	}
	if len(errors) != 1 || !strings.Contains(errors[0], missing) {
		t.Fatalf("read failure was not returned: %#v", errors)
	}

	preferred := filepath.Join(directory, "preferred")
	if err := os.WriteFile(preferred, []byte("preferred"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, errors = collectFirstExisting(preferred, fallback)
	if file.Path != preferred || len(errors) != 0 {
		t.Fatalf("first path was not preferred: file=%+v errors=%#v", file, errors)
	}
}

func TestSanitizedFilename(t *testing.T) {
	if got := sanitizedFilename(" NAS / office:1 "); got != "NAS_office_1" {
		t.Fatalf("sanitizedFilename() = %q", got)
	}
}
