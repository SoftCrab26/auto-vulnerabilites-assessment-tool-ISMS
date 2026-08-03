package main

import "testing"

func TestIsOracle12cOrNewer(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"11.2.0.4.0", false},
		{"11.1.0.7.0", false},
		{"12.1.0.2.0", true},
		{"12.2.0.1.0", true},
		{"19.0.0.0.0", true},
		{"21.0.0.0.0", true},
		{"", false},
		{"bogus", false},
	}
	for _, test := range tests {
		if got := isOracle12cOrNewer(test.version); got != test.want {
			t.Fatalf("isOracle12cOrNewer(%q)=%v, want %v", test.version, got, test.want)
		}
	}
}
