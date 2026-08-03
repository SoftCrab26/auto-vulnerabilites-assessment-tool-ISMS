package main

import (
	"strconv"
	"strings"
)

// isOracle12cOrNewer reports whether version looks like Oracle 12c or newer.
// Examples: "11.2.0.4.0" -> false, "12.1.0.2.0" / "19.0.0.0.0" -> true.
// Unparseable versions prefer the 11g-compatible query path.
func isOracle12cOrNewer(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	majorStr := version
	if i := strings.IndexAny(version, "."); i >= 0 {
		majorStr = version[:i]
	}
	// Strip leading non-digits (defensive).
	majorStr = strings.TrimLeftFunc(majorStr, func(r rune) bool {
		return r < '0' || r > '9'
	})
	if majorStr == "" {
		return false
	}
	end := 0
	for end < len(majorStr) && majorStr[end] >= '0' && majorStr[end] <= '9' {
		end++
	}
	major, err := strconv.Atoi(majorStr[:end])
	if err != nil {
		return false
	}
	return major >= 12
}

func useOracle12cSQL(scanCtx ScanContext) bool {
	if scanCtx.MetadataErr != nil {
		return false
	}
	return isOracle12cOrNewer(scanCtx.Metadata.Version)
}
