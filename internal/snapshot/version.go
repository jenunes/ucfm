package snapshot

import (
	"strconv"
	"strings"
)

// MajorMinor reduces "8.0.12-4" or "7.0.29" to "8.0" / "7.0".
func MajorMinor(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "r")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return ""
	}
	minor := parts[1]
	if i := strings.IndexAny(minor, "-+"); i >= 0 {
		minor = minor[:i]
	}
	if _, err := strconv.Atoi(minor); err != nil {
		return ""
	}
	return parts[0] + "." + minor
}

// CompareVersions compares dotted numeric versions ("8.0" < "8.3" < "9.0",
// "7.0.9" < "7.0.29"). Non-numeric suffixes after '-' are ignored.
func CompareVersions(a, b string) int {
	pa, pb := splitNums(a), splitNums(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitNums(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "r")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// HostPart strips the port from "host:port" (IPv6 "[::1]:27017" -> "::1").
func HostPart(hp string) string {
	if strings.HasPrefix(hp, "[") {
		if i := strings.Index(hp, "]"); i > 0 {
			return hp[1:i]
		}
	}
	if i := strings.LastIndex(hp, ":"); i >= 0 && strings.Count(hp, ":") == 1 {
		return hp[:i]
	}
	return hp
}
