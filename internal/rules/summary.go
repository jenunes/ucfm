package rules

import "fmt"

// Helpers for the "No issues found: <summary>" clauses (see Context.Checked).

// count writes "1 member" or "3 members".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// members writes "1 member" or "3 members".
func members(n int) string { return count(n, "member", "members") }

// plural64 writes "1 use" or "42 uses".
func plural64(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
