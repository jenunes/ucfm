package rules

import (
	"fmt"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Host checks need ucfm to run on each database host with --local. These
// helpers tell the user which hosts were not checked and print the exact
// command to run on each, built from the password-free connection template.

var (
	ruleHostCoverage = Rule{
		ID: "host-checks-coverage", Title: "Host checks coverage",
		Category: "procedure", Scope: ScopeGlobal, Severity: Notice, DocURL: docProdNotes,
	}
	ruleProdHostCoverage = Rule{
		ID: "prod-host-coverage", Title: "Host checks coverage",
		Category: "procedure", Scope: ScopeProduction, Severity: Notice, DocURL: docProdNotes,
	}
)

func init() {
	ruleHostCoverage.Check = func(c *Context) []Finding { return hostCoverage(c, ruleHostCoverage, "check") }
	ruleProdHostCoverage.Check = func(c *Context) []Finding { return hostCoverage(c, ruleProdHostCoverage, "audit") }
	register(ruleHostCoverage, ruleProdHostCoverage)
}

// hostName strips the port from "host:port".
func hostName(hp string) string {
	if i := strings.LastIndex(hp, ":"); i >= 0 && !strings.Contains(hp[i:], "]") {
		return hp[:i]
	}
	return hp
}

// localHostCovers reports whether the --local host facts belong to node n.
func localHostCovers(h *snapshot.HostInfo, n snapshot.Node) bool {
	if h == nil {
		return false
	}
	if h.Node != "" {
		return h.Node == n.Host
	}
	if h.Hostname == "" {
		return false
	}
	return strings.EqualFold(hostName(n.HostInfo.Hostname), h.Hostname) ||
		strings.EqualFold(hostName(n.Host), h.Hostname)
}

// rerunCommand builds the command to run on one host.
func rerunCommand(s *snapshot.Snapshot, mode, target, host string) string {
	tmpl := s.Collection.ConnTemplate
	if tmpl == "" {
		tmpl = "mongodb://USER@{host}/?authSource=admin"
	}
	// No password in the command: ucfm asks for it when it runs.
	uri := strings.Replace(strings.Replace(tmpl, ":****@", "@", 1), "{host}", host, 1)
	if strings.Contains(uri, "?") {
		uri += "&directConnection=true"
	} else {
		uri += "?directConnection=true"
	}
	if mode == "audit" {
		return fmt.Sprintf(`ucfm audit --uri "%s" --local --entry-only`, uri)
	}
	return fmt.Sprintf(`ucfm check --uri "%s" --target %s --local --entry-only`, uri, target)
}

func hostCoverage(c *Context, r Rule, mode string) []Finding {
	var missing []snapshot.Node
	covered := ""
	for _, n := range c.Snap.DataNodes() {
		if localHostCovers(c.Snap.Host, n) {
			covered = n.Host
			continue
		}
		missing = append(missing, n)
	}
	if len(missing) == 0 {
		if n := len(c.Snap.DataNodes()); n == 1 {
			return c.Checked("host settings were checked on %s, the only data-bearing member.", covered)
		}
		return c.Checked("host settings were checked on every data-bearing member.")
	}
	var items, commands []string
	for _, n := range missing {
		items = append(items, n.Host)
		commands = append(commands, rerunCommand(c.Snap, mode, c.Target, n.Host))
	}
	msg := "Operating system settings (Transparent Huge Pages, kernel, glibc, limits, filesystem, NUMA, clock) were not checked: ucfm reads them only when it runs on the database host with --local."
	switch {
	case covered != "":
		msg = fmt.Sprintf("Host settings were checked on %s only. Run ucfm on the other database hosts to check theirs.", covered)
	case c.hostSkipped != "":
		msg = fmt.Sprintf("ucfm ran with --local on %s, which is not a host of this deployment; host settings were not checked. Run ucfm on each database host instead.", c.hostSkipped)
	}
	if n := osWarningCount(c.Snap); n > 0 {
		msg += fmt.Sprintf(" The servers logged %s about the operating system.", count(n, "startup warning", "startup warnings"))
	}
	action := "Copy ucfm to each host and run the command for it; ucfm asks for the password:"
	if c.Snap.Collection.ConnTemplate == "" {
		action = "Copy ucfm to each host and run the command for it, with your user in place of USER; ucfm asks for the password:"
	}
	f := r.finding(Notice, msg, items, action)
	f.Commands = commands
	return []Finding{f}
}

// osWarnings maps startup-warning text to the host check that covers it.
var osWarnings = []struct {
	pattern string
	check   string
}{
	{"transparent_hugepage", "Transparent Huge Pages"},
	{"transparent huge", "Transparent Huge Pages"},
	{"rlimit", "Process limits"},
	{"ulimit", "Process limits"},
	{"open files", "Process limits"},
	{"numa", "NUMA configuration"},
	{"swappiness", "Swappiness"},
	{"xfs", "dbPath filesystem type"},
	{"filesystem", "dbPath filesystem type"},
	{"max_map_count", "Kernel limits"},
	{"vm.max_map_count", "Kernel limits"},
	{"glibc", "glibc rseq and TCMalloc per-CPU caches"},
	{"rseq", "glibc rseq and TCMalloc per-CPU caches"},
	{"tcmalloc", "glibc rseq and TCMalloc per-CPU caches"},
}

// relatedHostCheck returns the host check covering a startup warning, or "".
func relatedHostCheck(msg string) string {
	m := strings.ToLower(msg)
	for _, w := range osWarnings {
		if strings.Contains(m, w.pattern) {
			return w.check
		}
	}
	return ""
}

func osWarningCount(s *snapshot.Snapshot) int {
	seen := map[string]bool{}
	for _, n := range s.Nodes {
		for _, w := range n.StartupWarnings {
			msg := warningMessage(w)
			if relatedHostCheck(msg) != "" {
				seen[msg] = true
			}
		}
	}
	return len(seen)
}
