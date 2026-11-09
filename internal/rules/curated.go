package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
	"github.com/jenunes/ucfm/internal/upgradepath"
)

// Curated per-hop rules. Every rule below is backed by an official page that
// was fetched while writing it; the key sentence is quoted in a comment and
// the page is the rule's DocURL. Things the catalogs already catch
// generically (removed options, parameters, commands, actions, agg operators)
// are not repeated here.

const (
	docTCMalloc       = "https://www.mongodb.com/docs/manual/administration/tcmalloc-performance/"
	docCompat70       = "https://www.mongodb.com/docs/manual/release-notes/7.0-compatibility/"
	docCompat80       = "https://www.mongodb.com/docs/manual/release-notes/8.0-compatibility/"
	docRelease83      = "https://www.mongodb.com/docs/manual/release-notes/8.3/"
	docCompat83       = "https://www.mongodb.com/docs/manual/release-notes/8.3-compatibility/"
	docCompat90       = "https://www.mongodb.com/docs/manual/release-notes/9.0-compatibility/"
	docPSMDBUpgrade70 = "https://docs.percona.com/percona-server-for-mongodb/7.0/install/upgrade-from-60.html"
	docPSMDBUpgrade80 = "https://docs.percona.com/percona-server-for-mongodb/8.0/install/upgrade-from-70.html"
	docPSMDBVault     = "https://docs.percona.com/percona-server-for-mongodb/8.0/vault.html"
	docPSMDBKMIP      = "https://docs.percona.com/percona-server-for-mongodb/8.0/kmip.html"
	hop60to70         = "6.0→7.0"
	hop70to80         = "7.0→8.0"
	hop80to83         = "8.0→8.3"
	hop80to90         = "8.0→9.0"
	hop83to90         = "8.3→9.0"
)

// hops parses "6.0→7.0" style names.
func hops(names ...string) []upgradepath.Hop {
	var out []upgradepath.Hop
	for _, n := range names {
		from, to, _ := strings.Cut(n, "→")
		out = append(out, upgradepath.Hop{From: from, To: to})
	}
	return out
}

// Hop sets: changes introduced in 8.3 also apply when jumping 8.0→9.0, and
// 9.0 changes apply from both 8.0 and 8.3.
var (
	hopsInto83 = hops(hop80to83, hop80to90)
	hopsInto90 = hops(hop80to90, hop83to90)
)

// firstHopReaching reports whether c.Hop is the first hop of the path whose
// target is at least v. Host-level 8.0+ requirements are reported once.
func firstHopReaching(c *Context, v string) bool {
	for _, h := range c.Hops {
		if snapshot.CompareVersions(h.To, v) >= 0 {
			return h == c.Hop
		}
	}
	return false
}

// selected returns the bracketed token of a sysfs selector line
// ("always [madvise] never" -> "madvise"); plain values are returned as is.
func selected(line string) string {
	line = strings.TrimSpace(line)
	if i := strings.Index(line, "["); i >= 0 {
		if j := strings.Index(line[i:], "]"); j > 0 {
			return line[i+1 : i+j]
		}
	}
	return line
}

// arches returns the distinct CPU architectures reported by hostInfo.
func arches(s *snapshot.Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, n := range s.Nodes {
		if a := strings.ToLower(n.HostInfo.CPUArch); a != "" {
			out[a] = true
		}
	}
	return out
}

// legacyTCMallocArch: "MongoDB uses the legacy TCMalloc version on the
// PPC64LE and s390x architectures, regardless of operating system version."
func legacyTCMallocArch(s *snapshot.Snapshot) bool {
	a := arches(s)
	return a["ppc64le"] || a["s390x"]
}

// optionSet reports whether any node (or the local config file) sets an
// option with the given name or prefix (prefix ends with ".").
func optionHosts(s *snapshot.Snapshot, nameOrPrefix string) []string {
	match := func(k string) bool {
		if strings.HasSuffix(nameOrPrefix, ".") {
			return strings.HasPrefix(k, nameOrPrefix)
		}
		return k == nameOrPrefix
	}
	var out []string
	for _, n := range s.Nodes {
		for k := range n.Options {
			if match(k) {
				out = append(out, n.Host)
				break
			}
		}
	}
	if s.Host != nil {
		for k := range s.Host.ConfigOptions {
			if match(k) {
				out = append(out, s.Host.ConfigFile)
				break
			}
		}
	}
	return out
}

// commandCalls sums serverStatus counters for a command across nodes.
func commandCalls(s *snapshot.Snapshot, cmd string) int64 {
	var total int64
	for _, n := range s.Nodes {
		total += n.CommandCounters[cmd]
	}
	return total
}

// parameterValues returns host -> value for a parameter, from startup
// parameters first, then runtime getParameter values.
func parameterValues(s *snapshot.Snapshot, name string) map[string]string {
	out := map[string]string{}
	for _, n := range s.Nodes {
		raw, ok := n.StartupParameters[name]
		if !ok {
			raw, ok = n.Parameters[name]
		}
		if ok {
			out[n.Host] = jsonScalar(raw)
		}
	}
	return out
}

func jsonScalar(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// encryptedQueryTypes returns ns -> queryTypes used in encryptedFields.
func encryptedQueryTypes(s *snapshot.Snapshot) map[string][]string {
	out := map[string][]string{}
	for _, db := range s.Data.Databases {
		for _, coll := range db.Collections {
			if len(coll.EncryptedFields) == 0 {
				continue
			}
			ns := db.Name + "." + coll.Name
			var ef struct {
				Fields []struct {
					Queries json.RawMessage `json:"queries"`
				} `json:"fields"`
			}
			out[ns] = []string{}
			if json.Unmarshal(coll.EncryptedFields, &ef) != nil {
				continue
			}
			for _, f := range ef.Fields {
				// queries is a document or an array of documents.
				var one struct {
					QueryType string `json:"queryType"`
				}
				var many []struct {
					QueryType string `json:"queryType"`
				}
				if json.Unmarshal(f.Queries, &many) == nil {
					for _, q := range many {
						out[ns] = append(out[ns], q.QueryType)
					}
				} else if json.Unmarshal(f.Queries, &one) == nil && one.QueryType != "" {
					out[ns] = append(out[ns], one.QueryType)
				}
			}
		}
	}
	return out
}

// pipelines yields (namespace, what, raw) for every view pipeline and
// validator in the snapshot.
func pipelines(s *snapshot.Snapshot, fn func(ns, what string, raw json.RawMessage)) {
	for _, db := range s.Data.Databases {
		for _, coll := range db.Collections {
			ns := db.Name + "." + coll.Name
			if len(coll.Pipeline) > 0 {
				fn(ns, "view pipeline", coll.Pipeline)
			}
			if len(coll.Validator) > 0 {
				fn(ns, "validator", coll.Validator)
			}
		}
	}
}

// kernelVersions returns kernel -> hosts from hostInfo and the local host.
func kernelVersions(s *snapshot.Snapshot) map[string][]string {
	out := map[string][]string{}
	for _, n := range s.Nodes {
		k := n.HostInfo.KernelVersion
		if k == "" {
			// Some builds report the kernel only as os.version "Kernel 6.12.115-...".
			k = strings.TrimSpace(strings.TrimPrefix(n.HostInfo.OSVersion, "Kernel "))
			if k == n.HostInfo.OSVersion {
				k = ""
			}
		}
		if k != "" {
			out[k] = append(out[k], n.Host)
		}
	}
	if s.Host != nil && s.Host.KernelVersion != "" && len(out) == 0 {
		out[s.Host.KernelVersion] = append(out[s.Host.KernelVersion], s.Host.Hostname)
	}
	return out
}

// kernelNumeric strips distro suffixes: "6.12.115+deb13.1-amd64" -> "6.12.115".
func kernelNumeric(k string) string {
	end := 0
	for end < len(k) && (k[end] == '.' || (k[end] >= '0' && k[end] <= '9')) {
		end++
	}
	return strings.Trim(k[:end], ".")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Host requirements for the new TCMalloc (first hop reaching 8.0).

var ruleTHP = Rule{
	ID: "thp-enabled-for-8.0", Title: "Transparent Huge Pages for MongoDB 8.0 and later",
	Category: "host", Scope: ScopeHop, Severity: Warning, DocURL: docTCMalloc,
	Hops: hops(hop70to80, hop80to83, hop80to90, hop83to90),
	// tcmalloc-performance: "In MongoDB 8.0 and later, ensure that THP is
	// enabled before mongod starts" — service file sets enabled=always,
	// defrag=defer+madvise, khugepaged/max_ptes_none=0.
	// Production notes: "If you are running MongoDB 7.0 or earlier, disable
	// Transparent Hugepages" (the recommendation is reversed in 8.0).
	Check: func(c *Context) []Finding {
		h := c.Snap.Host
		if !firstHopReaching(c, "8.0") {
			return c.NotApplicable("checked on the step that first reaches 8.0")
		}
		if legacyTCMallocArch(c.Snap) {
			return c.NotApplicable("ppc64le/s390x use the legacy TCMalloc")
		}
		if h == nil {
			return c.NotChecked(c.localReason())
		}
		if h.THPEnabled == "" && h.THPDefrag == "" && h.THPMaxPtesNone == "" {
			return c.NotChecked(fmt.Sprintf("the Transparent Huge Pages settings were not reported on %s.", h.Hostname))
		}
		var items []string
		if h.THPEnabled != "" && selected(h.THPEnabled) != "always" {
			items = append(items, fmt.Sprintf("transparent_hugepage/enabled = %s (want always)", selected(h.THPEnabled)))
		}
		if h.THPDefrag != "" && selected(h.THPDefrag) != "defer+madvise" {
			items = append(items, fmt.Sprintf("transparent_hugepage/defrag = %s (want defer+madvise)", selected(h.THPDefrag)))
		}
		if h.THPMaxPtesNone != "" && strings.TrimSpace(h.THPMaxPtesNone) != "0" {
			items = append(items, fmt.Sprintf("khugepaged/max_ptes_none = %s (want 0)", strings.TrimSpace(h.THPMaxPtesNone)))
		}
		if len(items) == 0 {
			return c.Checked("Transparent Huge Pages on %s match what 8.0 needs (enabled=always, defrag=defer+madvise, khugepaged/max_ptes_none=0).", h.Hostname)
		}
		f := ruleTHPFinding(c, items, h.Hostname)
		return []Finding{f}
	},
}

func ruleTHPFinding(c *Context, items []string, host string) Finding {
	msg := fmt.Sprintf("MongoDB 8.0 and later use a new TCMalloc with per-CPU caches and need THP enabled before mongod starts; host %s is configured the 7.0-and-earlier way (THP disabled). Leaving it disabled hurts memory efficiency and performance after the upgrade.", host)
	f := rule("thp-enabled-for-8.0").finding(Warning, msg, items,
		"Before starting the 8.0 binaries, set THP enabled=always, defrag=defer+madvise and khugepaged/max_ptes_none=0 through a boot-time service (and a custom tuned profile on RHEL with tuned), on every host.")
	if c.Flavor == "psmdb" {
		// PSMDB upgrade-from-70: "Enable Transparent Hugepages (THP) before
		// starting Percona Server for MongoDB 8.0."
		f.DocURL = docPSMDBUpgrade80
	}
	return f
}

var ruleRseq = Rule{
	ID: "tcmalloc-glibc-rseq", Title: "glibc rseq and TCMalloc per-CPU caches",
	Category: "host", Scope: ScopeHop, Severity: Notice, DocURL: docTCMalloc,
	Hops: hops(hop70to80, hop80to83, hop80to90, hop83to90),
	// tcmalloc-performance: "If another application, such as the glibc
	// library, registers an rseq structure before TCMalloc, TCMalloc can't use
	// rseq." Fix: "GLIBC_TUNABLES=glibc.pthread.rseq=0" before starting mongod.
	Check: func(c *Context) []Finding {
		h := c.Snap.Host
		if !firstHopReaching(c, "8.0") {
			return c.NotApplicable("checked on the step that first reaches 8.0")
		}
		if legacyTCMallocArch(c.Snap) {
			return c.NotApplicable("ppc64le/s390x use the legacy TCMalloc")
		}
		// Servers already on the 8.0+ TCMalloc report the outcome directly.
		off, reported, all := perCPUCaches(c.Snap)
		if len(off) > 0 {
			return []Finding{rule("tcmalloc-glibc-rseq").finding(Notice,
				"These servers run the 8.0+ TCMalloc without per-CPU caches (serverStatus tcmalloc.usingPerCPUCaches is false). The upgraded binaries use the same TCMalloc, so the condition stays after the upgrade.",
				off, perCPUAction)}
		}
		if reported > 0 && all {
			return c.Checked("all %s report serverStatus tcmalloc.usingPerCPUCaches true.", members(reported))
		}
		if h == nil {
			return c.NotChecked(c.localReason())
		}
		var items []string
		readable := 0
		for _, p := range h.MongodProcesses {
			if !p.EnvReadable {
				continue
			}
			readable++
			if !strings.Contains(p.GlibcTunables, "glibc.pthread.rseq=0") {
				items = append(items, fmt.Sprintf("pid %d %s: GLIBC_TUNABLES=%q", p.PID, p.Name, p.GlibcTunables))
			}
		}
		if len(items) == 0 {
			if readable == 0 {
				return c.NotChecked(fmt.Sprintf("no mongod process environment on %s was readable, so GLIBC_TUNABLES could not be compared (run ucfm as root or as the mongod user).", h.Hostname))
			}
			return c.Checked("%s on %s set GLIBC_TUNABLES=glibc.pthread.rseq=0.",
				count(readable, "mongod process", "mongod processes"), h.Hostname)
		}
		msg := "The running mongod processes do not set GLIBC_TUNABLES=glibc.pthread.rseq=0. If glibc registers rseq first, the 8.0+ TCMalloc cannot use per-CPU caches."
		if h.GlibcVersion != "" {
			msg += fmt.Sprintf(" (glibc %s on %s)", h.GlibcVersion, h.Hostname)
		}
		return []Finding{rule("tcmalloc-glibc-rseq").finding(Notice, msg, items,
			"Add GLIBC_TUNABLES=glibc.pthread.rseq=0 to the mongod service environment, and after the upgrade verify serverStatus().tcmalloc.usingPerCPUCaches is true.")}
	},
}

// perCPUAction is the fix the tcmalloc-performance page gives for missing
// per-CPU caches.
const perCPUAction = "Set GLIBC_TUNABLES=glibc.pthread.rseq=0 in the mongod service environment, make sure the host runs Linux kernel 4.18 or later, restart mongod, then check that serverStatus().tcmalloc.usingPerCPUCaches is true and tcmalloc.tcmalloc.cpu_free is greater than 0."

// perCPUCaches reads serverStatus tcmalloc.usingPerCPUCaches, which only the
// 8.0+ TCMalloc reports. off lists the servers without per-CPU caches;
// reported counts the servers that reported the field; all is true when
// every server reported it.
func perCPUCaches(s *snapshot.Snapshot) (off []string, reported int, all bool) {
	all = len(s.Nodes) > 0
	for _, n := range s.Nodes {
		if n.TCMalloc == nil {
			all = false
			continue
		}
		reported++
		if !n.TCMalloc.UsingPerCPUCaches {
			off = append(off, fmt.Sprintf("%s: usingPerCPUCaches false (cpu_free %d bytes)", n.Host, n.TCMalloc.CPUFreeBytes))
		}
	}
	return off, reported, all
}

var ruleKernel = Rule{
	ID: "kernel-tcmalloc-compat", Title: "Linux kernel compatibility with the 8.0 TCMalloc",
	Category: "platform", Scope: ScopeHop, Severity: Error,
	DocURL: "https://www.mongodb.com/docs/manual/administration/production-notes/",
	Hops:   hops(hop70to80, hop80to83, hop80to90, hop83to90),
	// Production notes: "running MongoDB with a Linux kernel version from 6.19
	// through 7.0.13 can cause MongoDB to crash. To prevent this crash,
	// MongoDB detects these kernel versions and stops during startup."
	// tcmalloc-performance: per-CPU caches need "Linux kernel version 4.18 or later".
	Check: func(c *Context) []Finding {
		if !firstHopReaching(c, "8.0") {
			return c.NotApplicable("checked on the step that first reaches 8.0")
		}
		if len(kernelVersions(c.Snap)) == 0 {
			return c.NotChecked("No kernel version was reported; run ucfm with --local on the database host.")
		}
		var bad, old []string
		for _, k := range sortedKeys(kernelVersions(c.Snap)) {
			hosts := kernelVersions(c.Snap)[k]
			v := kernelNumeric(k)
			if v == "" {
				continue
			}
			item := fmt.Sprintf("%s [%s]", k, summarizeHosts(hosts))
			switch {
			case snapshot.CompareVersions(v, "6.19") >= 0 && snapshot.CompareVersions(v, "7.0.13") <= 0:
				bad = append(bad, item)
			case snapshot.CompareVersions(v, "4.18") < 0:
				old = append(old, item)
			}
		}
		var out []Finding
		kernels := kernelVersions(c.Snap)
		if len(bad) == 0 && (len(old) == 0 || legacyTCMallocArch(c.Snap)) {
			hosts := 0
			for _, h := range kernels {
				hosts += len(h)
			}
			return c.Checked("checked %s (%s) on %s; none is in the 6.19 to 7.0.13 crash range or older than 4.18.",
				count(len(kernels), "kernel", "kernels"), strings.Join(sortedKeys(kernels), ", "), count(hosts, "host", "hosts"))
		}
		if len(bad) > 0 {
			out = append(out, ruleKernelFinding(Error,
				"These hosts run a Linux kernel between 6.19 and 7.0.13. MongoDB detects these kernels and stops during startup because the vendored TCMalloc can crash on them.",
				bad, "Upgrade the kernel to 7.0.14 or later (or use a kernel outside the affected range) before installing the new binaries."))
		}
		if len(old) > 0 && !legacyTCMallocArch(c.Snap) {
			f := ruleKernelFinding(Warning,
				"These hosts run a kernel older than 4.18, so the 8.0+ TCMalloc cannot enable per-CPU caches.",
				old, "Move to a supported distribution kernel 4.18 or later.")
			f.DocURL = docTCMalloc
			out = append(out, f)
		}
		return out
	},
}

func ruleKernelFinding(sev Severity, msg string, items []string, action string) Finding {
	return Finding{RuleID: "kernel-tcmalloc-compat", Severity: sev, Category: "platform",
		Title: "Linux kernel compatibility with the 8.0 TCMalloc", Message: msg, Items: items, Action: action,
		DocURL: "https://www.mongodb.com/docs/manual/administration/production-notes/"}
}

// ---------------------------------------------------------------------------
// 6.0 → 7.0

var ruleQEPreview70 = Rule{
	ID: "qe-preview-6x", Title: "Queryable Encryption 6.x preview collections",
	Category: "data", Scope: ScopeHop, Severity: Warning, DocURL: docCompat70, Hops: hops(hop60to70),
	// 7.0-compatibility: "You cannot use MongoDB 6.x compatible drivers with a
	// 7.0 server, or 7.0 compatible drivers with a 6.x server." Preferred path:
	// create a new encrypted collection after upgrading and re-ingest.
	Check: func(c *Context) []Finding {
		if !dataCollected(c.Snap) {
			return c.NotChecked(needData)
		}
		nss := sortedKeys(encryptedQueryTypes(c.Snap))
		if len(nss) == 0 {
			return qeNotUsed(c)
		}
		return []Finding{rule("qe-preview-6x").finding(Warning,
			"These collections use Queryable Encryption from the 6.x public preview. 7.0 Queryable Encryption is GA and incompatible with the preview: 6.x drivers cannot talk to a 7.0 server, and 7.0 drivers cannot query preview-encrypted fields.",
			nss, "Plan the migration before upgrading: after the upgrade, create new encrypted collections with 7.0 drivers and re-ingest the data (mongodump/mongoexport do not decrypt).")}
	},
}

var ruleViewsOnBuckets = Rule{
	ID: "views-on-system-buckets", Title: "Views on system.buckets namespaces",
	Category: "data", Scope: ScopeHop, Severity: Error, DocURL: docCompat70, Hops: hops(hop60to70),
	// 7.0-compatibility (6.1 changes): views on system.buckets are "not
	// permitted. Drop any existing views on these namespaces before upgrading."
	Check: func(c *Context) []Finding {
		if !dataCollected(c.Snap) {
			return c.NotChecked(needData)
		}
		var items []string
		views := 0
		for _, db := range c.Snap.Data.Databases {
			for _, coll := range db.Collections {
				if coll.Type == "view" {
					views++
				}
				if coll.Type == "view" && strings.HasPrefix(coll.ViewOn, "system.buckets.") {
					items = append(items, fmt.Sprintf("%s.%s (on %s)", db.Name, coll.Name, coll.ViewOn))
				}
			}
		}
		if len(items) == 0 {
			if views == 0 {
				return c.Checked("the deployment has no views, including those hidden from listCollections.")
			}
			return c.Checked("checked %s, including those hidden from listCollections; none is defined on a system.buckets collection.", count(views, "view", "views"))
		}
		return []Finding{rule("views-on-system-buckets").finding(Error,
			"Views defined on system.buckets.* collections are not permitted starting in 6.1.",
			items, "Drop these views before upgrading.")}
	},
}

var ruleFreeMonitoring = Rule{
	ID: "free-monitoring-decommissioned", Title: "Free monitoring settings",
	Category: "config", Scope: ScopeHop, Severity: Notice, DocURL: docCompat70, Hops: hops(hop60to70),
	// 7.0-compatibility: "Starting in MongoDB 7.0, free monitoring is
	// decommissioned." Affects cloud.monitoring.free, --enableFreeMonitoring,
	// db.enableFreeMonitoring()/disableFreeMonitoring(), setFreeMonitoring.
	Check: func(c *Context) []Finding {
		if !optionsReported(c.Snap) && !countersReported(c.Snap) {
			return c.NotChecked("no member reported its startup options or command counters.")
		}
		var items []string
		for _, h := range optionHosts(c.Snap, "cloud.monitoring.free.") {
			items = append(items, "cloud.monitoring.free.* set on "+h)
		}
		if n := commandCalls(c.Snap, "setFreeMonitoring"); n > 0 {
			items = append(items, fmt.Sprintf("setFreeMonitoring called %s", plural64(int64(n), "time", "times")))
		}
		if len(items) == 0 {
			if !countersReported(c.Snap) {
				return c.Checked("cloud.monitoring.free is not set on %s; setFreeMonitoring calls could not be counted (no command counters).", members(len(c.Snap.Nodes)))
			}
			if !optionsReported(c.Snap) {
				return c.Checked("setFreeMonitoring was not called on %s since the servers started; the startup options were not reported.", members(len(c.Snap.Nodes)))
			}
			return c.Checked("cloud.monitoring.free is not set on %s, and setFreeMonitoring was not called since the servers started.", members(len(c.Snap.Nodes)))
		}
		return []Finding{rule("free-monitoring-decommissioned").finding(Notice,
			"Free monitoring settings or calls were found; free monitoring no longer exists in 7.0.",
			items, "Remove the cloud.monitoring.free settings and any automation calling setFreeMonitoring.")}
	},
}

// deprecatedParams: parameters a compatibility page lists as deprecated in
// the hop target. Removal is caught by the catalog diff; this is the warning
// before removal.
var deprecatedParams = []struct {
	hop, name, doc, note string
}{
	// 7.0-compatibility: taskExecutorPoolSize "Deprecated only for Linux in 7.0."
	{hop60to70, "taskExecutorPoolSize", docCompat70, "deprecated on Linux in 7.0"},
	// 8.0-compatibility: tcmallocAggressiveMemoryDecommit and
	// enableFinerGrainedCatalogCacheRefresh are deprecated.
	{hop70to80, "tcmallocAggressiveMemoryDecommit", docCompat80, "deprecated in 8.0"},
	{hop70to80, "enableFinerGrainedCatalogCacheRefresh", docCompat80, "deprecated in 8.0"},
}

var ruleDeprecatedParams = Rule{
	ID: "parameter-deprecated", Title: "Usage of deprecated server parameters",
	Category: "parameters", Scope: ScopeHop, Severity: Notice, DocURL: docServerParams,
	Hops: hops(hop60to70, hop70to80),
	Check: func(c *Context) []Finding {
		if !optionsReported(c.Snap) {
			return c.NotChecked(noOptions)
		}
		params := startupParams(c.Snap)
		var items, names []string
		doc := ""
		for _, d := range deprecatedParams {
			if d.hop != c.Hop.From+"→"+c.Hop.To {
				continue
			}
			names = append(names, d.name)
			if hosts, ok := params[d.name]; ok {
				items = append(items, fmt.Sprintf("%s: %s [%s]", d.name, d.note, summarizeHosts(hosts)))
				doc = d.doc
			}
		}
		if len(items) == 0 {
			return c.Checked("none of the parameters deprecated in %s (%s) is set at startup on %s.",
				c.Hop.To, strings.Join(names, ", "), members(len(c.Snap.Nodes)))
		}
		f := rule("parameter-deprecated").finding(Notice, "These startup parameters are deprecated in the target release and will be removed in a future one.",
			items, "Plan to stop setting them.")
		f.DocURL = doc
		return []Finding{f}
	},
}

// ---------------------------------------------------------------------------
// 7.0 → 8.0

var ruleRangePreview = Rule{
	ID: "qe-range-preview-removed", Title: "Queryable Encryption rangePreview fields",
	Category: "data", Scope: ScopeHop, Severity: Error, DocURL: docCompat80, Hops: hops(hop70to80),
	// 8.0-compatibility: the rangePreview Queryable Encryption algorithm is
	// "deprecated and removed ... Use the range algorithm instead."
	Check: func(c *Context) []Finding {
		if !dataCollected(c.Snap) {
			return c.NotChecked(needData)
		}
		var items []string
		qe := encryptedQueryTypes(c.Snap)
		for ns, types := range qe {
			for _, t := range types {
				if t == "rangePreview" {
					items = append(items, ns)
					break
				}
			}
		}
		if len(items) == 0 {
			if len(qe) == 0 {
				return qeNotUsed(c)
			}
			return c.Checked("checked %s; none uses the rangePreview query type.", count(len(qe), "encrypted collection", "encrypted collections"))
		}
		sort.Strings(items)
		return []Finding{rule("qe-range-preview-removed").finding(Error,
			"These encrypted collections use the rangePreview query type, which 8.0 removes.",
			items, "Recreate the encrypted fields with the range algorithm (new collection + re-ingest through a driver) before upgrading.")}
	},
}

var ruleLDAPDeprecated = Rule{
	ID: "ldap-deprecated", Title: "LDAP authentication and authorization",
	Category: "security", Scope: ScopeHop, Severity: Notice, DocURL: docCompat80,
	Hops: hops(hop70to80), Flavors: []string{"community"},
	// 8.0-compatibility: "LDAP authentication and authorization is
	// deprecated." It will be removed in a future major release.
	// (MongoDB Enterprise feature; PSMDB has its own LDAP implementation.)
	Check: func(c *Context) []Finding {
		if !optionsReported(c.Snap) {
			return c.NotChecked(noOptions)
		}
		hosts := optionHosts(c.Snap, "security.ldap.")
		if len(hosts) == 0 {
			return c.Checked("LDAP (security.ldap) is not configured on %s.", members(len(c.Snap.Nodes)))
		}
		return []Finding{rule("ldap-deprecated").finding(Notice,
			"LDAP is configured. MongoDB 8.0 deprecates LDAP authentication and authorization and plans to remove it in a future major release.",
			hosts, "Plan a move to another mechanism (for example OIDC, x.509 or SCRAM).")}
	},
}

// deprecatedCommands: commands a compatibility page deprecates; flagged when
// clients actually call them.
var deprecatedCommands = []struct {
	hops     []upgradepath.Hop
	cmd, msg string
	doc      string
}{
	// 8.0-compatibility: index filters deprecated — "use query settings
	// instead of adding index filters."
	{hops(hop70to80), "planCacheSetFilter", "index filters are deprecated in 8.0; use setQuerySettings", docCompat80},
	// 8.0-compatibility: "MongoDB 8.0 deprecates the cleanupOrphaned command."
	{hops(hop70to80), "cleanupOrphaned", "cleanupOrphaned is deprecated in 8.0; use $shardedDataDistribution to monitor orphans", docCompat80},
	// 8.3 release notes: "the removeShard command is deprecated."
	{hopsInto83, "removeShard", "removeShard is deprecated in 8.3; use startShardDraining / shardDrainingStatus / commitShardRemoval", docRelease83},
}

var ruleDeprecatedCommands = Rule{
	ID: "command-deprecated-in-use", Title: "Usage of deprecated commands",
	Category: "commands", Scope: ScopeHop, Severity: Notice,
	Hops: hops(hop70to80, hop80to83, hop80to90),
	Check: func(c *Context) []Finding {
		if !countersReported(c.Snap) {
			return c.NotChecked(noCounters)
		}
		var out []Finding
		var checked []string
		for _, d := range deprecatedCommands {
			applies := false
			for _, h := range d.hops {
				applies = applies || h == c.Hop
			}
			if !applies {
				continue
			}
			checked = append(checked, d.cmd)
			if n := commandCalls(c.Snap, d.cmd); n > 0 {
				f := rule("command-deprecated-in-use").finding(Notice,
					fmt.Sprintf("%s was called %s since the servers started: %s.", d.cmd, plural64(int64(n), "time", "times"), d.msg),
					[]string{d.cmd}, "Update the tools or scripts issuing it.")
				f.DocURL = d.doc
				out = append(out, f)
			}
		}
		if len(out) == 0 {
			verb := "were"
			if len(checked) == 1 {
				verb = "was"
			}
			return c.Checked("%s (deprecated as of %s) %s not called on %s since the servers started.",
				strings.Join(checked, ", "), c.Hop.To, verb, members(len(c.Snap.Nodes)))
		}
		return out
	},
}

// ---------------------------------------------------------------------------
// 8.0 → 8.3 (and 8.0 → 9.0)

var ruleSCRAMSHA1FIPS = Rule{
	ID: "scram-sha1-with-fips", Title: "SCRAM-SHA-1 with FIPS mode",
	Category: "security", Scope: ScopeHop, Severity: Error, DocURL: docRelease83, Hops: hopsInto83,
	// 8.3 release notes: "you cannot specify SCRAM-SHA-1 for
	// authenticationMechanisms while also specifying mongod --tlsFIPSMode or
	// mongos --tlsFIPSMode."
	Check: func(c *Context) []Finding {
		if !optionsReported(c.Snap) {
			return c.NotChecked(noOptions)
		}
		var items []string
		fips := 0
		for _, n := range c.Snap.Nodes {
			if jsonScalar(n.Options["net.tls.FIPSMode"]) != "true" {
				continue
			}
			fips++
			raw, ok := n.StartupParameters["authenticationMechanisms"]
			if !ok {
				raw, ok = n.Parameters["authenticationMechanisms"]
			}
			if ok && contains(mechanisms(raw), "SCRAM-SHA-1") {
				items = append(items, n.Host)
			}
		}
		if len(items) == 0 {
			if fips == 0 {
				return c.Checked("none of the %s runs with net.tls.FIPSMode.", members(len(c.Snap.Nodes)))
			}
			verb := "run"
			if fips == 1 {
				verb = "runs"
			}
			return c.Checked("%d of the %s %s with net.tls.FIPSMode, and none allows SCRAM-SHA-1.", fips, members(len(c.Snap.Nodes)), verb)
		}
		return []Finding{rule("scram-sha1-with-fips").finding(Error,
			"These nodes run with net.tls.FIPSMode and allow SCRAM-SHA-1 in authenticationMechanisms; 8.3 rejects that combination.",
			items, "Remove SCRAM-SHA-1 from authenticationMechanisms (move users to SCRAM-SHA-256) before upgrading.")}
	},
}

var ruleTimeFieldDollar = Rule{
	ID: "timeseries-timefield-dollar", Title: "Time series timeField names starting with $",
	Category: "data", Scope: ScopeHop, Severity: Warning, DocURL: docRelease83, Hops: hopsInto83,
	// 8.3 release notes (time series): "timeField cannot start with $".
	Check: func(c *Context) []Finding {
		if !dataCollected(c.Snap) {
			return c.NotChecked(needData)
		}
		var items []string
		ts := 0
		for _, db := range c.Snap.Data.Databases {
			for _, coll := range db.Collections {
				var o struct {
					Timeseries struct {
						TimeField string `json:"timeField"`
					} `json:"timeseries"`
				}
				if len(coll.Options) == 0 || json.Unmarshal(coll.Options, &o) != nil {
					continue
				}
				if o.Timeseries.TimeField != "" {
					ts++
				}
				if strings.HasPrefix(o.Timeseries.TimeField, "$") {
					items = append(items, fmt.Sprintf("%s.%s (timeField %q)", db.Name, coll.Name, o.Timeseries.TimeField))
				}
			}
		}
		if len(items) == 0 {
			if ts == 0 {
				return c.Checked("the deployment has no time series collections.")
			}
			return c.Checked("checked %s; no timeField starts with $.", count(ts, "time series collection", "time series collections"))
		}
		return []Finding{rule("timeseries-timefield-dollar").finding(Warning,
			"Starting in 8.3 a time series timeField cannot start with $.",
			items, "Recreate these time series collections with a timeField that does not start with $ before upgrading.")}
	},
}

var ruleFCBIS83 = Rule{
	ID: "initial-sync-filecopy-known-issue", Title: "File copy based initial sync",
	Category: "config", Scope: ScopeHop, Severity: Warning, DocURL: docRelease83, Hops: hops(hop80to83),
	// 8.3 release notes, known issue SERVER-136961 (8.3.0 and later): after
	// an unclean shutdown, a node restarting into file-copy-based initial sync
	// crashes repeatedly. Workaround: set initialSyncMethod to logical.
	Check: func(c *Context) []Finding {
		values := parameterValues(c.Snap, "initialSyncMethod")
		if len(values) == 0 {
			return c.NotChecked("no member reported initialSyncMethod (getParameter).")
		}
		var items []string
		for host, v := range values {
			if v == "fileCopyBased" {
				items = append(items, host)
			}
		}
		if len(items) == 0 {
			return c.Checked("initialSyncMethod is not fileCopyBased on any of the %s that reported it.", members(len(values)))
		}
		sort.Strings(items)
		return []Finding{rule("initial-sync-filecopy-known-issue").finding(Warning,
			"These nodes use initialSyncMethod=fileCopyBased. 8.3 has an open known issue (SERVER-136961) where a node restarting into file-copy-based initial sync after an unclean shutdown crashes repeatedly.",
			items, "Set initialSyncMethod to logical on 8.3, or check whether SERVER-136961 is fixed in the 8.3 patch you deploy.")}
	},
}

// ---------------------------------------------------------------------------
// → 9.0

var ruleQETextPreview = Rule{
	ID: "qe-text-preview-removed", Title: "Queryable Encryption prefix/suffix/substring preview fields",
	Category: "data", Scope: ScopeHop, Severity: Error, DocURL: docCompat90, Hops: hopsInto90,
	// 9.0-compatibility: prefixPreview, suffixPreview, substringPreview are
	// "deprecated and removed"; "The GA feature is incompatible with the
	// Public Preview version released in MongoDB 8.2."
	Check: func(c *Context) []Finding {
		if !dataCollected(c.Snap) {
			return c.NotChecked(needData)
		}
		var items []string
		qe := encryptedQueryTypes(c.Snap)
		for ns, types := range qe {
			for _, t := range types {
				if t == "prefixPreview" || t == "suffixPreview" || t == "substringPreview" {
					items = append(items, fmt.Sprintf("%s (%s)", ns, t))
				}
			}
		}
		if len(items) == 0 {
			if len(qe) == 0 {
				return qeNotUsed(c)
			}
			return c.Checked("checked %s; none uses the prefixPreview, suffixPreview or substringPreview query types.", count(len(qe), "encrypted collection", "encrypted collections"))
		}
		sort.Strings(items)
		return []Finding{rule("qe-text-preview-removed").finding(Error,
			"These encrypted collections use the 8.2 public preview text query types, which 9.0 removes; the 9.0 GA prefix/suffix/substring support is incompatible with them.",
			items, "Stay on 8.2/8.3 for these collections, or after upgrading recreate them with the string algorithm (prefix/suffix/substring) and re-ingest through a 9.0 driver.")}
	},
}

var ruleFLESubstringLimits = Rule{
	ID: "fle-substring-limits-override", Title: "fleDisableSubstringPreviewParameterLimits parameter",
	Category: "parameters", Scope: ScopeHop, Severity: Warning, DocURL: docCompat90, Hops: hopsInto90,
	// 9.0-compatibility: "You cannot override the internal limits on
	// substring queries against encrypted fields in MongoDB 9.0."
	Check: func(c *Context) []Finding {
		if !optionsReported(c.Snap) {
			return c.NotChecked(noOptions)
		}
		hosts := startupParams(c.Snap)["fleDisableSubstringPreviewParameterLimits"]
		if len(hosts) == 0 {
			return c.Checked("fleDisableSubstringPreviewParameterLimits is not set at startup on %s.", members(len(c.Snap.Nodes)))
		}
		return []Finding{rule("fle-substring-limits-override").finding(Warning,
			"fleDisableSubstringPreviewParameterLimits is set, but 9.0 no longer lets you override the substring query limits on encrypted fields.",
			[]string{summarizeHosts(hosts)}, "Remove the parameter and make sure substring queries fit within the default limits.")}
	},
}

var ruleGroupEmptyField = Rule{
	ID: "group-empty-field-name", Title: "$group accumulators with an empty field name",
	Category: "data", Scope: ScopeHop, Severity: Error, DocURL: docCompat90, Hops: hopsInto90,
	// 9.0-compatibility: "the $group stage returns an error if an accumulator
	// expression has an empty field name."
	Check: func(c *Context) []Finding {
		if !dataCollected(c.Snap) {
			return c.NotChecked(needData)
		}
		var items []string
		views := 0
		pipelines(c.Snap, func(ns, what string, raw json.RawMessage) {
			if what == "view pipeline" {
				views++
			}
			if what == "view pipeline" && groupHasEmptyField(raw) {
				items = append(items, ns)
			}
		})
		if len(items) == 0 {
			if views == 0 {
				return c.Checked("the deployment has no views.")
			}
			return c.Checked("checked %s; no $group accumulator has an empty field name.", count(views, "view pipeline", "view pipelines"))
		}
		return []Finding{rule("group-empty-field-name").finding(Error,
			"These views contain a $group stage with an accumulator under an empty field name; 9.0 returns an error for it, so queries on the views will fail.",
			items, "Rename the accumulator fields in the view pipelines (collMod) before upgrading.")}
	},
}

func groupHasEmptyField(raw json.RawMessage) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	found := false
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if k == "$group" {
					if g, ok := val.(map[string]any); ok {
						if _, empty := g[""]; empty {
							found = true
						}
					}
				}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return found
}

var ruleServerJS90 = Rule{
	ID: "server-side-js-9.0", Title: "Usage of server-side JavaScript",
	Category: "data", Scope: ScopeHop, Severity: Warning, DocURL: docCompat90, Hops: hopsInto90,
	// 9.0-compatibility: server-side JS "evaluates local Date operations in
	// UTC, regardless of the mongod host time zone" ($function, $accumulator,
	// $where, mapReduce), and "The mongod and mongos binaries for ppc64le do
	// not include a JavaScript engine."
	Check: func(c *Context) []Finding {
		var items []string
		pipelines(c.Snap, func(ns, what string, raw json.RawMessage) {
			for _, op := range dollarKeys(raw) {
				if op == "$function" || op == "$accumulator" || op == "$where" {
					items = append(items, fmt.Sprintf("%s: %s in %s", ns, op, what))
				}
			}
		})
		if n := commandCalls(c.Snap, "mapReduce"); n > 0 {
			items = append(items, fmt.Sprintf("mapReduce called %s", plural64(int64(n), "time", "times")))
		}
		// Usage counters since startup (serverStatus metrics.operatorCounters).
		for _, oc := range []struct{ group, op string }{
			{"expressions", "$function"}, {"groupAccumulators", "$accumulator"},
			{"windowAccumulators", "$accumulator"}, {"match", "$where"},
		} {
			if h := opCounter(c.Snap, oc.group, oc.op); h.total > 0 {
				items = append(items, h.describe(oc.op))
			}
		}
		if len(items) == 0 {
			views, validators := pipelineCounts(c.Snap)
			data, counters := dataCollected(c.Snap), operatorCountersReported(c.Snap) && countersReported(c.Snap)
			switch {
			case !data && !counters:
				return c.NotChecked("views and validators were not listed and no member reported operator or command counters.")
			case !data:
				return c.Checked("no $function, $accumulator, $where or mapReduce in the operator and command counters of %s since the servers started; views and validators were not listed.", members(len(c.Snap.Nodes)))
			case !counters:
				return c.Checked("no $function, $accumulator or $where in %s and %s; usage counters were not reported.",
					count(views, "view pipeline", "view pipelines"), count(validators, "validator", "validators"))
			}
			if views+validators == 0 {
				return c.Checked("no $function, $accumulator, $where or mapReduce in the operator and command counters of %s since the servers started; the deployment has no views or validators.", members(len(c.Snap.Nodes)))
			}
			return c.Checked("no $function, $accumulator, $where or mapReduce in %s and %s, nor in the operator and command counters of %s since the servers started.",
				count(views, "view pipeline", "view pipelines"), count(validators, "validator", "validators"), members(len(c.Snap.Nodes)))
		}
		sort.Strings(items)
		if arches(c.Snap)["ppc64le"] {
			return []Finding{rule("server-side-js-9.0").finding(Error,
				"This deployment runs on ppc64le and uses server-side JavaScript; the 9.0 ppc64le binaries have no JavaScript engine, so these operations will fail.",
				items, "Rewrite them with aggregation operators, or move to another architecture, before upgrading.")}
		}
		return []Finding{rule("server-side-js-9.0").finding(Warning,
			"Server-side JavaScript is in use. In 9.0 local Date operations inside $function, $accumulator, $where and mapReduce are evaluated in UTC regardless of the host time zone, so results can change.",
			items, "Review the JavaScript for local-time Date use (getHours(), toString(), local constructors) and switch to UTC methods or aggregation date operators with an explicit timezone.")}
	},
}

// ---------------------------------------------------------------------------
// PSMDB-specific

var rulePSMDBJournal = Rule{
	ID: "psmdb-journal-option-ignored", Title: "PSMDB journal options",
	Category: "config", Scope: ScopeHop, Severity: Notice, DocURL: docPSMDBUpgrade70,
	Hops: hops(hop60to70), Flavors: []string{"psmdb"},
	// PSMDB upgrade-from-60: in 7.0 "journaling is enabled by default" and the
	// storage.journal.enabled option and --journal/--nojournal flags are
	// ignored, with a startup warning until removed.
	Check: func(c *Context) []Finding {
		if !optionsReported(c.Snap) {
			return c.NotChecked(noOptions)
		}
		hosts := append(optionHosts(c.Snap, "storage.journal.enabled"), optionHosts(c.Snap, "nojournal")...)
		if len(hosts) == 0 {
			return c.Checked("storage.journal.enabled and --journal/--nojournal are not set on %s.", members(len(c.Snap.Nodes)))
		}
		return []Finding{rule("psmdb-journal-option-ignored").finding(Notice,
			"storage.journal.enabled / --journal / --nojournal are set. PSMDB 7.0 and later always journal and ignore these settings, logging a startup warning.",
			[]string{summarizeHosts(hosts)}, "Remove the journal settings from the configuration.")}
	},
}

var rulePSMDBKMIP = Rule{
	ID: "psmdb-kmip-key-active", Title: "PSMDB KMIP master key state",
	Category: "security", Scope: ScopeHop, Severity: Warning, DocURL: docPSMDBKMIP,
	Hops: hops(hop60to70, hop70to80), Flavors: []string{"psmdb"},
	// PSMDB kmip.html, Upgrade considerations: "Percona Server for MongoDB
	// requires that the master encryption key is in the Active state before
	// decrypting the data directory on startup." Rotate the key (rotateMasterKey)
	// after installing the new version but before starting it; "This is the
	// one-time action". Key activation exists since 7.0.14-8.
	Check: func(c *Context) []Finding {
		if len(c.Hops) == 0 || c.Hop != c.Hops[0] {
			return c.Checked("the KMIP master key state is checked on the first upgrade step only.")
		}
		if !optionsReported(c.Snap) {
			return c.NotChecked(noOptions)
		}
		hosts := optionHosts(c.Snap, "security.kmip.")
		if len(hosts) == 0 {
			return c.Checked("KMIP encryption (security.kmip) is not configured on %s.", members(len(c.Snap.Nodes)))
		}
		if snapshot.CompareVersions(minVersion(c.Snap), "7.0.14") >= 0 {
			return c.Checked("KMIP is configured and every member runs %s or later, which already supports KMIP key activation.", minVersion(c.Snap))
		}
		return []Finding{rule("psmdb-kmip-key-active").finding(Warning,
			"Data-at-rest encryption uses KMIP and the running version predates KMIP key activation (7.0.14-8). The upgraded server refuses to decrypt the data directory unless the master key is in the Active state.",
			hosts, "On each node, after installing the new binaries and before the normal start: set security.kmip.rotateMasterKey=true, start mongod and let it exit after rotating, remove the option, then start normally.")}
	},
}

var rulePSMDBVault = Rule{
	ID: "psmdb-vault-metadata-permission", Title: "PSMDB Vault policy for secret metadata",
	Category: "security", Scope: ScopeHop, Severity: Warning, DocURL: docPSMDBVault,
	Hops: hops(hop60to70, hop70to80), Flavors: []string{"psmdb"},
	// PSMDB vault.html: "Percona Server for MongoDB requires read permissions
	// for the secret's metadata and the secrets engine configuration." If you
	// upgraded "from version 7.0.14-9 or earlier", add them to the policy;
	// "If the number of secrets reaches the maximum, Percona Server for
	// MongoDB logs an error and exits."
	Check: func(c *Context) []Finding {
		if len(c.Hops) == 0 || c.Hop != c.Hops[0] {
			return c.Checked("the Vault policy is checked on the first upgrade step only.")
		}
		if !optionsReported(c.Snap) {
			return c.NotChecked(noOptions)
		}
		hosts := optionHosts(c.Snap, "security.vault.")
		if len(hosts) == 0 {
			return c.Checked("Vault encryption (security.vault) is not configured on %s.", members(len(c.Snap.Nodes)))
		}
		if snapshot.CompareVersions(minVersion(c.Snap), "7.0.14") > 0 {
			return c.Checked("Vault is configured and every member runs %s or later, which already checks the secret metadata.", minVersion(c.Snap))
		}
		return []Finding{rule("psmdb-vault-metadata-permission").finding(Warning,
			"Data-at-rest encryption uses HashiCorp Vault and the running version predates the secret-version check. Newer versions need read access to the secret's metadata and the secrets engine configuration, and exit when the secret reaches its max_versions.",
			hosts, `Add read capability on the secret metadata path (e.g. path "secret/metadata/*") and on the secrets engine configuration to the Vault policy, and check max_versions, before upgrading.`)}
	},
}

// rule returns a registered rule by ID. Checks use it instead of referring
// to their own package variable, which Go rejects as an initialization cycle.
func rule(id string) Rule {
	for _, r := range registry {
		if r.ID == id {
			return r
		}
	}
	return Rule{ID: id}
}

// mechanisms parses authenticationMechanisms given as a JSON array or as a
// comma-separated string.
func mechanisms(raw json.RawMessage) []string {
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		list = strings.Split(jsonScalar(raw), ",")
	}
	var out []string
	for _, m := range list {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func minVersion(s *snapshot.Snapshot) string {
	min := ""
	for _, n := range s.Nodes {
		if n.Version == "" {
			continue
		}
		if min == "" || snapshot.CompareVersions(n.Version, min) < 0 {
			min = n.Version
		}
	}
	return min
}

func init() {
	register(ruleTHP, ruleRseq, ruleKernel,
		ruleQEPreview70, ruleViewsOnBuckets, ruleFreeMonitoring, ruleDeprecatedParams,
		ruleRangePreview, ruleLDAPDeprecated, ruleDeprecatedCommands,
		ruleSCRAMSHA1FIPS, ruleTimeFieldDollar, ruleFCBIS83,
		ruleQETextPreview, ruleFLESubstringLimits, ruleGroupEmptyField, ruleServerJS90,
		rulePSMDBJournal, rulePSMDBKMIP, rulePSMDBVault)
}

// qeNotUsed is the summary when no collection has encryptedFields.
func qeNotUsed(c *Context) []Finding {
	n := collectionCount(c.Snap)
	if n == 0 {
		return c.Checked("the deployment has no collections, so no Queryable Encryption.")
	}
	return c.Checked("checked %s; none uses Queryable Encryption.", count(n, "collection or view", "collections and views"))
}
