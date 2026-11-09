package rules

import (
	"encoding/json"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Summaries of the catalog-diff and curated rules (group B).

func init() {
	passNotOnFixtures["thp-enabled-for-8.0"] = "unit test TestGroupBHostSummaries"
	passNotOnFixtures["tcmalloc-glibc-rseq"] = "unit test TestGroupBHostSummaries"
	passNotOnFixtures["psmdb-journal-option-ignored"] = "unit test TestGroupBSummaries"
}

// hopCheck returns the check result of rule id at the given step.
func hopCheck(t *testing.T, res *Result, id, hop string) CheckResult {
	t.Helper()
	for _, h := range res.Hops {
		if h.Hop.String() != hop {
			continue
		}
		for _, c := range h.Checks {
			if c.RuleID == id {
				return c
			}
		}
	}
	t.Fatalf("%s: no check at %s", id, hop)
	return CheckResult{}
}

func withVersion(s *snapshot.Snapshot, version, fcv, flavor string) *snapshot.Snapshot {
	for i := range s.Nodes {
		s.Nodes[i].Version, s.Nodes[i].FCV, s.Nodes[i].Flavor = version, fcv, flavor
	}
	return s
}

// reported adds the serverStatus counters and getParameter values a live
// collection returns, so counter- and parameter-based rules have facts to
// evaluate.
func reported(s *snapshot.Snapshot) *snapshot.Snapshot {
	for i := range s.Nodes {
		s.Nodes[i].CommandCounters = map[string]int64{"find": 10}
		s.Nodes[i].OperatorCounters = map[string]map[string]int64{"match": {"$eq": 4}}
		s.Nodes[i].Parameters = map[string]json.RawMessage{"initialSyncMethod": json.RawMessage(`"logical"`)}
	}
	return s
}

func TestGroupBSummaries(t *testing.T) {
	community70 := run(t, reported(base()), "9.0")
	psmdb60 := run(t, reported(withVersion(base(), "6.0.29-23", "6.0", "psmdb")), "7.0")
	community80 := run(t, reported(withVersion(base(), "8.0.12", "8.0", "community")), "8.3")
	cases := []struct {
		res     *Result
		id, hop string
		summary string
	}{
		{community70, "config-option-removed", "7.0 → 8.0", "checked 1 startup option set on 3 members against 8.0; none was removed."},
		{community70, "config-option-deprecated", "7.0 → 8.0", "checked 1 startup option set on 3 members against 8.0; none is a deprecated alias there."},
		{community70, "parameter-removed", "7.0 → 8.0", "no server parameter is set at startup on 3 members."},
		{community70, "parameter-renamed", "8.0 → 9.0", "no server parameter is set at startup on 3 members."},
		{community70, "command-removed-in-use", "7.0 → 8.0", "no command removed in 8.0 was called on 3 members since the servers started (longest uptime 0s)."},
		{community70, "agg-operator-removed", "8.0 → 9.0", "the deployment has no views or validators."},
		{community70, "role-action-removed", "8.0 → 9.0", "the deployment has no custom roles."},
		{community70, "ldap-deprecated", "7.0 → 8.0", "LDAP (security.ldap) is not configured on 3 members."},
		{community70, "command-deprecated-in-use", "7.0 → 8.0", "planCacheSetFilter, cleanupOrphaned (deprecated as of 8.0) were not called on 3 members since the servers started."},
		{community70, "parameter-deprecated", "7.0 → 8.0", "none of the parameters deprecated in 8.0 (tcmallocAggressiveMemoryDecommit, enableFinerGrainedCatalogCacheRefresh) is set at startup on 3 members."},
		{community70, "qe-range-preview-removed", "7.0 → 8.0", "the deployment has no collections, so no Queryable Encryption."},
		{community70, "qe-text-preview-removed", "8.0 → 9.0", "the deployment has no collections, so no Queryable Encryption."},
		{community70, "fle-substring-limits-override", "8.0 → 9.0", "fleDisableSubstringPreviewParameterLimits is not set at startup on 3 members."},
		{community70, "group-empty-field-name", "8.0 → 9.0", "the deployment has no views."},
		{community70, "server-side-js-9.0", "8.0 → 9.0", "no $function, $accumulator, $where or mapReduce in the operator and command counters of 3 members since the servers started; the deployment has no views or validators."},
		{psmdb60, "psmdb-journal-option-ignored", "6.0 → 7.0", "storage.journal.enabled and --journal/--nojournal are not set on 3 members."},
		{psmdb60, "psmdb-kmip-key-active", "6.0 → 7.0", "KMIP encryption (security.kmip) is not configured on 3 members."},
		{psmdb60, "psmdb-vault-metadata-permission", "6.0 → 7.0", "Vault encryption (security.vault) is not configured on 3 members."},
		{psmdb60, "qe-preview-6x", "6.0 → 7.0", "the deployment has no collections, so no Queryable Encryption."},
		{psmdb60, "views-on-system-buckets", "6.0 → 7.0", "the deployment has no views, including those hidden from listCollections."},
		{psmdb60, "free-monitoring-decommissioned", "6.0 → 7.0", "cloud.monitoring.free is not set on 3 members, and setFreeMonitoring was not called since the servers started."},
		{community80, "scram-sha1-with-fips", "8.0 → 8.3", "none of the 3 members runs with net.tls.FIPSMode."},
		{community80, "timeseries-timefield-dollar", "8.0 → 8.3", "the deployment has no time series collections."},
		{community80, "initial-sync-filecopy-known-issue", "8.0 → 8.3", "initialSyncMethod is not fileCopyBased on any of the 3 members that reported it."},
	}
	for _, tc := range cases {
		c := hopCheck(t, tc.res, tc.id, tc.hop)
		if c.Status != StatusOK || c.Summary != tc.summary {
			t.Errorf("%s at %s: status %s\n got  %q\n want %q", tc.id, tc.hop, c.Status, c.Summary, tc.summary)
		}
	}
}

func TestGroupBHostSummaries(t *testing.T) {
	s := base()
	s.Host = &snapshot.HostInfo{Node: "a:27017", Hostname: "db1",
		THPEnabled: "[always] madvise never", THPDefrag: "always defer [defer+madvise] madvise never", THPMaxPtesNone: "0"}
	for i := range s.Nodes {
		s.Nodes[i].TCMalloc = &snapshot.TCMallocInfo{UsingPerCPUCaches: true}
		s.Nodes[i].HostInfo.KernelVersion = "6.12.115"
	}
	res := run(t, s, "8.0")
	for _, tc := range []struct{ id, summary string }{
		{"thp-enabled-for-8.0", "Transparent Huge Pages on db1 match what 8.0 needs (enabled=always, defrag=defer+madvise, khugepaged/max_ptes_none=0)."},
		{"tcmalloc-glibc-rseq", "all 3 members report serverStatus tcmalloc.usingPerCPUCaches true."},
		{"kernel-tcmalloc-compat", "checked 1 kernel (6.12.115) on 3 hosts; none is in the 6.19 to 7.0.13 crash range or older than 4.18."},
	} {
		c := hopCheck(t, res, tc.id, "7.0 → 8.0")
		if c.Status != StatusOK || c.Summary != tc.summary {
			t.Errorf("%s: status %s\n got  %q\n want %q", tc.id, c.Status, c.Summary, tc.summary)
		}
	}

	// Servers not yet on the 8.0 TCMalloc: the local process environment.
	s = base()
	s.Host = &snapshot.HostInfo{Node: "a:27017", Hostname: "db1",
		MongodProcesses: []snapshot.LocalProcess{{PID: 7, Name: "mongod", EnvReadable: true, GlibcTunables: "glibc.pthread.rseq=0"}}}
	c := hopCheck(t, run(t, s, "8.0"), "tcmalloc-glibc-rseq", "7.0 → 8.0")
	if want := "1 mongod process on db1 set GLIBC_TUNABLES=glibc.pthread.rseq=0."; c.Summary != want {
		t.Errorf("rseq from the environment: got %q want %q", c.Summary, want)
	}
}

// Nothing to evaluate is "Not checked", never "No issues found".
func TestGroupBNotCheckedWithoutFacts(t *testing.T) {
	s := base() // no command counters, operator counters or parameters
	for i := range s.Nodes {
		s.Nodes[i].Options = nil
	}
	res := run(t, s, "9.0")
	for _, tc := range []struct{ id, hop, reason string }{
		{"command-removed-in-use", "7.0 → 8.0", "no member reported its command counters (serverStatus)."},
		{"command-deprecated-in-use", "7.0 → 8.0", "no member reported its command counters (serverStatus)."},
		{"config-option-removed", "7.0 → 8.0", "no member reported its startup options (getCmdLineOpts)."},
		{"parameter-removed", "8.0 → 9.0", "no member reported its startup options (getCmdLineOpts)."},
		{"ldap-deprecated", "7.0 → 8.0", "no member reported its startup options (getCmdLineOpts)."},
	} {
		c := hopCheck(t, res, tc.id, tc.hop)
		if c.Status != StatusNotChecked || c.Reason != tc.reason || c.Summary != "" {
			t.Errorf("%s: status %s reason %q summary %q", tc.id, c.Status, c.Reason, c.Summary)
		}
	}
	c := hopCheck(t, run(t, withVersion(base(), "8.0.12", "8.0", "community"), "8.3"), "initial-sync-filecopy-known-issue", "8.0 → 8.3")
	if c.Status != StatusNotChecked {
		t.Errorf("initialSyncMethod not reported: status %s summary %q", c.Status, c.Summary)
	}
}

func TestSCRAMFIPSSummaryWording(t *testing.T) {
	s := reported(withVersion(base(), "8.0.12", "8.0", "community"))
	for i := range s.Nodes[:2] {
		s.Nodes[i].Options["net.tls.FIPSMode"] = json.RawMessage(`true`)
		s.Nodes[i].Parameters["authenticationMechanisms"] = json.RawMessage(`"SCRAM-SHA-256"`)
	}
	c := hopCheck(t, run(t, s, "8.3"), "scram-sha1-with-fips", "8.0 → 8.3")
	if want := "2 of the 3 members run with net.tls.FIPSMode, and none allows SCRAM-SHA-1."; c.Summary != want {
		t.Errorf("got %q want %q", c.Summary, want)
	}
	s.Nodes[1].Options = map[string]json.RawMessage{"net.bindIp": json.RawMessage(`"0.0.0.0"`)}
	c = hopCheck(t, run(t, s, "8.3"), "scram-sha1-with-fips", "8.0 → 8.3")
	if want := "1 of the 3 members runs with net.tls.FIPSMode, and none allows SCRAM-SHA-1."; c.Summary != want {
		t.Errorf("got %q want %q", c.Summary, want)
	}
}
