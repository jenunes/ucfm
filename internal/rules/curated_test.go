package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// at returns base() moved to version v (binaries and FCV) and flavor f.
func at(v, flavor string) *snapshot.Snapshot {
	s := base()
	for i := range s.Nodes {
		s.Nodes[i].Version = v
		s.Nodes[i].FCV = snapshot.MajorMinor(v)
		s.Nodes[i].Flavor = flavor
		s.Nodes[i].HostInfo.CPUArch = "x86_64"
	}
	return s
}

// findHop returns the finding of ruleID on the given hop ("7.0 → 8.0").
func findHop(res *Result, ruleID, hop string) *Finding {
	for _, h := range res.Hops {
		if h.Hop.String() != hop {
			continue
		}
		for _, f := range h.Findings() {
			if f.RuleID == ruleID {
				return &f
			}
		}
	}
	return nil
}

func countRule(res *Result, ruleID string) int {
	n := 0
	for _, f := range res.AllFindings() {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

func withHost(s *snapshot.Snapshot, thp, defrag, ptes string) *snapshot.Snapshot {
	s.Host = &snapshot.HostInfo{Hostname: "a", THPEnabled: thp, THPDefrag: defrag, THPMaxPtesNone: ptes, GlibcVersion: "2.35",
		MongodProcesses: []snapshot.LocalProcess{{PID: 1, Name: "mongod", EnvReadable: true}}}
	return s
}

func view(db, name, pipeline string) snapshot.Database {
	return snapshot.Database{Name: db, Collections: []snapshot.Collection{{Name: name, Type: "view", ViewOn: "c", Pipeline: json.RawMessage(pipeline)}}}
}

// Real --local snapshot of an anydbver PSMDB 6.0.29 node (THP [never]).
// memberLocalFixture is psmdb60-local.json with its host facts attributed to
// the snapshot's node. The fixture itself was collected on node1 while the
// entry connection followed discovery to node0, so as-is the facts belong to
// no member (see TestLocalFixtureFromOtherMachineIsNotUsed).
func memberLocalFixture(t *testing.T) *snapshot.Snapshot {
	s := loadFixture(t, "psmdb60-local.json")
	s.Host.Node = s.Nodes[0].Host
	return s
}

func TestLocalFixtureFromOtherMachineIsNotUsed(t *testing.T) {
	res := run(t, loadFixture(t, "psmdb60-local.json"), "8.0")
	for _, h := range res.Hops {
		for _, c := range h.Checks {
			if c.RuleID == "thp-enabled-for-8.0" {
				if c.Status != StatusNotChecked || !strings.Contains(c.Reason, "ucfm ran with --local on node1, which is not a host of this deployment") {
					t.Errorf("thp check = %s %q", c.Status, c.Reason)
				}
			}
		}
	}
	if f := find(res, "host-checks-coverage"); f == nil || !strings.Contains(f.Message, "node1, which is not a host of this deployment") {
		t.Errorf("coverage = %+v", f)
	}
}

func TestGoldenTHPFromLocalFixture(t *testing.T) {
	res := run(t, memberLocalFixture(t), "8.0")
	f := findHop(res, "thp-enabled-for-8.0", "7.0 → 8.0")
	if f == nil || f.Severity != Warning || len(f.Items) != 1 || !strings.Contains(f.Items[0], "enabled = never") {
		t.Fatalf("thp: %+v", f)
	}
	if f.DocURL != docPSMDBUpgrade80 {
		t.Errorf("psmdb doc url = %s", f.DocURL)
	}
	if findHop(res, "tcmalloc-glibc-rseq", "7.0 → 8.0") == nil {
		t.Error("expected rseq notice (env readable, no GLIBC_TUNABLES)")
	}
	if findHop(res, "thp-enabled-for-8.0", "6.0 → 7.0") != nil {
		t.Error("THP must not be reported on the 6.0 → 7.0 hop")
	}
}

func TestTHP(t *testing.T) {
	cases := []struct {
		name               string
		thp, defrag, ptes  string
		arch, target       string
		hostNil, wantFound bool
		wantItems          int
	}{
		{"all good", "[always] madvise never", "always defer [defer+madvise] madvise never", "0", "x86_64", "8.0", false, false, 0},
		{"never", "always madvise [never]", "always defer [defer+madvise] madvise never", "0", "x86_64", "8.0", false, true, 1},
		{"all three off", "always [madvise] never", "[always] defer defer+madvise madvise never", "511", "x86_64", "8.0", false, true, 3},
		{"no host facts", "", "", "", "x86_64", "8.0", true, false, 0},
		{"legacy tcmalloc arch", "always madvise [never]", "", "", "ppc64le", "8.0", false, false, 0},
		{"target 7.0 only", "always madvise [never]", "", "", "x86_64", "7.0", false, false, 0},
	}
	for _, c := range cases {
		s := withHost(at("6.0.20", "community"), c.thp, c.defrag, c.ptes)
		if c.hostNil {
			s.Host = nil
		}
		for i := range s.Nodes {
			s.Nodes[i].HostInfo.CPUArch = c.arch
		}
		res := run(t, s, c.target)
		f := find(res, "thp-enabled-for-8.0")
		if (f != nil) != c.wantFound || (f != nil && len(f.Items) != c.wantItems) {
			t.Errorf("%s: got %+v", c.name, f)
		}
		if countRule(res, "thp-enabled-for-8.0") > 1 {
			t.Errorf("%s: THP reported more than once", c.name)
		}
	}
}

func TestTHPReportedOnceOnLongPath(t *testing.T) {
	res := run(t, withHost(at("6.0.20", "community"), "always madvise [never]", "", ""), "9.0")
	if n := countRule(res, "thp-enabled-for-8.0"); n != 1 {
		t.Fatalf("THP reported %d times", n)
	}
	if findHop(res, "thp-enabled-for-8.0", "7.0 → 8.0") == nil {
		t.Error("THP should be on the first hop reaching 8.0")
	}
	// Already on 8.0: reported on the 8.0 → 9.0 hop.
	res = run(t, withHost(at("8.0.19", "community"), "always madvise [never]", "", ""), "9.0")
	if findHop(res, "thp-enabled-for-8.0", "8.0 → 9.0") == nil {
		t.Error("THP should be reported for an 8.0 source")
	}
}

func TestRseq(t *testing.T) {
	s := withHost(at("7.0.29", "community"), "[always] madvise never", "", "")
	s.Host.MongodProcesses[0].GlibcTunables = "glibc.pthread.rseq=0"
	if f := find(run(t, s, "8.0"), "tcmalloc-glibc-rseq"); f != nil {
		t.Errorf("tunable set: unexpected %+v", f)
	}
	s.Host.MongodProcesses[0].GlibcTunables = ""
	s.Host.MongodProcesses[0].EnvReadable = false
	if f := find(run(t, s, "8.0"), "tcmalloc-glibc-rseq"); f != nil {
		t.Errorf("env unreadable: must not guess, got %+v", f)
	}
}

func TestKernel(t *testing.T) {
	cases := []struct {
		kernel string
		sev    Severity // 0 = no finding
	}{
		{"6.19.2-arch1-1", Error},
		{"7.0.13", Error},
		{"7.0.14-200.fc44.x86_64", 0},
		{"6.12.115+deb13.1-amd64", 0},
		{"4.14.0-1.el7", Warning},
		{"5.14.0-427.el9.x86_64", 0},
	}
	for _, c := range cases {
		s := at("7.0.29", "community")
		for i := range s.Nodes {
			s.Nodes[i].HostInfo.KernelVersion = c.kernel
		}
		f := find(run(t, s, "8.0"), "kernel-tcmalloc-compat")
		switch {
		case c.sev == 0 && f != nil:
			t.Errorf("%s: unexpected %+v", c.kernel, f)
		case c.sev != 0 && (f == nil || f.Severity != c.sev):
			t.Errorf("%s: got %+v want %v", c.kernel, f, c.sev)
		}
	}
}

func TestKernelFallsBackToLocalHost(t *testing.T) {
	s := withHost(at("7.0.29", "community"), "[always] madvise never", "", "")
	s.Host.KernelVersion = "6.19.0"
	if f := find(run(t, s, "8.0"), "kernel-tcmalloc-compat"); f == nil || f.Severity != Error {
		t.Errorf("got %+v", f)
	}
}

func TestQEPreview6x(t *testing.T) {
	s := at("6.0.20", "community")
	s.Data.Databases = []snapshot.Database{{Name: "hr", Collections: []snapshot.Collection{{Name: "emp", Type: "collection",
		EncryptedFields: json.RawMessage(`{"fields":[{"path":"ssn","queries":{"queryType":"equality"}}]}`)}}}}
	if f := findHop(run(t, s, "7.0"), "qe-preview-6x", "6.0 → 7.0"); f == nil || f.Items[0] != "hr.emp" {
		t.Fatalf("got %+v", f)
	}
	if f := find(run(t, at("6.0.20", "community"), "7.0"), "qe-preview-6x"); f != nil {
		t.Errorf("no QE: unexpected %+v", f)
	}
}

func TestViewsOnSystemBuckets(t *testing.T) {
	s := at("6.0.20", "community")
	s.Data.Databases = []snapshot.Database{{Name: "m", Collections: []snapshot.Collection{
		{Name: "v1", Type: "view", ViewOn: "system.buckets.weather"},
		{Name: "v2", Type: "view", ViewOn: "weather"},
	}}}
	f := find(run(t, s, "7.0"), "views-on-system-buckets")
	if f == nil || f.Severity != Error || len(f.Items) != 1 || !strings.HasPrefix(f.Items[0], "m.v1") {
		t.Fatalf("got %+v", f)
	}
}

func TestFreeMonitoring(t *testing.T) {
	s := at("6.0.20", "community")
	s.Nodes[0].Options["cloud.monitoring.free.state"] = json.RawMessage(`"on"`)
	s.Nodes[1].CommandCounters = map[string]int64{"setFreeMonitoring": 2}
	if f := find(run(t, s, "7.0"), "free-monitoring-decommissioned"); f == nil || len(f.Items) != 2 {
		t.Fatalf("got %+v", f)
	}
	if f := find(run(t, at("6.0.20", "community"), "7.0"), "free-monitoring-decommissioned"); f != nil {
		t.Errorf("unexpected %+v", f)
	}
}

func TestDeprecatedParams(t *testing.T) {
	s := at("7.0.29", "community")
	s.Nodes[0].StartupParameters = map[string]json.RawMessage{"tcmallocAggressiveMemoryDecommit": json.RawMessage(`"1"`)}
	f := find(run(t, s, "8.0"), "parameter-deprecated")
	if f == nil || !strings.HasPrefix(f.Items[0], "tcmallocAggressiveMemoryDecommit") || f.DocURL != docCompat80 {
		t.Fatalf("got %+v", f)
	}
	s = at("6.0.20", "community")
	s.Nodes[0].StartupParameters = map[string]json.RawMessage{"taskExecutorPoolSize": json.RawMessage(`"4"`)}
	if f := findHop(run(t, s, "7.0"), "parameter-deprecated", "6.0 → 7.0"); f == nil {
		t.Fatal("taskExecutorPoolSize not reported")
	}
}

func TestRangePreview(t *testing.T) {
	s := at("7.0.29", "community")
	s.Data.Databases = []snapshot.Database{{Name: "pay", Collections: []snapshot.Collection{
		{Name: "a", Type: "collection", EncryptedFields: json.RawMessage(`{"fields":[{"path":"amt","queries":[{"queryType":"rangePreview"}]}]}`)},
		{Name: "b", Type: "collection", EncryptedFields: json.RawMessage(`{"fields":[{"path":"amt","queries":[{"queryType":"range"}]}]}`)},
	}}}
	f := find(run(t, s, "8.0"), "qe-range-preview-removed")
	if f == nil || f.Severity != Error || len(f.Items) != 1 || f.Items[0] != "pay.a" {
		t.Fatalf("got %+v", f)
	}
}

func TestLDAPDeprecatedCommunityOnly(t *testing.T) {
	s := at("7.0.29", "enterprise")
	s.Nodes[0].Options["security.ldap.servers"] = json.RawMessage(`"ldap.example.com"`)
	if f := find(run(t, s, "8.0"), "ldap-deprecated"); f == nil {
		t.Fatal("expected LDAP notice for enterprise/community catalogs")
	}
	s = at("7.0.29", "psmdb")
	s.Nodes[0].Options["security.ldap.servers"] = json.RawMessage(`"ldap.example.com"`)
	if f := find(run(t, s, "8.0"), "ldap-deprecated"); f != nil {
		t.Errorf("PSMDB must not get the MongoDB LDAP deprecation: %+v", f)
	}
}

func TestDeprecatedCommands(t *testing.T) {
	s := at("7.0.29", "community")
	s.Nodes[0].CommandCounters = map[string]int64{"planCacheSetFilter": 3, "cleanupOrphaned": 0}
	res := run(t, s, "8.0")
	if n := countRule(res, "command-deprecated-in-use"); n != 1 {
		t.Fatalf("got %d findings", n)
	}
	s = at("8.0.19", "community")
	s.Nodes[0].CommandCounters = map[string]int64{"removeShard": 1}
	for _, target := range []string{"8.3", "9.0"} {
		if f := find(run(t, s, target), "command-deprecated-in-use"); f == nil || f.Items[0] != "removeShard" {
			t.Errorf("%s: got %+v", target, f)
		}
	}
}

func TestSCRAMSHA1WithFIPS(t *testing.T) {
	mk := func(mech string) *snapshot.Snapshot {
		s := at("8.0.19", "community")
		s.Nodes[0].Options["net.tls.FIPSMode"] = json.RawMessage(`true`)
		s.Nodes[0].StartupParameters = map[string]json.RawMessage{"authenticationMechanisms": json.RawMessage(mech)}
		return s
	}
	if f := find(run(t, mk(`"SCRAM-SHA-1,SCRAM-SHA-256"`), "8.3"), "scram-sha1-with-fips"); f == nil || f.Severity != Error {
		t.Fatalf("string form: got %+v", f)
	}
	if f := find(run(t, mk(`["SCRAM-SHA-256"]`), "8.3"), "scram-sha1-with-fips"); f != nil {
		t.Errorf("SHA-256 only: unexpected %+v", f)
	}
	s := mk(`"SCRAM-SHA-1"`)
	delete(s.Nodes[0].Options, "net.tls.FIPSMode")
	if f := find(run(t, s, "9.0"), "scram-sha1-with-fips"); f != nil {
		t.Errorf("no FIPS: unexpected %+v", f)
	}
}

func TestTimeFieldDollar(t *testing.T) {
	s := at("8.0.19", "community")
	s.Data.Databases = []snapshot.Database{{Name: "iot", Collections: []snapshot.Collection{
		{Name: "bad", Type: "timeseries", Options: json.RawMessage(`{"timeseries":{"timeField":"$ts"}}`)},
		{Name: "ok", Type: "timeseries", Options: json.RawMessage(`{"timeseries":{"timeField":"ts"}}`)},
	}}}
	f := find(run(t, s, "8.3"), "timeseries-timefield-dollar")
	if f == nil || len(f.Items) != 1 || !strings.HasPrefix(f.Items[0], "iot.bad") {
		t.Fatalf("got %+v", f)
	}
}

func TestFCBIS83(t *testing.T) {
	s := at("8.0.19", "community")
	s.Nodes[1].Parameters = map[string]json.RawMessage{"initialSyncMethod": json.RawMessage(`"fileCopyBased"`)}
	s.Nodes[2].Parameters = map[string]json.RawMessage{"initialSyncMethod": json.RawMessage(`"logical"`)}
	f := find(run(t, s, "8.3"), "initial-sync-filecopy-known-issue")
	if f == nil || len(f.Items) != 1 || f.Items[0] != "b:27017" {
		t.Fatalf("got %+v", f)
	}
}

func TestQETextPreview(t *testing.T) {
	s := at("8.3.13", "community")
	s.Data.Databases = []snapshot.Database{{Name: "crm", Collections: []snapshot.Collection{{Name: "c", Type: "collection",
		EncryptedFields: json.RawMessage(`{"fields":[{"path":"name","queries":[{"queryType":"substringPreview"},{"queryType":"equality"}]}]}`)}}}}
	if f := findHop(run(t, s, "9.0"), "qe-text-preview-removed", "8.3 → 9.0"); f == nil || f.Items[0] != "crm.c (substringPreview)" {
		t.Fatalf("got %+v", f)
	}
}

func TestFLESubstringLimits(t *testing.T) {
	s := at("8.3.13", "community")
	s.Nodes[0].StartupParameters = map[string]json.RawMessage{"fleDisableSubstringPreviewParameterLimits": json.RawMessage(`"true"`)}
	if f := find(run(t, s, "9.0"), "fle-substring-limits-override"); f == nil {
		t.Fatal("expected warning")
	}
}

func TestGroupEmptyFieldName(t *testing.T) {
	s := at("8.0.19", "community")
	s.Data.Databases = []snapshot.Database{
		view("a", "bad", `[{"$group":{"_id":"$k","":{"$sum":1}}}]`),
		view("b", "ok", `[{"$group":{"_id":"$k","n":{"$sum":1}}}]`),
	}
	f := find(run(t, s, "9.0"), "group-empty-field-name")
	if f == nil || len(f.Items) != 1 || f.Items[0] != "a.bad" {
		t.Fatalf("got %+v", f)
	}
}

func TestServerSideJS90(t *testing.T) {
	s := at("8.0.19", "community")
	s.Data.Databases = []snapshot.Database{view("a", "js", `[{"$addFields":{"x":{"$function":{"body":"function(){return 1}","args":[],"lang":"js"}}}}]`)}
	f := find(run(t, s, "9.0"), "server-side-js-9.0")
	if f == nil || f.Severity != Warning || f.Items[0] != "a.js: $function in view pipeline" {
		t.Fatalf("x86: got %+v", f)
	}
	for i := range s.Nodes {
		s.Nodes[i].HostInfo.CPUArch = "ppc64le"
	}
	if f := find(run(t, s, "9.0"), "server-side-js-9.0"); f == nil || f.Severity != Error {
		t.Fatalf("ppc64le: got %+v", f)
	}
	if f := find(run(t, at("8.0.19", "community"), "9.0"), "server-side-js-9.0"); f != nil {
		t.Errorf("no JS: unexpected %+v", f)
	}
}

func TestPSMDBJournal(t *testing.T) {
	s := at("6.0.20", "psmdb")
	s.Nodes[0].Options["storage.journal.enabled"] = json.RawMessage(`true`)
	if f := find(run(t, s, "7.0"), "psmdb-journal-option-ignored"); f == nil {
		t.Fatal("expected notice")
	}
	s = at("6.0.20", "community")
	s.Nodes[0].Options["storage.journal.enabled"] = json.RawMessage(`true`)
	if f := find(run(t, s, "7.0"), "psmdb-journal-option-ignored"); f != nil {
		t.Errorf("community: unexpected %+v", f)
	}
}

func TestPSMDBKMIPAndVault(t *testing.T) {
	cases := []struct {
		version, opt, rule string
		target, hop        string
		want               bool
	}{
		{"6.0.20-17", "security.kmip.serverName", "psmdb-kmip-key-active", "8.0", "6.0 → 7.0", true},
		{"7.0.12-7", "security.kmip.serverName", "psmdb-kmip-key-active", "8.0", "7.0 → 8.0", true},
		{"7.0.20-11", "security.kmip.serverName", "psmdb-kmip-key-active", "8.0", "", false},
		{"7.0.14-9", "security.vault.serverName", "psmdb-vault-metadata-permission", "8.0", "7.0 → 8.0", true},
		{"7.0.15-9", "security.vault.serverName", "psmdb-vault-metadata-permission", "8.0", "", false},
	}
	for _, c := range cases {
		s := at(c.version, "psmdb")
		s.Nodes[0].Options[c.opt] = json.RawMessage(`"kms.example.com"`)
		res := run(t, s, c.target)
		f := find(res, c.rule)
		if (f != nil) != c.want {
			t.Errorf("%s %s: got %+v", c.version, c.rule, f)
			continue
		}
		if f != nil && f.Hop != c.hop {
			t.Errorf("%s %s: hop %s want %s", c.version, c.rule, f.Hop, c.hop)
		}
		if countRule(res, c.rule) > 1 {
			t.Errorf("%s %s: reported more than once", c.version, c.rule)
		}
	}
}

func TestBehaviorRulesPerHop(t *testing.T) {
	res := run(t, at("6.0.20", "community"), "9.0")
	want := map[string][]string{
		"6.0 → 7.0": {"add-rounding", "natural-hint-values", "setclusterparameter-active"},
		"7.0 → 8.0": {"null-undefined-match", "majority-write-ack", "compact-concurrency"},
		"8.0 → 9.0": {"ftdc-directory-size", "trim-limits", "changestream-getmore-errors", "multikey-query-killed"},
	}
	for _, h := range res.Hops {
		got := map[string]bool{}
		for _, c := range h.Checks {
			got[c.RuleID] = true
		}
		for _, id := range want[h.Hop.String()] {
			if !got[id] {
				t.Errorf("hop %s: missing check %s", h.Hop, id)
			}
		}
	}
}

func TestCuratedRulesHaveDocs(t *testing.T) {
	for _, r := range All() {
		if r.Scope == ScopeHop && r.DocURL != "" && !strings.HasPrefix(r.DocURL, "https://") {
			t.Errorf("%s: bad doc url %q", r.ID, r.DocURL)
		}
	}
	for _, d := range deprecatedCommands {
		if !strings.HasPrefix(d.doc, "https://") {
			t.Errorf("%s: missing doc", d.cmd)
		}
	}
}

func TestKernelFromOSVersion(t *testing.T) {
	s := base()
	s.Nodes[0].HostInfo.OSVersion = "Kernel 6.12.115+deb13.1-amd64"
	got := kernelVersions(s)
	if len(got["6.12.115+deb13.1-amd64"]) != 1 {
		t.Errorf("kernelVersions = %v", got)
	}
}

func TestRseqUsesServerEvidence(t *testing.T) {
	// An 8.0 source without --local: the servers' own tcmalloc state decides.
	s := at("8.0.19", "community")
	for i := range s.Nodes {
		s.Nodes[i].TCMalloc = &snapshot.TCMallocInfo{UsingPerCPUCaches: true, CPUFreeBytes: 1 << 20}
	}
	c := checkOf(t, run(t, s, "9.0"), "tcmalloc-glibc-rseq")
	if c.Status != StatusOK {
		t.Fatalf("per-CPU caches on everywhere: status %s (%s)", c.Status, c.Reason)
	}
	s.Nodes[1].TCMalloc.UsingPerCPUCaches = false
	s.Nodes[1].TCMalloc.CPUFreeBytes = 0
	f := find(run(t, s, "9.0"), "tcmalloc-glibc-rseq")
	if f == nil || f.Severity != Notice || len(f.Items) != 1 || !strings.Contains(f.Items[0], s.Nodes[1].Host+": usingPerCPUCaches false") {
		t.Fatalf("got %+v", f)
	}
	// A 7.0 source reports nothing: without --local the check cannot run.
	if c := checkOf(t, run(t, at("7.0.29", "community"), "8.0"), "tcmalloc-glibc-rseq"); c.Status != StatusNotChecked {
		t.Errorf("7.0 without --local: %s", c.Status)
	}
}
