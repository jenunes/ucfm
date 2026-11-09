package rules

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
	"github.com/jenunes/ucfm/internal/upgradepath"
)

func loadFixture(t *testing.T, name string) *snapshot.Snapshot {
	t.Helper()
	s, err := snapshot.Load(filepath.Join("..", "..", "testdata", "snapshots", name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ids returns "hop|ruleId|SEVERITY" for every finding, sorted.
func ids(res *Result) []string {
	var out []string
	for _, f := range res.AllFindings() {
		out = append(out, f.Hop+"|"+f.RuleID+"|"+f.Severity.String())
	}
	sort.Strings(out)
	return out
}

func find(res *Result, ruleID string) *Finding {
	for _, f := range res.AllFindings() {
		if f.RuleID == ruleID {
			return &f
		}
	}
	return nil
}

// Planted on an anydbver PSMDB 6.0.29 replica set: FCV 5.0, a removed
// startup parameter on one secondary, a removed command in use, and a custom
// role with an action removed after 8.0.
func TestGoldenPSMDB60Planted(t *testing.T) {
	res, err := Run(loadFixture(t, "psmdb60-planted.json"), "9.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"6.0 → 7.0|command-removed-in-use|WARNING",
		"6.0 → 7.0|psmdb-journal-option-ignored|NOTICE",
		"7.0 → 8.0|null-undefined-match|WARNING",
		"8.0 → 9.0|ftdc-directory-size|NOTICE",
		"8.0 → 9.0|multikey-query-killed|NOTICE",
		"6.0 → 7.0|parameter-removed|ERROR",
		"8.0 → 9.0|catalog-fallback|NOTICE",
		"8.0 → 9.0|config-option-removed|WARNING",
		"8.0 → 9.0|role-action-removed|ERROR",
		"|backup-before-upgrade|NOTICE",
		"|fcv-matches-binary|ERROR",
		"|host-checks-coverage|NOTICE",
		"|startup-warnings|NOTICE",
		"|upgrade-path|WARNING", // 6.0 → 9.0 takes three upgrades
	}
	sort.Strings(want)
	if got := ids(res); !reflect.DeepEqual(got, want) {
		t.Errorf("findings:\n got  %v\n want %v", got, want)
	}
	if res.Max() != Error {
		t.Errorf("max severity = %v", res.Max())
	}
	if f := find(res, "parameter-removed"); f == nil || !strings.Contains(strings.Join(f.Items, " "), "internalQueryForceClassicEngine [172.21.0.3:27017]") {
		t.Errorf("parameter-removed items: %+v", f)
	}
}

func TestGoldenShardedBalancer(t *testing.T) {
	res, err := Run(loadFixture(t, "psmdb70sh.json"), "8.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(res, "sharding-balancer"); f == nil || f.Severity != Warning {
		t.Errorf("expected balancer warning, got %+v", f)
	}
	if res.Topology != snapshot.KindSharded || res.Flavor != "psmdb" {
		t.Errorf("topology/flavor = %s/%s", res.Topology, res.Flavor)
	}
}

func TestCleanCommunityRS(t *testing.T) {
	res, err := Run(loadFixture(t, "rs80.json"), "8.3", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.AllFindings() {
		if f.Severity == Error {
			t.Errorf("unexpected error finding %s: %v", f.RuleID, f.Items)
		}
	}
	if len(res.Hops) != 1 || res.Hops[0].Hop.String() != "8.0 → 8.3" {
		t.Errorf("hops = %+v", res.Hops)
	}
}

// base builds a minimal healthy 3-member 7.0 community replica set.
func base() *snapshot.Snapshot {
	s := &snapshot.Snapshot{SchemaVersion: snapshot.SchemaVersion, EntryHost: "a:27017",
		Topology: snapshot.Topology{Kind: snapshot.KindReplicaSet}}
	rs := snapshot.ReplSet{Name: "rs0", Role: "replset"}
	for i, h := range []string{"a:27017", "b:27017", "c:27017"} {
		role := snapshot.RoleSecondary
		if i == 0 {
			role = snapshot.RolePrimary
		}
		s.Nodes = append(s.Nodes, snapshot.Node{Host: h, Role: role, ReplSet: "rs0", Version: "7.0.29", Flavor: "community", FCV: "7.0",
			Options: map[string]json.RawMessage{"net.bindIp": json.RawMessage(`"0.0.0.0"`)}})
		rs.Members = append(rs.Members, snapshot.Member{Host: h, State: role, Health: 1, Priority: 1, Votes: 1})
	}
	s.Topology.ReplSets = []snapshot.ReplSet{rs}
	return s
}

func run(t *testing.T, s *snapshot.Snapshot, target string) *Result {
	t.Helper()
	res, err := Run(s, target, Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestHealthyBaseHasNoProblems(t *testing.T) {
	s := base()
	// Without a document sample, null-undefined-match asks for --deep-check.
	s.DeepCheck = &snapshot.DeepCheckInfo{Ran: true, Collections: 1, Documents: 10}
	res := run(t, s, "8.0")
	for _, f := range res.AllFindings() {
		if f.Severity > Notice {
			t.Errorf("unexpected %s %s", f.Severity, f.RuleID)
		}
	}
}

func TestMixedVersions(t *testing.T) {
	s := base()
	s.Nodes[2].Version = "6.0.20"
	res := run(t, s, "8.0")
	if f := find(res, "binary-versions-consistent"); f == nil || f.Severity != Error {
		t.Fatalf("got %+v", f)
	}
	// Source is the lowest series, so the path starts at 6.0.
	if res.Source != "6.0" || len(res.Hops) != 2 {
		t.Errorf("source %s hops %v", res.Source, res.Hops)
	}
}

func TestPatchDrift(t *testing.T) {
	s := base()
	s.Nodes[1].Version = "7.0.12"
	if f := find(run(t, s, "8.0"), "binary-versions-consistent"); f == nil || f.Severity != Notice {
		t.Fatalf("got %+v", f)
	}
}

func TestMemberHealthAndArbiter(t *testing.T) {
	s := base()
	s.Topology.ReplSets[0].Members[1].LagSeconds = 300
	s.Topology.ReplSets[0].Members[2].State = snapshot.RoleArbiter
	s.Topology.ReplSets[0].Members[2].ArbiterOnly = true
	res := run(t, s, "8.0")
	if f := find(res, "replset-members-healthy"); f == nil || !strings.Contains(f.Items[0], "300s behind") {
		t.Errorf("health: %+v", f)
	}
	if f := find(res, "replset-arbiters"); f == nil || f.Items[0] != "rs0/c:27017" {
		t.Errorf("arbiters: %+v", f)
	}
}

func TestNoPrimary(t *testing.T) {
	s := base()
	s.Topology.ReplSets[0].Members[0].State = snapshot.RoleSecondary
	if f := find(run(t, s, "8.0"), "replset-has-primary"); f == nil || f.Severity != Error {
		t.Fatalf("got %+v", f)
	}
}

func TestShardingStateRules(t *testing.T) {
	s := base()
	s.Topology.Kind = snapshot.KindSharded
	s.Sharding = &snapshot.ShardingInfo{BalancerMode: "off", ActiveResharding: 1, ActiveMigrations: 2,
		Shards: []snapshot.Shard{{ID: "sh1", Draining: true}}}
	res := run(t, s, "8.0")
	if find(res, "sharding-balancer") != nil {
		t.Error("balancer off must not be reported")
	}
	if f := find(res, "sharding-no-resharding"); f == nil || f.Severity != Error {
		t.Errorf("resharding: %+v", f)
	}
	if f := find(res, "sharding-no-migrations"); f == nil || len(f.Items) != 2 {
		t.Errorf("migrations: %+v", f)
	}
}

func TestRemovedOptionAndDeprecatedAlias(t *testing.T) {
	s := base()
	// net.transportLayer was removed in 8.0 (catalog diff 7.0 → 8.0).
	s.Nodes[0].Options["net.transportLayer"] = json.RawMessage(`"asio"`)
	res := run(t, s, "8.0")
	f := find(res, "config-option-removed")
	if f == nil || f.Severity != Error || f.Hop != "7.0 → 8.0" || !strings.HasPrefix(f.Items[0], "net.transportLayer") {
		t.Fatalf("got %+v", f)
	}
}

func TestOptionUnknownToSourceIsIgnored(t *testing.T) {
	s := base()
	s.Nodes[0].Options["made.up.option"] = json.RawMessage(`1`)
	if f := find(run(t, s, "8.0"), "config-option-removed"); f != nil {
		t.Fatalf("unexpected %+v", f)
	}
}

func TestRenamedParameter(t *testing.T) {
	s := base()
	s.Nodes[0].Version, s.Nodes[1].Version, s.Nodes[2].Version = "8.0.19", "8.0.19", "8.0.19"
	for i := range s.Nodes {
		s.Nodes[i].FCV = "8.0"
	}
	// Renamed between 8.0 and 8.3 according to the catalogs.
	s.Nodes[0].StartupParameters = map[string]json.RawMessage{"storageEngineConcurrentReadTransactions": json.RawMessage(`"64"`)}
	f := find(run(t, s, "8.3"), "parameter-renamed")
	if f == nil || !strings.Contains(f.Items[0], "executionControlConcurrentReadTransactions") {
		t.Fatalf("got %+v", f)
	}
}

func TestAggOperatorRemovedInView(t *testing.T) {
	s := base()
	s.Nodes[0].Version, s.Nodes[1].Version, s.Nodes[2].Version = "8.0.19", "8.0.19", "8.0.19"
	for i := range s.Nodes {
		s.Nodes[i].FCV = "8.0"
	}
	s.Data.Databases = []snapshot.Database{{Name: "app", Collections: []snapshot.Collection{{
		Name: "v", Type: "view", ViewOn: "c",
		Pipeline: json.RawMessage(`[{"$_internalReplaceRoot":{"newRoot":"$x"}},{"$match":{"d":{"$date":"2024-01-01T00:00:00Z"}}}]`),
	}}}}
	f := find(run(t, s, "8.3"), "agg-operator-removed")
	if f == nil || f.Items[0] != "app.v: $_internalReplaceRoot in view pipeline" {
		t.Fatalf("got %+v", f)
	}
}

func TestCommandsInternalIgnored(t *testing.T) {
	s := base()
	s.Nodes[0].CommandCounters = map[string]int64{"_configsvrMoveChunk": 5, "getLastError": 0}
	if f := find(run(t, s, "8.0"), "command-removed-in-use"); f != nil {
		t.Fatalf("unexpected %+v", f)
	}
}

func TestPathErrorStillRunsGlobalRules(t *testing.T) {
	s := base()
	res := run(t, s, "6.0") // downgrade
	if f := find(res, "upgrade-path"); f == nil || f.Severity != Error {
		t.Fatalf("got %+v", f)
	}
	if find(res, "backup-before-upgrade") == nil {
		t.Error("global rules should still run")
	}
}

func TestPathCheckSaysWhatWasChecked(t *testing.T) {
	one := pathCheck("6.0", "7.0", []upgradepath.Hop{{From: "6.0", To: "7.0"}}, nil, "replicaset", false)
	if one.Status != StatusOK || one.Summary != "from 6.0 (current) to 7.0 (target) is a supported upgrade path." {
		t.Errorf("one step: %+v", one)
	}
	path := []upgradepath.Hop{{From: "6.0", To: "7.0"}, {From: "7.0", To: "8.0"}}

	next := pathCheck("6.0", "8.0", path, nil, "replicaset", false)
	f := next.Findings[0]
	if next.Status != StatusIssues || f.Severity != Error ||
		f.Message != "MongoDB 8.0 is 2 upgrades away: 6.0 → 7.0 → 8.0. Only the next step, 6.0 → 7.0, was checked; the later steps depend on a deployment that does not exist yet." ||
		f.Action != "Upgrade to 7.0, then run ucfm again with --target 8.0." ||
		f.DocURL != "https://www.mongodb.com/docs/manual/release-notes/7.0-upgrade-replica-set/" || len(f.DocURLs) != 0 {
		t.Errorf("next step only: %+v", f)
	}
	if strings.Contains(f.Message+f.Action, "see-the-future") {
		t.Error("the path error must not advertise --see-the-future")
	}
	far := pathCheck("6.0", "9.0", append(path, upgradepath.Hop{From: "8.0", To: "9.0"}), nil, "replicaset", false)
	if a := far.Findings[0].Action; a != "Upgrade to 7.0, then run ucfm again (--target 8.0, or --target 9.0 to continue the path)." {
		t.Errorf("three steps action %q", a)
	}

	all := pathCheck("6.0", "8.0", path, nil, "sharded", true)
	f = all.Findings[0]
	if f.Severity != Warning || !strings.Contains(f.Message, "2 upgrades in sequence: 6.0 → 7.0 → 8.0. Each one is a rolling binary upgrade.") ||
		f.Action != "Do the upgrades one at a time." {
		t.Errorf("see the future: %+v", f)
	}
	if got := append([]string{f.DocURL}, f.DocURLs...); !reflect.DeepEqual(got, []string{
		"https://www.mongodb.com/docs/manual/release-notes/7.0-upgrade-sharded-cluster/",
		"https://www.mongodb.com/docs/manual/release-notes/8.0-upgrade-sharded-cluster/"}) {
		t.Errorf("upgrade docs %v", got)
	}
}

func TestDefaultChecksOnlyTheNextStep(t *testing.T) {
	s := loadFixture(t, "psmdb60-planted.json")
	res, err := Run(s, "9.0", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hops) != 1 || res.Hops[0].Hop.String() != "6.0 → 7.0" || res.CheckedTarget != "7.0" || len(res.PlannedPath) != 3 || res.SeeTheFuture {
		t.Fatalf("hops %v checked %s planned %v", res.Hops, res.CheckedTarget, res.PlannedPath)
	}
	if f := find(res, "upgrade-path"); f == nil || f.Severity != Error {
		t.Fatalf("upgrade-path: %+v", f)
	}
	for _, f := range res.AllFindings() {
		if f.Hop != "" && f.Hop != "6.0 → 7.0" {
			t.Errorf("finding outside the next step: %s %s", f.Hop, f.RuleID)
		}
	}
	all, err := Run(s, "9.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Hops) != 3 || all.CheckedTarget != "9.0" || !all.SeeTheFuture {
		t.Fatalf("see the future: hops %d checked %s", len(all.Hops), all.CheckedTarget)
	}
	if f := find(all, "upgrade-path"); f == nil || f.Severity != Warning {
		t.Fatalf("upgrade-path with the flag: %+v", f)
	}
}

func TestStartupWarningParsing(t *testing.T) {
	line := `{"t":{"$date":"2026-11-06T20:37:37.769-03:00"},"s":"W","c":"CONTROL","id":22202,"msg":"Failed to read file","attr":{"filepath":"/sys/kernel/mm/transparent_hugepage/enabled"}}`
	if got := warningMessage(line); got != "Failed to read file (/sys/kernel/mm/transparent_hugepage/enabled)" {
		t.Errorf("got %q", got)
	}
	if got := warningMessage("plain text"); got != "plain text" {
		t.Errorf("got %q", got)
	}
}

func TestDollarKeysSkipsExtJSON(t *testing.T) {
	got := dollarKeys(json.RawMessage(`{"$and":[{"a":{"$gt":{"$numberLong":"5"}}},{"$expr":{"$eq":["$x",{"$oid":"0123"}]}}]}`))
	want := []string{"$and", "$eq", "$expr", "$gt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestRuleIDsUniqueAndDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range All() {
		if seen[r.ID] {
			t.Errorf("duplicate %s", r.ID)
		}
		seen[r.ID] = true
		if r.Check == nil || r.Title == "" || r.Category == "" || r.Severity == 0 {
			t.Errorf("rule %s is incomplete", r.ID)
		}
	}
}

// Planted on an anydbver PSMDB 8.0.32 replica set: an option removed in 8.3
// and a parameter renamed in 8.3 on node2 (172.23.0.4), plus a custom role
// with the operationMetrics action removed in 8.3.
func TestGoldenPSMDB80Planted(t *testing.T) {
	for _, target := range []string{"8.3", "9.0"} {
		res, err := Run(loadFixture(t, "psmdb80-planted.json"), target, Options{SeeTheFuture: true})
		if err != nil {
			t.Fatal(err)
		}
		hop := "8.0 → " + target
		for _, want := range []struct {
			rule string
			sev  Severity
			item string
		}{
			{"config-option-removed", Error, "replication.enableMajorityReadConcern [172.23.0.4:27017]"},
			{"role-action-removed", Error, "admin.metricsReader: operationMetrics"},
			{"parameter-renamed", Warning, "storageEngineConcurrentReadTransactions → executionControlConcurrentReadTransactions [172.23.0.4:27017]"},
		} {
			f := find(res, want.rule)
			if f == nil || f.Severity != want.sev || f.Hop != hop || !containsStr(f.Items, want.item) {
				t.Errorf("target %s: %s = %+v", target, want.rule, f)
			}
		}
	}
}

// Every supported version's snapshot must load and check without errors
// from the engine itself.
func TestAllVersionFixturesRun(t *testing.T) {
	for fixture, target := range map[string]string{
		"psmdb60-planted.json": "7.0", "psmdb70sh.json": "8.0", "rs80.json": "8.3",
		"psmdb83.json": "9.0", "rs90.json": "9.0", "psmdb60-local.json": "8.0",
	} {
		if _, err := Run(loadFixture(t, fixture), target, Options{SeeTheFuture: true}); err != nil {
			t.Errorf("%s → %s: %v", fixture, target, err)
		}
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
