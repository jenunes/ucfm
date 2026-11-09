package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// checkOf returns the result of ruleID in any section of res.
func checkOf(t *testing.T, res *Result, ruleID string) CheckResult {
	t.Helper()
	for _, c := range res.Checks {
		if c.RuleID == ruleID {
			return c
		}
	}
	for _, h := range res.Hops {
		for _, c := range h.Checks {
			if c.RuleID == ruleID {
				return c
			}
		}
	}
	t.Fatalf("check %s not run", ruleID)
	return CheckResult{}
}

// expect asserts the status (and, for issues, the first finding's severity).
func expect(t *testing.T, s *snapshot.Snapshot, target, ruleID string, status CheckStatus, sev Severity) CheckResult {
	t.Helper()
	c := checkOf(t, run(t, s, target), ruleID)
	if c.Status != status {
		t.Fatalf("%s: status %s (%s), want %s; findings %+v", ruleID, c.Status, c.Reason, status, c.Findings)
	}
	if status == StatusIssues && c.Findings[0].Severity != sev {
		t.Fatalf("%s: severity %s, want %s", ruleID, c.Findings[0].Severity, sev)
	}
	return c
}

// withCounters gives every node empty counter maps (counters known, zero).
func withCounters(s *snapshot.Snapshot) *snapshot.Snapshot {
	for i := range s.Nodes {
		s.Nodes[i].UptimeSeconds = 3 * 86400
		s.Nodes[i].OperatorCounters = map[string]map[string]int64{
			"expressions": {}, "match": {}, "groupAccumulators": {}, "windowAccumulators": {},
		}
		s.Nodes[i].AggStageCounters = map[string]int64{}
		if s.Nodes[i].CommandCounters == nil {
			s.Nodes[i].CommandCounters = map[string]int64{}
		}
	}
	return s
}

// shardedAt builds a sharded cluster: one shard member, one config member,
// one mongos.
func shardedAt(v string) *snapshot.Snapshot {
	s := at(v, "community")
	s.Topology.Kind = snapshot.KindSharded
	s.Nodes[0].ShardName, s.Nodes[0].ReplSet = "sh1", "sh1"
	s.Nodes[1].IsConfig, s.Nodes[1].ReplSet = true, "cfg"
	s.Nodes[2].Role, s.Nodes[2].ReplSet, s.Nodes[2].FCV = snapshot.RoleMongos, "", ""
	s.Topology.ReplSets = []snapshot.ReplSet{
		{Name: "sh1", Role: "shard", Members: []snapshot.Member{{Host: s.Nodes[0].Host, State: snapshot.RolePrimary, Health: 1, Votes: 1}}},
		{Name: "cfg", Role: "config", Members: []snapshot.Member{{Host: s.Nodes[1].Host, State: snapshot.RolePrimary, Health: 1, Votes: 1}}},
	}
	s.Sharding = &snapshot.ShardingInfo{Shards: []snapshot.Shard{{ID: "sh1", Host: "sh1/a:27017"}}, BalancerMode: "off"}
	return s
}

func bview(db, name, pipeline string) snapshot.Database {
	return snapshot.Database{Name: db, Collections: []snapshot.Collection{{Name: name, Type: "view", ViewOn: "c", Pipeline: json.RawMessage(pipeline)}}}
}

func withIndex(s *snapshot.Snapshot, typ string) *snapshot.Snapshot {
	s.Data.Databases = append(s.Data.Databases, snapshot.Database{Name: "geo", Collections: []snapshot.Collection{{
		Name: "places", Type: "collection",
		Indexes: []snapshot.Index{{Name: "loc_1", Key: []snapshot.IndexKey{{Field: "loc", Value: json.RawMessage(`"` + typ + `"`)}}}},
	}}})
	return s
}

// ---------------------------------------------------------------- 7.0

func TestAddRounding(t *testing.T) {
	s := withCounters(at("6.0.20", "community"))
	s.Nodes[0].OperatorCounters["expressions"]["$add"] = 42
	c := expect(t, s, "7.0", "add-rounding", StatusIssues, Warning)
	if !strings.Contains(c.Findings[0].Items[0], "$add: 42 uses since startup 3d ago") {
		t.Errorf("items %v", c.Findings[0].Items)
	}
	expect(t, withCounters(at("6.0.20", "community")), "7.0", "add-rounding", StatusOK, 0)
	noData := at("6.0.20", "community")
	noData.Collection.SkipData = true
	expect(t, noData, "7.0", "add-rounding", StatusNotChecked, 0)
	v := at("6.0.20", "community")
	v.Data.Databases = []snapshot.Database{bview("app", "v", `[{"$project":{"t":{"$add":["$a","$b"]}}}]`)}
	expect(t, v, "7.0", "add-rounding", StatusIssues, Warning)
}

func TestAutosplitChunkSizeMaxSize(t *testing.T) {
	rs := at("6.0.20", "community")
	expect(t, rs, "7.0", "autosplit-removed", StatusNotApplicable, 0)
	expect(t, rs, "7.0", "chunksize-range", StatusNotApplicable, 0)
	expect(t, rs, "7.0", "addshard-maxsize", StatusNotApplicable, 0)

	s := shardedAt("6.0.20")
	expect(t, s, "7.0", "autosplit-removed", StatusOK, 0)
	expect(t, s, "7.0", "chunksize-range", StatusOK, 0)
	expect(t, s, "7.0", "addshard-maxsize", StatusOK, 0)

	s.Sharding.ShardedCollections = 3
	s.Sharding.ChunkSizeMB = 2048
	s.Sharding.Shards[0].MaxSizeMB = 100
	expect(t, s, "7.0", "autosplit-removed", StatusIssues, Notice)
	expect(t, s, "7.0", "chunksize-range", StatusIssues, Error)
	expect(t, s, "7.0", "addshard-maxsize", StatusIssues, Warning)
}

func TestNaturalHintValues(t *testing.T) {
	s := at("6.0.20", "community")
	expect(t, s, "7.0", "natural-hint-values", StatusNotChecked, 0)
	s.Profiler = &snapshot.ProfilerInfo{DatabasesProfiled: []string{"a:27017/app"}, EntriesScanned: 10}
	expect(t, s, "7.0", "natural-hint-values", StatusOK, 0)
	s.Profiler.Evidence = map[string]*snapshot.ProfilerEvidence{snapshot.EvidenceNatural: {Count: 2, Examples: []string{`app.c find {"hint":{"$natural":2}}`}}}
	c := expect(t, s, "7.0", "natural-hint-values", StatusIssues, Warning)
	if !strings.Contains(strings.Join(c.Findings[0].Items, "\n"), `"$natural":2`) {
		t.Errorf("example missing: %v", c.Findings[0].Items)
	}
}

func TestSetClusterParameterActive(t *testing.T) {
	s := at("6.0.20", "community")
	expect(t, s, "7.0", "setclusterparameter-active", StatusOK, 0)
	s.ActiveSetClusterParameter = 1
	expect(t, s, "7.0", "setclusterparameter-active", StatusIssues, Warning)
}

// ---------------------------------------------------------------- 8.0

func TestNullUndefinedMatch(t *testing.T) {
	s := at("7.0.29", "community")
	c := expect(t, s, "8.0", "null-undefined-match", StatusIssues, Warning)
	if !strings.Contains(c.Findings[0].Action, "--deep-check") {
		t.Errorf("must suggest --deep-check: %q", c.Findings[0].Action)
	}
	s.Profiler = &snapshot.ProfilerInfo{DatabasesProfiled: []string{"a/app"}, Evidence: map[string]*snapshot.ProfilerEvidence{snapshot.EvidenceNullEq: {Count: 4}}}
	c = expect(t, s, "8.0", "null-undefined-match", StatusIssues, Warning)
	if !strings.HasPrefix(c.Findings[0].Items[0], "profiler: 4 queries match on null") {
		t.Errorf("profiler evidence missing: %v", c.Findings[0].Items)
	}
	s.Profiler = nil
	s.DeepCheck = &snapshot.DeepCheckInfo{Ran: true, Collections: 2, Documents: 50}
	expect(t, s, "8.0", "null-undefined-match", StatusOK, 0)
	s.DeepCheck.Undefined = []snapshot.UndefinedField{{NS: "app.items", Path: "u", Count: 3}}
	c = expect(t, s, "8.0", "null-undefined-match", StatusIssues, Warning)
	if c.Findings[0].Items[0] != "app.items: u (3 documents in the sample)" {
		t.Errorf("items %v", c.Findings[0].Items)
	}
}

func TestMajorityWriteAck(t *testing.T) {
	s := at("7.0.29", "community")
	expect(t, s, "8.0", "majority-write-ack", StatusNotChecked, 0)
	s.DefaultRWConcern = &snapshot.DefaultRWConcern{WriteConcern: json.RawMessage(`{"w":"majority","wtimeout":0}`), WriteConcernSource: "implicit"}
	c := expect(t, s, "8.0", "majority-write-ack", StatusIssues, Notice)
	if !strings.Contains(c.Findings[0].Items[0], "source: implicit") {
		t.Errorf("items %v", c.Findings[0].Items)
	}
}

func TestDirectShardOperationsAndDDL(t *testing.T) {
	expect(t, at("7.0.29", "community"), "8.0", "direct-shard-operations", StatusNotApplicable, 0)
	s := shardedAt("7.0.29")
	expect(t, s, "8.0", "direct-shard-operations", StatusOK, 0)
	s.Nodes[0].Clients = []snapshot.ClientDriver{{DriverName: "nodejs", DriverVersion: "6.3.0", Connections: 4, AppNames: []string{"billing"}}}
	c := expect(t, s, "8.0", "direct-shard-operations", StatusIssues, Warning)
	if !strings.Contains(c.Findings[0].Items[0], "nodejs 6.3.0") {
		t.Errorf("items %v", c.Findings[0].Items)
	}
	s.Collection.EntryOnly = true
	expect(t, s, "8.0", "direct-shard-operations", StatusNotChecked, 0)

	d := shardedAt("8.0.19")
	expect(t, d, "8.3", "ddl-via-mongos", StatusOK, 0)
	d.Nodes[0].CommandCounters = map[string]int64{"applyOps": 7}
	expect(t, d, "8.3", "ddl-via-mongos", StatusIssues, Warning)
	expect(t, at("8.0.19", "community"), "8.3", "ddl-via-mongos", StatusNotApplicable, 0)
}

func TestHedgedReads(t *testing.T) {
	s := shardedAt("7.0.29")
	expect(t, s, "8.0", "hedged-reads-default", StatusNotChecked, 0)
	s.Nodes[2].Hedging = &snapshot.HedgingMetrics{NumTotalOperations: 100}
	expect(t, s, "8.0", "hedged-reads-default", StatusOK, 0)
	s.Nodes[2].Hedging.NumTotalHedgedOperations = 5
	expect(t, s, "8.0", "hedged-reads-default", StatusIssues, Notice)
	expect(t, at("7.0.29", "community"), "8.0", "hedged-reads-default", StatusNotApplicable, 0)
}

func TestSystemBucketsOrphans(t *testing.T) {
	s := at("7.0.29", "community")
	s.Data.Databases = []snapshot.Database{{Name: "iot", BucketCollections: []string{"system.buckets.metrics", "system.buckets.old"},
		Collections: []snapshot.Collection{{Name: "metrics", Type: "timeseries"}}}}
	c := expect(t, s, "8.0", "system-buckets-orphans", StatusIssues, Warning)
	if len(c.Findings[0].Items) != 1 || c.Findings[0].Items[0] != "iot.system.buckets.old" {
		t.Errorf("items %v", c.Findings[0].Items)
	}
	s.Data.Databases[0].BucketCollections = []string{"system.buckets.metrics"}
	expect(t, s, "8.0", "system-buckets-orphans", StatusOK, 0)
	s.Collection.SkipData = true
	expect(t, s, "8.0", "system-buckets-orphans", StatusNotChecked, 0)
}

func TestCompactConcurrency(t *testing.T) {
	s := withCounters(at("7.0.29", "community"))
	expect(t, s, "8.0", "compact-concurrency", StatusOK, 0)
	s.Nodes[1].CommandCounters["compact"] = 2
	expect(t, s, "8.0", "compact-concurrency", StatusIssues, Notice)
}

// ---------------------------------------------------------------- 8.3

func Test2dsphereIndexes(t *testing.T) {
	s := at("8.0.19", "community")
	expect(t, s, "8.3", "2dsphere-index-v4", StatusOK, 0)
	expect(t, at("8.3.13", "community"), "9.0", "2dsphere-error-codes", StatusOK, 0)
	withIndex(s, "2dsphere")
	c := expect(t, s, "8.3", "2dsphere-index-v4", StatusIssues, Notice)
	if c.Findings[0].Items[0] != "geo.places: loc_1" {
		t.Errorf("items %v", c.Findings[0].Items)
	}
	g := withIndex(at("8.3.13", "community"), "2dsphere")
	expect(t, g, "9.0", "2dsphere-error-codes", StatusIssues, Notice)
	g.Collection.SkipData = true
	expect(t, g, "9.0", "2dsphere-error-codes", StatusNotChecked, 0)
}

func TestFTDCDirectorySize(t *testing.T) {
	s := at("8.0.19", "community")
	expect(t, s, "8.3", "ftdc-directory-size", StatusNotChecked, 0)
	for i := range s.Nodes {
		s.Nodes[i].Parameters = map[string]json.RawMessage{"diagnosticDataCollectionDirectorySizeMB": json.RawMessage(`200`)}
	}
	expect(t, s, "8.3", "ftdc-directory-size", StatusIssues, Notice)
	for i := range s.Nodes {
		s.Nodes[i].StartupParameters = map[string]json.RawMessage{"diagnosticDataCollectionDirectorySizeMB": json.RawMessage(`"200"`)}
	}
	expect(t, s, "8.3", "ftdc-directory-size", StatusOK, 0)

	// 8.0.10+ defaults to 250 MiB (seen on PSMDB 8.0.32 in the lab).
	s = at("8.0.32", "psmdb")
	for i := range s.Nodes {
		s.Nodes[i].Parameters = map[string]json.RawMessage{"diagnosticDataCollectionDirectorySizeMB": json.RawMessage(`250`)}
	}
	r := expect(t, s, "8.3", "ftdc-directory-size", StatusIssues, Notice)
	if got := r.Findings[0].Items[0]; !strings.HasPrefix(got, "using the default of 250 MiB") {
		t.Fatalf("item = %q", got)
	}
	// An explicit value at or above the new default is not reported.
	for i := range s.Nodes {
		s.Nodes[i].Parameters = map[string]json.RawMessage{"diagnosticDataCollectionDirectorySizeMB": json.RawMessage(`500`)}
	}
	expect(t, s, "8.3", "ftdc-directory-size", StatusOK, 0)
}

func TestTrimLimits(t *testing.T) {
	s := withCounters(at("8.0.19", "community"))
	expect(t, s, "8.3", "trim-limits", StatusOK, 0)
	s.Nodes[0].OperatorCounters["expressions"]["$ltrim"] = 9
	expect(t, s, "8.3", "trim-limits", StatusIssues, Notice)

	v := at("8.0.19", "community")
	v.Data.Databases = []snapshot.Database{bview("app", "v", `[{"$project":{"s":{"$trim":{"input":"$s","chars":"`+strings.Repeat("x", 5000)+`"}}}}]`)}
	c := expect(t, v, "8.3", "trim-limits", StatusIssues, Notice)
	if !strings.Contains(strings.Join(c.Findings[0].Items, "\n"), "chars of 5000 characters") {
		t.Errorf("items %v", c.Findings[0].Items)
	}
	expect(t, withIndex(at("8.0.19", "community"), "text"), "8.3", "trim-limits", StatusIssues, Notice)
}

func TestDateAddPreEpoch(t *testing.T) {
	s := withCounters(at("8.0.19", "community"))
	expect(t, s, "8.3", "dateadd-preepoch", StatusOK, 0)
	s.Nodes[0].OperatorCounters["expressions"]["$dateSubtract"] = 1
	expect(t, s, "8.3", "dateadd-preepoch", StatusIssues, Notice)
	// 8.3 changes also apply to the direct 8.0 → 9.0 step.
	expect(t, s, "9.0", "dateadd-preepoch", StatusIssues, Notice)
}

// ---------------------------------------------------------------- 9.0

func TestChangeStreamsQueryStatsRename(t *testing.T) {
	s := at("8.3.13", "community")
	expect(t, s, "9.0", "changestream-getmore-errors", StatusNotChecked, 0)
	withCounters(s)
	expect(t, s, "9.0", "changestream-getmore-errors", StatusOK, 0)
	expect(t, s, "9.0", "querystats-keys", StatusOK, 0)
	expect(t, s, "9.0", "rename-cross-db-locks", StatusOK, 0)
	s.Nodes[0].AggStageCounters["$changeStream"] = 12
	s.Nodes[0].AggStageCounters["$queryStats"] = 3
	s.Nodes[0].CommandCounters["renameCollection"] = 1
	expect(t, s, "9.0", "changestream-getmore-errors", StatusIssues, Warning)
	expect(t, s, "9.0", "querystats-keys", StatusIssues, Notice)
	expect(t, s, "9.0", "rename-cross-db-locks", StatusIssues, Notice)
	expect(t, shardedAt("8.3.13"), "9.0", "rename-cross-db-locks", StatusNotApplicable, 0)
}

func TestMultikeyAlwaysNotice(t *testing.T) {
	c := expect(t, at("8.3.13", "community"), "9.0", "multikey-query-killed", StatusIssues, Notice)
	if !strings.Contains(c.Findings[0].Message, "cannot be verified") {
		t.Errorf("message %q", c.Findings[0].Message)
	}
}

func TestServerSideJSCounters(t *testing.T) {
	s := withCounters(at("8.3.13", "community"))
	s.Nodes[0].OperatorCounters["match"]["$where"] = 5
	c := expect(t, s, "9.0", "server-side-js-9.0", StatusIssues, Warning)
	if !strings.Contains(strings.Join(c.Findings[0].Items, "\n"), "$where: 5 uses") {
		t.Errorf("items %v", c.Findings[0].Items)
	}
}

func TestBehaviorRulesCategoryAndDocs(t *testing.T) {
	ids := []string{"add-rounding", "autosplit-removed", "chunksize-range", "addshard-maxsize", "natural-hint-values",
		"setclusterparameter-active", "null-undefined-match", "majority-write-ack", "direct-shard-operations",
		"hedged-reads-default", "system-buckets-orphans", "compact-concurrency", "ddl-via-mongos", "2dsphere-index-v4",
		"ftdc-directory-size", "trim-limits", "dateadd-preepoch", "changestream-getmore-errors", "2dsphere-error-codes",
		"rename-cross-db-locks", "querystats-keys", "multikey-query-killed"}
	for _, id := range ids {
		r := rule(id)
		if r.Check == nil {
			t.Errorf("%s not registered", id)
			continue
		}
		if r.Category != "behavior" || !strings.HasPrefix(r.DocURL, "https://www.mongodb.com/docs/") || len(r.Hops) == 0 {
			t.Errorf("%s: category %q doc %q hops %v", id, r.Category, r.DocURL, r.Hops)
		}
	}
	if rule("behavior-changes").Check != nil {
		t.Error("behavior-changes must be removed")
	}
}

func TestTimeseriesShardKeyTimeField(t *testing.T) {
	expect(t, at("7.0.12", "community"), "8.0", "timeseries-shardkey-timefield", StatusNotApplicable, 0)

	s := shardedAt("7.0.12")
	expect(t, s, "8.0", "timeseries-shardkey-timefield", StatusNotChecked, 0)

	key := func(kv ...string) []snapshot.IndexKey {
		var out []snapshot.IndexKey
		for i := 0; i < len(kv); i += 2 {
			out = append(out, snapshot.IndexKey{Field: kv[i], Value: json.RawMessage(kv[i+1])})
		}
		return out
	}
	s.Sharding.CollectionsRead = true
	s.Sharding.Collections = []snapshot.ShardedCollection{
		{NS: "app.orders", Key: key("customer", "1")},
		{NS: "app.system.buckets.bymeta", Key: key("meta", "1"), TimeField: "ts", MetaField: "sensor"},
		{NS: "app.unsplit", Key: key("_id", "1"), Unsplittable: true},
	}
	expect(t, s, "8.0", "timeseries-shardkey-timefield", StatusOK, 0)

	s.Sharding.Collections = append(s.Sharding.Collections,
		snapshot.ShardedCollection{NS: "app.system.buckets.bytime", Key: key("meta", "1", "control.min.ts", "1"), TimeField: "ts", MetaField: "sensor"},
		// 8.2+ viewless time series store the user-facing namespace and key.
		snapshot.ShardedCollection{NS: "app.viewless", Key: key("t", "1"), TimeField: "t"})
	c := expect(t, s, "8.0", "timeseries-shardkey-timefield", StatusIssues, Warning)
	items := strings.Join(c.Findings[0].Items, "\n")
	for _, want := range []string{"app.bytime (shard key {sensor: 1, ts: 1})", "app.viewless (shard key {t: 1})"} {
		if !strings.Contains(items, want) {
			t.Errorf("items %q missing %q", items, want)
		}
	}
	if strings.Contains(items, "bymeta") {
		t.Errorf("a metaField shard key was reported: %q", items)
	}
	// Only the hop into 8.0 reports the deprecation.
	if c.Hop == "" || !strings.Contains(c.Hop, "8.0") {
		t.Errorf("hop %q", c.Hop)
	}
	s2 := shardedAt("8.0.4")
	s2.Sharding = s.Sharding
	for _, h := range run(t, s2, "9.0").Hops {
		for _, ch := range h.Checks {
			if ch.RuleID == "timeseries-shardkey-timefield" {
				t.Errorf("reported again on %v", h.Hop)
			}
		}
	}
}
