package rules

import (
	"encoding/json"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
)

func init() {
	for _, id := range []string{
		"addshard-maxsize", "autosplit-removed", "chunksize-range", "changestream-getmore-errors",
		"ftdc-directory-size", "hedged-reads-default", "natural-hint-values", "null-undefined-match",
		"querystats-keys", "timeseries-shardkey-timefield",
	} {
		passNotOnFixtures[id] = "unit test TestBehaviorSummaries"
	}
	// Both always emit a NOTICE: the majority acknowledgment change applies to
	// every deployment that writes with "majority", and the multikey
	// QueryKilledError cannot be verified from server state.
	passNotOnFixtures["majority-write-ack"] = "always reports"
	passNotOnFixtures["multikey-query-killed"] = "always reports"
}

// TestBehaviorSummaries asserts what each behavior rule says when it passes.
func TestBehaviorSummaries(t *testing.T) {
	summary := func(t *testing.T, s *snapshot.Snapshot, target, id, want string) {
		t.Helper()
		if got := expect(t, s, target, id, StatusOK, 0).Summary; got != want {
			t.Errorf("%s summary\n got  %q\n want %q", id, got, want)
		}
	}

	// 7.0
	s := withCounters(at("6.0.20", "community"))
	summary(t, s, "7.0", "add-rounding", "$add was not used on 3 members since startup 3d ago, nor in any view or validator.")
	s.Profiler = &snapshot.ProfilerInfo{DatabasesProfiled: []string{"a:27017/app", "b:27017/app"}}
	summary(t, s, "7.0", "add-rounding", "$add was not used on 3 members since startup 3d ago, in any view or validator, nor in the profiled operations.")
	summary(t, s, "7.0", "natural-hint-values", "the profiler on 2 databases recorded no $natural hint or sort with a value other than 1 or -1.")
	summary(t, s, "7.0", "setclusterparameter-active", "no setClusterParameter operation was running when the snapshot was taken.")

	sh := shardedAt("6.0.20")
	summary(t, sh, "7.0", "autosplit-removed", "there is no sharded collection and no autosplit setting in config.settings.")
	summary(t, sh, "7.0", "chunksize-range", "config.settings has no chunksize setting, so the default applies.")
	sh.Sharding.ChunkSizeMB = 128
	summary(t, sh, "7.0", "chunksize-range", "config.settings chunksize is 128 MB, between 1 and 1024 MB.")
	summary(t, sh, "7.0", "addshard-maxsize", "the only shard has no maxSize set.")

	// 8.0
	s = at("7.0.29", "community")
	s.DeepCheck = &snapshot.DeepCheckInfo{Ran: true, Collections: 2, Documents: 50}
	summary(t, s, "8.0", "null-undefined-match", "the --deep-check sample of 50 documents from 2 collections has no BSON undefined value.")
	summary(t, s, "8.0", "system-buckets-orphans", "no system.buckets collection exists in the 0 databases listed.")
	s.Data.Databases = []snapshot.Database{{Name: "iot", BucketCollections: []string{"system.buckets.metrics"},
		Collections: []snapshot.Collection{{Name: "metrics", Type: "timeseries"}}}}
	summary(t, s, "8.0", "system-buckets-orphans", "the only system.buckets collection belongs to a time series collection.")
	withCounters(s)
	summary(t, s, "8.0", "compact-concurrency", "compact was not run on 3 members since startup 3d ago.")

	sh = shardedAt("7.0.29")
	summary(t, sh, "8.0", "direct-shard-operations", "no application driver is connected directly to the shard member inspected.")
	sh.Nodes[2].Hedging = &snapshot.HedgingMetrics{NumTotalOperations: 100}
	sh.Nodes[2].UptimeSeconds = 7200
	summary(t, sh, "8.0", "hedged-reads-default", "1 mongos performed no hedged read since startup 2h ago.")
	sh.Sharding.CollectionsRead = true
	sh.Sharding.Collections = []snapshot.ShardedCollection{
		{NS: "app.orders", Key: []snapshot.IndexKey{{Field: "customer", Value: json.RawMessage("1")}}},
		{NS: "app.system.buckets.m", Key: []snapshot.IndexKey{{Field: "meta", Value: json.RawMessage("1")}}, TimeField: "ts", MetaField: "s"},
	}
	summary(t, sh, "8.0", "timeseries-shardkey-timefield", "checked 2 sharded collections in config.collections (1 time series); none is sharded on its timeField.")

	// 8.3
	d := shardedAt("8.0.19")
	summary(t, d, "8.3", "ddl-via-mongos", "no application driver is connected directly to the shard member inspected.")
	withCounters(d)
	summary(t, d, "8.3", "ddl-via-mongos", "no application driver is connected directly to the shard member inspected, and applyOps was not run on them since startup 3d ago.")

	s = withCounters(at("8.0.19", "community"))
	summary(t, s, "8.3", "2dsphere-index-v4", "no 2dsphere index exists in the 0 collections listed.")
	summary(t, s, "8.3", "trim-limits", "$trim, $ltrim and $rtrim were not used on 3 members since startup 3d ago, nor in any view or validator, and there is no text index.")
	summary(t, s, "8.3", "dateadd-preepoch", "$dateAdd and $dateSubtract were not used on 3 members since startup 3d ago, nor in any view or validator.")
	for i := range s.Nodes {
		s.Nodes[i].Parameters = map[string]json.RawMessage{"diagnosticDataCollectionDirectorySizeMB": json.RawMessage(`500`)}
	}
	summary(t, s, "8.3", "ftdc-directory-size", "diagnosticDataCollectionDirectorySizeMB is set at startup or already 500 MiB or more on 3 members.")

	// 9.0
	s = withCounters(at("8.3.13", "community"))
	summary(t, s, "9.0", "changestream-getmore-errors", "$changeStream was not used on 3 members since startup 3d ago.")
	summary(t, s, "9.0", "querystats-keys", "$queryStats was not used on 3 members since startup 3d ago.")
	summary(t, s, "9.0", "rename-cross-db-locks", "renameCollection was not run on 3 members since startup 3d ago.")
	summary(t, s, "9.0", "2dsphere-error-codes", "no 2dsphere index exists in the 0 collections listed.")
}
