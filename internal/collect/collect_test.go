package collect

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/jenunes/ucfm/internal/snapshot"
)

func raw(t *testing.T, d bson.D) bson.Raw {
	t.Helper()
	b, err := bson.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFlattenStopsAtSetParameter(t *testing.T) {
	parsed := raw(t, bson.D{
		{Key: "net", Value: bson.D{{Key: "bindIp", Value: "0.0.0.0"}, {Key: "port", Value: int32(27017)}}},
		{Key: "storage", Value: bson.D{{Key: "wiredTiger", Value: bson.D{{Key: "engineConfig", Value: bson.D{{Key: "cacheSizeGB", Value: 1.5}}}}}}},
		{Key: "setParameter", Value: bson.D{{Key: "enableLocalhostAuthBypass", Value: "false"}}},
		{Key: "replication", Value: bson.D{{Key: "replSetName", Value: "rs0"}}},
	})
	out := map[string]json.RawMessage{}
	flatten(parsed, "", out, map[string]bool{"setParameter": true})
	want := map[string]string{
		"net.bindIp": `"0.0.0.0"`,
		"net.port":   `27017`,
		"storage.wiredTiger.engineConfig.cacheSizeGB": `1.5`,
		"setParameter":            `{"enableLocalhostAuthBypass":"false"}`,
		"replication.replSetName": `"rs0"`,
	}
	if len(out) != len(want) {
		t.Fatalf("got keys %v", keys(out))
	}
	for k, v := range want {
		if string(out[k]) != v {
			t.Errorf("%s = %s, want %s", k, out[k], v)
		}
	}
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestHostsFromShardString(t *testing.T) {
	set, hosts := hostsFromShardString("shard01/h1:27018,h2:27018")
	if set != "shard01" || !reflect.DeepEqual(hosts, []string{"h1:27018", "h2:27018"}) {
		t.Errorf("got %q %v", set, hosts)
	}
	set, hosts = hostsFromShardString("h1:27019")
	if set != "" || !reflect.DeepEqual(hosts, []string{"h1:27019"}) {
		t.Errorf("got %q %v", set, hosts)
	}
}

func TestCommandCounters(t *testing.T) {
	r := raw(t, bson.D{
		{Key: "<UNKNOWN>", Value: int64(0)},
		{Key: "find", Value: bson.D{{Key: "failed", Value: int64(0)}, {Key: "total", Value: int64(42)}}},
		{Key: "mapReduce", Value: bson.D{{Key: "failed", Value: int64(1)}, {Key: "total", Value: int64(3)}}},
		{Key: "update", Value: bson.D{{Key: "arrayFilters", Value: int64(0)}, {Key: "total", Value: int64(7)}}},
	})
	got := commandCounters(r)
	want := map[string]int64{"find": 42, "mapReduce": 3, "update": 7}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"mongodb://admin:s3cr@t@h:27017/":   "mongodb://admin:***@h:27017/",
		"mongodb+srv://u:p@cluster.example": "mongodb+srv://u:***@cluster.example",
		"mongodb://h:27017":                 "mongodb://h:27017",
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Errorf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectionFromListing(t *testing.T) {
	r := raw(t, bson.D{
		{Key: "name", Value: "v1"},
		{Key: "type", Value: "view"},
		{Key: "options", Value: bson.D{
			{Key: "viewOn", Value: "orders"},
			{Key: "pipeline", Value: bson.A{bson.D{{Key: "$match", Value: bson.D{{Key: "$where", Value: "true"}}}}}},
		}},
	})
	c := collectionFromListing(r)
	if c.Name != "v1" || c.Type != "view" || c.ViewOn != "orders" {
		t.Errorf("unexpected %+v", c)
	}
	if string(c.Pipeline) != `[{"$match":{"$where":"true"}}]` {
		t.Errorf("pipeline = %s", c.Pipeline)
	}
}

func TestRecentMongos(t *testing.T) {
	now := time.Now()
	list := []snapshot.Mongos{
		{Host: "fresh:27017", Ping: now.Add(-time.Minute)},
		{Host: "stale:27017", Ping: now.Add(-48 * time.Hour)},
	}
	got := recentMongos(list, now, 10*time.Minute)
	if len(got) != 1 || got[0].Host != "fresh:27017" {
		t.Errorf("got %v", got)
	}
}

func TestShardedCollection(t *testing.T) {
	r := raw(t, bson.D{
		{Key: "_id", Value: "app.system.buckets.ts"},
		{Key: "key", Value: bson.D{{Key: "meta", Value: int32(1)}, {Key: "control.min.t", Value: int32(1)}}},
		{Key: "unique", Value: false},
		{Key: "timeseriesFields", Value: bson.D{{Key: "timeField", Value: "t"}, {Key: "metaField", Value: "m"}, {Key: "granularity", Value: "seconds"}}},
	})
	got := shardedCollection(r)
	want := snapshot.ShardedCollection{NS: "app.system.buckets.ts", TimeField: "t", MetaField: "m",
		Key: []snapshot.IndexKey{{Field: "meta", Value: json.RawMessage("1")}, {Field: "control.min.t", Value: json.RawMessage("1")}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	u := shardedCollection(raw(t, bson.D{{Key: "_id", Value: "app.c"}, {Key: "key", Value: bson.D{{Key: "_id", Value: int32(1)}}}, {Key: "unsplittable", Value: true}}))
	if !u.Unsplittable || u.TimeField != "" {
		t.Errorf("unsplittable: %+v", u)
	}
}

func TestTCMallocInfo(t *testing.T) {
	if tcmallocInfo(nil) != nil {
		t.Error("nil section")
	}
	// gperftools (7.0 and earlier) has no usingPerCPUCaches.
	if got := tcmallocInfo(raw(t, bson.D{{Key: "generic", Value: bson.D{}}, {Key: "tcmalloc", Value: bson.D{{Key: "pageheap_free_bytes", Value: int64(1)}}}})); got != nil {
		t.Errorf("gperf: %+v", got)
	}
	got := tcmallocInfo(raw(t, bson.D{{Key: "usingPerCPUCaches", Value: true}, {Key: "maxPerCPUCacheSizeBytes", Value: int32(3 << 20)},
		{Key: "tcmalloc", Value: bson.D{{Key: "cpu_free", Value: int64(12345)}}}}))
	want := &snapshot.TCMallocInfo{UsingPerCPUCaches: true, MaxPerCPUCacheSizeBytes: 3 << 20, CPUFreeBytes: 12345}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestShardedCollectionsFilterSkipsUnsplittable(t *testing.T) {
	got := fmt.Sprint(shardedCollectionsFilter)
	for _, want := range []string{"config.system.sessions", "unsplittable", `"unsplittable":{"$ne":true}`} {
		if !strings.Contains(got, want) {
			t.Errorf("filter %s lacks %q", got, want)
		}
	}
}

func TestMergeClientsAcrossMembers(t *testing.T) {
	got := mergeClients(
		[]snapshot.ClientDriver{{DriverName: "nodejs", DriverVersion: "6.9.0", Connections: 4, AppNames: []string{"api"}, SeenOn: []string{"a:27017"}}},
		[]snapshot.ClientDriver{
			{DriverName: "nodejs", DriverVersion: "6.9.0", Connections: 2, AppNames: []string{"reports", "api"}, SeenOn: []string{"b:27017"}},
			{DriverName: "mongo-go-driver", DriverVersion: "2.10.0", Connections: 1, SeenOn: []string{"b:27017"}},
		},
	)
	want := []snapshot.ClientDriver{
		{DriverName: "mongo-go-driver", DriverVersion: "2.10.0", Connections: 1, SeenOn: []string{"b:27017"}},
		{DriverName: "nodejs", DriverVersion: "6.9.0", Connections: 6, AppNames: []string{"api", "reports"}, SeenOn: []string{"a:27017", "b:27017"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}
