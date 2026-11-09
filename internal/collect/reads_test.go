package collect

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/jenunes/ucfm/internal/snapshot"
)

func TestCommandBuildersLeaveMaxTimeMSToTheDriver(t *testing.T) {
	// The driver adds maxTimeMS from the context deadline; a second one in
	// the command would be rejected by the server.
	for _, cmd := range []bson.D{
		findCmd("system.profile", nil, bson.D{{Key: "op", Value: 1}}, bson.D{{Key: "ts", Value: -1}}, 100),
		aggregateCmd("", bson.A{bson.D{{Key: "$currentOp", Value: bson.D{}}}}),
		aggregateCmd("coll", bson.A{bson.D{{Key: "$sample", Value: bson.D{{Key: "size", Value: 10}}}}}),
	} {
		for _, e := range cmd {
			if e.Key == "maxTimeMS" {
				t.Errorf("%v carries its own maxTimeMS", cmd)
			}
		}
	}
	if got := findCmd("c", nil, nil, nil, 0); len(got) != 2 {
		t.Errorf("empty projection, sort and limit must be left out: %v", got)
	}
	if got := aggregateCmd("", nil); got[0].Value != 1 {
		t.Errorf("database-level aggregate must use aggregate: 1, got %v", got[0].Value)
	}
}

func TestDataReadPreference(t *testing.T) {
	cases := []struct {
		kind      string
		entryOnly bool
		want      readpref.Mode
	}{
		{snapshot.KindReplicaSet, false, readpref.SecondaryPreferredMode},
		{snapshot.KindReplicaSet, true, readpref.PrimaryPreferredMode},
		{snapshot.KindSharded, false, readpref.PrimaryPreferredMode},
		{snapshot.KindStandalone, false, readpref.PrimaryPreferredMode},
	}
	for _, c := range cases {
		rp := dataReadPrefFor(c.kind, c.entryOnly)
		if rp.Mode() != c.want {
			t.Errorf("%s entryOnly=%v: %v, want %v", c.kind, c.entryOnly, rp.Mode(), c.want)
		}
		if c.want == readpref.SecondaryPreferredMode {
			if ms, ok := rp.MaxStaleness(); !ok || ms != maxStaleness {
				t.Errorf("secondary reads must exclude delayed members (maxStaleness %v)", ms)
			}
		}
	}
}

// TestLiveCommandsCarryMaxTimeMS collects from a real deployment and checks
// that every potentially long command reached the server with maxTimeMS.
// Set UCFM_TEST_URI (for example a lab member) to run it.
func TestLiveCommandsCarryMaxTimeMS(t *testing.T) {
	uri := os.Getenv("UCFM_TEST_URI")
	if uri == "" {
		t.Skip("set UCFM_TEST_URI to run against a live deployment")
	}
	var mu sync.Mutex
	missing := map[string]bool{}
	seen := map[string]bool{}
	long := map[string]bool{"find": true, "aggregate": true, "listCollections": true, "listIndexes": true,
		"listDatabases": true, "usersInfo": true, "rolesInfo": true, "count": true, "collStats": true}
	testMonitor = &event.CommandMonitor{Started: func(_ context.Context, e *event.CommandStartedEvent) {
		if !long[e.CommandName] {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		seen[e.CommandName] = true
		if _, err := e.Command.LookupErr("maxTimeMS"); err != nil {
			missing[e.CommandName] = true
		}
	}}
	defer func() { testMonitor = nil }()
	_, err := Run(context.Background(), Options{URI: uri, CommandTimeout: 30 * time.Second, MaxNamespaces: 1000, DeepCheck: true, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for n := range seen {
		names = append(names, n)
	}
	t.Logf("long commands seen: %s", strings.Join(names, ", "))
	for n := range missing {
		t.Errorf("%s reached the server without maxTimeMS", n)
	}
}
