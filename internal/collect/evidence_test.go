package collect

import (
	"reflect"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/jenunes/ucfm/internal/snapshot"
)

func TestDetectProfiler(t *testing.T) {
	cases := []struct {
		name string
		cmd  bson.D
		want []string
	}{
		{"natural hint 2", bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.D{}}, {Key: "hint", Value: bson.D{{Key: "$natural", Value: int32(2)}}}}, []string{snapshot.EvidenceNatural}},
		{"natural sort -1 ok", bson.D{{Key: "find", Value: "c"}, {Key: "sort", Value: bson.D{{Key: "$natural", Value: int32(-1)}}}}, []string{}},
		{"null eq", bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.D{{Key: "x", Value: nil}}}}, []string{snapshot.EvidenceNullEq}},
		{"$eq null under $or", bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "a", Value: int32(1)}}, bson.D{{Key: "b", Value: bson.D{{Key: "$eq", Value: nil}}}}}}}}}, []string{snapshot.EvidenceNullEq}},
		{"$in with null in update q", bson.D{{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{
			bson.D{{Key: "q", Value: bson.D{{Key: "s", Value: bson.D{{Key: "$in", Value: bson.A{"x", nil}}}}}}, {Key: "u", Value: bson.D{{Key: "$set", Value: bson.D{{Key: "y", Value: nil}}}}}}}}}, []string{snapshot.EvidenceNullEq}},
		{"$set null is not a predicate", bson.D{{Key: "update", Value: "c"}, {Key: "updates", Value: bson.A{
			bson.D{{Key: "q", Value: bson.D{{Key: "_id", Value: int32(1)}}}, {Key: "u", Value: bson.D{{Key: "$set", Value: bson.D{{Key: "y", Value: nil}}}}}}}}}, []string{}},
		{"$add and $match null in pipeline", bson.D{{Key: "aggregate", Value: "c"}, {Key: "pipeline", Value: bson.A{
			bson.D{{Key: "$match", Value: bson.D{{Key: "k", Value: nil}}}},
			bson.D{{Key: "$project", Value: bson.D{{Key: "t", Value: bson.D{{Key: "$add", Value: bson.A{"$a", int32(1)}}}}}}}}}},
			[]string{snapshot.EvidenceNullEq, snapshot.EvidenceOpPrefix + "$add"}},
		{"$where", bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.D{{Key: "$where", Value: "this.a > 1"}}}}, []string{snapshot.EvidenceOpPrefix + "$where"}},
	}
	for _, c := range cases {
		raw, err := bson.Marshal(c.cmd)
		if err != nil {
			t.Fatal(err)
		}
		got := detectProfiler(raw)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRedactShapeKeepsOnlyEvidence(t *testing.T) {
	cmd, _ := bson.Marshal(bson.D{
		{Key: "find", Value: "customers"},
		{Key: "filter", Value: bson.D{{Key: "email", Value: "alice@example.com"}, {Key: "age", Value: int32(42)}, {Key: "deleted", Value: nil}}},
		{Key: "hint", Value: bson.D{{Key: "$natural", Value: int32(2)}}},
		{Key: "limit", Value: int64(7)},
		{Key: "lsid", Value: bson.D{{Key: "id", Value: "secret-session"}}},
		{Key: "$db", Value: "shop"},
	})
	got := redactShape(cmd)
	want := `{"find":"?","filter":{"email":"?","age":"?","deleted":null},"hint":{"$natural":2},"limit":"?"}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	for _, leak := range []string{"alice", "42", "customers", "secret-session", "shop", "7"} {
		if strings.Contains(got, leak) {
			t.Errorf("redacted shape leaks %q: %s", leak, got)
		}
	}
}

func TestUndefinedPaths(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "a", Value: bson.Undefined{}},
		{Key: "b", Value: bson.D{{Key: "c", Value: bson.Undefined{}}, {Key: "d", Value: int32(1)}}},
		{Key: "arr", Value: bson.A{int32(1), bson.Undefined{}, bson.D{{Key: "e", Value: bson.Undefined{}}}}},
		{Key: "n", Value: nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := undefinedPaths(doc)
	want := map[string]bool{"a": true, "b.c": true, "arr.$": true, "arr.$.e": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCounterMap(t *testing.T) {
	r, _ := bson.Marshal(bson.D{{Key: "$add", Value: int64(5)}, {Key: "$trim", Value: int64(0)}, {Key: "$x", Value: 2.0}, {Key: "skip", Value: "str"}})
	got := counterMap(r)
	want := map[string]int64{"$add": 5, "$trim": 0, "$x": 2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if counterMap(nil) != nil {
		t.Error("nil document should give nil map")
	}
}

func TestAddEvidenceCapsAndDedupes(t *testing.T) {
	p := &snapshot.ProfilerInfo{Evidence: map[string]*snapshot.ProfilerEvidence{}}
	cmd, _ := bson.Marshal(bson.D{{Key: "find", Value: "c"}, {Key: "filter", Value: bson.D{{Key: "x", Value: nil}}}})
	for i := 0; i < 5; i++ {
		addEvidence(p, snapshot.EvidenceNullEq, "db.c", "query", cmd)
	}
	ev := p.Evidence[snapshot.EvidenceNullEq]
	if ev.Count != 5 || len(ev.Examples) != 1 {
		t.Errorf("count %d examples %v", ev.Count, ev.Examples)
	}
}
