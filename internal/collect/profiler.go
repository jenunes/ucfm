package collect

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/jenunes/ucfm/internal/snapshot"
)

const (
	profilerMaxEntries  = 1000 // newest entries read per database and node
	profilerMaxExamples = 3
	profilerMaxExample  = 300 // characters per redacted example
)

// profilerOperators are the operators whose use the behavior checks need.
var profilerOperators = map[string]bool{
	"$add": true, "$dateAdd": true, "$dateSubtract": true,
	"$trim": true, "$ltrim": true, "$rtrim": true,
	"$function": true, "$accumulator": true, "$where": true,
}

// profilerSkipDBs never hold application queries worth scanning.
var profilerSkipDBs = map[string]bool{"admin": true, "local": true, "config": true}

// collectProfiler scans system.profile on the node behind cl. Only matched
// evidence is kept, as redacted query shapes.
func (c *Collector) collectProfiler(ctx context.Context, cl *mongo.Client, host, scope string) {
	res, err := c.run(ctx, cl, "admin", bson.D{{Key: "listDatabases", Value: 1}, {Key: "nameOnly", Value: true}})
	if err != nil {
		c.snap.AddError(scope, "listDatabases (profiler)", err)
		return
	}
	for _, d := range docArray(res, "databases") {
		db := str(d, "name")
		if profilerSkipDBs[db] {
			continue
		}
		exists, err := c.hasCollection(ctx, cl, db, "system.profile")
		if err != nil {
			c.snap.AddError(scope, "listCollections "+db+".system.profile", err)
			continue
		}
		if !exists {
			continue
		}
		if err := c.scanProfile(ctx, cl, host, db); err != nil {
			c.snap.AddError(scope, "find "+db+".system.profile", err)
		}
	}
}

func (c *Collector) hasCollection(ctx context.Context, cl *mongo.Client, db, coll string) (bool, error) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	names, err := cl.Database(db).ListCollectionNames(cctx, bson.D{{Key: "name", Value: coll}})
	return len(names) > 0, err
}

// scanProfile reads the newest entries of one member's profiler; the profiler
// is per node, so it reads the member cl points at.
func (c *Collector) scanProfile(ctx context.Context, cl *mongo.Client, host, db string) error {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, cl.Database(db), findCmd("system.profile", nil,
		bson.D{{Key: "op", Value: 1}, {Key: "ns", Value: 1}, {Key: "command", Value: 1}},
		bson.D{{Key: "ts", Value: -1}}, profilerMaxEntries), nodeReadPref())
	if err != nil {
		return err
	}
	defer func() { _ = cur.Close(cctx) }()
	p := c.profilerInfo()
	p.DatabasesProfiled = append(p.DatabasesProfiled, host+"/"+db)
	for cur.Next(cctx) {
		p.EntriesScanned++
		cmd := doc(cur.Current, "command")
		if cmd == nil {
			continue
		}
		ns, op := str(cur.Current, "ns"), str(cur.Current, "op")
		for _, key := range detectProfiler(cmd) {
			addEvidence(p, key, ns, op, cmd)
		}
	}
	return cur.Err()
}

func (c *Collector) profilerInfo() *snapshot.ProfilerInfo {
	if c.snap.Profiler == nil {
		c.snap.Profiler = &snapshot.ProfilerInfo{Evidence: map[string]*snapshot.ProfilerEvidence{}}
	}
	return c.snap.Profiler
}

func addEvidence(p *snapshot.ProfilerInfo, key, ns, op string, cmd bson.Raw) {
	ev := p.Evidence[key]
	if ev == nil {
		ev = &snapshot.ProfilerEvidence{}
		p.Evidence[key] = ev
	}
	ev.Count++
	if len(ev.Examples) >= profilerMaxExamples {
		return
	}
	ex := ns + " " + op + ": " + redactShape(cmd)
	if len(ex) > profilerMaxExample {
		ex = ex[:profilerMaxExample] + "…"
	}
	for _, e := range ev.Examples {
		if e == ex {
			return
		}
	}
	ev.Examples = append(ev.Examples, ex)
}

// detectProfiler returns the evidence keys found in one profiled command.
func detectProfiler(cmd bson.Raw) []string {
	found := map[string]bool{}
	walkElements(cmd, func(key string, v bson.RawValue) {
		if key == "$natural" && !isUnitDirection(v) {
			found[snapshot.EvidenceNatural] = true
		}
		if profilerOperators[key] {
			found[snapshot.EvidenceOpPrefix+key] = true
		}
	})
	for _, pred := range predicates(cmd) {
		if hasNullEquality(pred) {
			found[snapshot.EvidenceNullEq] = true
			break
		}
	}
	out := make([]string, 0, len(found))
	for k := range found {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isUnitDirection reports whether v is the number 1 or -1.
func isUnitDirection(v bson.RawValue) bool {
	if n, ok := v.AsInt64OK(); ok {
		return n == 1 || n == -1
	}
	if f, ok := v.DoubleOK(); ok {
		return f == 1 || f == -1
	}
	return false
}

// walkElements calls fn for every element of r, recursing into documents and
// arrays.
func walkElements(r bson.Raw, fn func(key string, v bson.RawValue)) {
	elems, err := r.Elements()
	if err != nil {
		return
	}
	for _, e := range elems {
		v := e.Value()
		fn(e.Key(), v)
		switch v.Type {
		case bson.TypeEmbeddedDocument:
			walkElements(v.Document(), fn)
		case bson.TypeArray:
			walkElements(bson.Raw(v.Array()), fn)
		}
	}
}

// predicates returns the query filters of a profiled command: find.filter,
// count.query, update/delete statements' q, findAndModify.query, distinct.query
// and every $match stage of a pipeline.
func predicates(cmd bson.Raw) []bson.Raw {
	var out []bson.Raw
	for _, k := range []string{"filter", "query", "q"} {
		if d := doc(cmd, k); d != nil {
			out = append(out, d)
		}
	}
	for _, list := range []string{"updates", "deletes"} {
		for _, st := range docArray(cmd, list) {
			if d := doc(st, "q"); d != nil {
				out = append(out, d)
			}
		}
	}
	for _, stage := range docArray(cmd, "pipeline") {
		if d := doc(stage, "$match"); d != nil {
			out = append(out, d)
		}
	}
	return out
}

// hasNullEquality reports {f: null}, {f: {$eq: null}} or {f: {$in: [.., null]}}
// anywhere in a predicate (including under $and/$or/$nor).
func hasNullEquality(pred bson.Raw) bool {
	elems, err := pred.Elements()
	if err != nil {
		return false
	}
	for _, e := range elems {
		k, v := e.Key(), e.Value()
		switch {
		case k == "$and" || k == "$or" || k == "$nor":
			for _, sub := range rawArrayDocs(v) {
				if hasNullEquality(sub) {
					return true
				}
			}
		case strings.HasPrefix(k, "$"):
			// other top-level operators ($expr, $where, $text...) are not field equality
		case v.Type == bson.TypeNull:
			return true
		case v.Type == bson.TypeEmbeddedDocument:
			ops := v.Document()
			if eq, err := ops.LookupErr("$eq"); err == nil && eq.Type == bson.TypeNull {
				return true
			}
			if in, err := ops.LookupErr("$in"); err == nil && in.Type == bson.TypeArray {
				if vals, err := in.Array().Values(); err == nil {
					for _, x := range vals {
						if x.Type == bson.TypeNull {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func rawArrayDocs(v bson.RawValue) []bson.Raw {
	arr, ok := v.ArrayOK()
	if !ok {
		return nil
	}
	vals, err := arr.Values()
	if err != nil {
		return nil
	}
	var out []bson.Raw
	for _, x := range vals {
		if d, ok := x.DocumentOK(); ok {
			out = append(out, d)
		}
	}
	return out
}

// redactedTopLevel are driver/session fields dropped from examples.
var redactedTopLevel = map[string]bool{
	"lsid": true, "$clusterTime": true, "$readPreference": true, "$audit": true,
	"$client": true, "signature": true, "txnNumber": true, "$db": true,
}

// redactShape renders a command as compact JSON with every scalar replaced by
// "?", except $natural directions and nulls, which are the evidence.
func redactShape(cmd bson.Raw) string {
	var b strings.Builder
	writeRedacted(&b, cmd, true, false)
	return b.String()
}

func writeRedacted(b *strings.Builder, r bson.Raw, top, isArray bool) {
	elems, err := r.Elements()
	if err != nil {
		b.WriteString(`"?"`)
		return
	}
	open, close := "{", "}"
	if isArray {
		open, close = "[", "]"
	}
	b.WriteString(open)
	first := true
	for _, e := range elems {
		if top && redactedTopLevel[e.Key()] {
			continue
		}
		if !first {
			b.WriteString(",")
		}
		first = false
		if !isArray {
			b.WriteString(strconv.Quote(e.Key()))
			b.WriteString(":")
		}
		writeRedactedValue(b, e.Key(), e.Value())
	}
	b.WriteString(close)
}

func writeRedactedValue(b *strings.Builder, key string, v bson.RawValue) {
	switch v.Type {
	case bson.TypeEmbeddedDocument:
		writeRedacted(b, v.Document(), false, false)
	case bson.TypeArray:
		writeRedacted(b, bson.Raw(v.Array()), false, true)
	case bson.TypeNull:
		b.WriteString("null")
	default:
		if key == "$natural" {
			if n, ok := v.AsInt64OK(); ok {
				b.WriteString(strconv.FormatInt(n, 10))
				return
			}
			if f, ok := v.DoubleOK(); ok {
				b.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
				return
			}
		}
		b.WriteString(`"?"`)
	}
}
