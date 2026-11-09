package collect

import (
	"context"
	"sort"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/jenunes/ucfm/internal/snapshot"
)

const deepCheckSampleSize = 1000

// collectDeepCheck samples documents of every regular collection and records
// field paths holding the deprecated BSON undefined type. Documents are only
// walked in memory; nothing from them is stored except paths and counts.
func (c *Collector) collectDeepCheck(ctx context.Context) {
	dc := &snapshot.DeepCheckInfo{Ran: true}
	c.snap.DeepCheck = dc
	if len(c.snap.Data.Databases) == 0 {
		c.snap.AddError("deep-check", "listCollections", errNoNamespaces)
		return
	}
	budget := c.opts.MaxNamespaces
	for _, db := range c.snap.Data.Databases {
		for _, coll := range db.Collections {
			if coll.Type != "collection" {
				continue
			}
			if budget <= 0 {
				return
			}
			budget--
			ns := db.Name + "." + coll.Name
			c.opts.Log("deep-check: sampling %s", ns)
			counts, docs, err := c.sampleUndefined(ctx, db.Name, coll.Name)
			if err != nil {
				c.snap.AddError("deep-check:"+ns, "$sample", err)
				continue
			}
			dc.Collections++
			dc.Documents += docs
			for _, p := range sortedPaths(counts) {
				dc.Undefined = append(dc.Undefined, snapshot.UndefinedField{NS: ns, Path: p, Count: counts[p]})
			}
		}
	}
}

// sampleUndefined reads a random sample of documents. A secondary holds the
// same data, so on a replica set the sample spares the primary (dataReadPref).
func (c *Collector) sampleUndefined(ctx context.Context, db, coll string) (map[string]int, int, error) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, c.entry.Database(db), aggregateCmd(coll,
		bson.A{bson.D{{Key: "$sample", Value: bson.D{{Key: "size", Value: deepCheckSampleSize}}}}}), c.dataReadPref())
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = cur.Close(cctx) }()
	counts := map[string]int{}
	docs := 0
	for cur.Next(cctx) {
		docs++
		for p := range undefinedPaths(cur.Current) {
			counts[p]++
		}
	}
	return counts, docs, cur.Err()
}

// undefinedPaths returns the dotted paths (array positions as "$") whose value
// is BSON undefined, once per path.
func undefinedPaths(r bson.Raw) map[string]bool {
	out := map[string]bool{}
	var walk func(r bson.Raw, prefix string, isArray bool)
	walk = func(r bson.Raw, prefix string, isArray bool) {
		elems, err := r.Elements()
		if err != nil {
			return
		}
		for _, e := range elems {
			name := e.Key()
			if isArray {
				name = "$"
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			v := e.Value()
			switch v.Type {
			case bson.TypeUndefined:
				out[path] = true
			case bson.TypeEmbeddedDocument:
				walk(v.Document(), path, false)
			case bson.TypeArray:
				walk(bson.Raw(v.Array()), path, true)
			}
		}
	}
	walk(r, "", false)
	return out
}

func sortedPaths(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type collectErr string

func (e collectErr) Error() string { return string(e) }

const errNoNamespaces = collectErr("--deep-check needs the namespace listing; do not combine it with --skip-data")
