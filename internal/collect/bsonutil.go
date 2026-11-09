package collect

import (
	"encoding/json"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// relaxedJSON converts any BSON value to relaxed extended JSON.
func relaxedJSON(v bson.RawValue) json.RawMessage {
	doc := bson.D{{Key: "v", Value: v}}
	b, err := bson.MarshalExtJSON(doc, false, false)
	if err != nil {
		return json.RawMessage(`null`)
	}
	var wrap struct {
		V json.RawMessage `json:"v"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return json.RawMessage(`null`)
	}
	return wrap.V
}

// docJSON converts a whole BSON document to relaxed extended JSON.
func docJSON(r bson.Raw) json.RawMessage {
	if len(r) == 0 {
		return nil
	}
	b, err := bson.MarshalExtJSON(r, false, false)
	if err != nil {
		return nil
	}
	return b
}

func str(r bson.Raw, path ...string) string {
	if v, err := r.LookupErr(path...); err == nil {
		if s, ok := v.StringValueOK(); ok {
			return s
		}
	}
	return ""
}

func num(r bson.Raw, path ...string) int64 {
	if v, err := r.LookupErr(path...); err == nil {
		if n, ok := v.AsInt64OK(); ok {
			return n
		}
		if f, ok := v.DoubleOK(); ok {
			return int64(f)
		}
	}
	return 0
}

func flt(r bson.Raw, path ...string) float64 {
	if v, err := r.LookupErr(path...); err == nil {
		if f, ok := v.DoubleOK(); ok {
			return f
		}
		if n, ok := v.AsInt64OK(); ok {
			return float64(n)
		}
	}
	return 0
}

func boolean(r bson.Raw, path ...string) bool {
	if v, err := r.LookupErr(path...); err == nil {
		if b, ok := v.BooleanOK(); ok {
			return b
		}
	}
	return false
}

func timeVal(r bson.Raw, path ...string) time.Time {
	if v, err := r.LookupErr(path...); err == nil {
		if t, ok := v.TimeOK(); ok {
			return t.UTC()
		}
	}
	return time.Time{}
}

func doc(r bson.Raw, path ...string) bson.Raw {
	if v, err := r.LookupErr(path...); err == nil {
		if d, ok := v.DocumentOK(); ok {
			return d
		}
	}
	return nil
}

func strArray(r bson.Raw, path ...string) []string {
	v, err := r.LookupErr(path...)
	if err != nil {
		return nil
	}
	arr, ok := v.ArrayOK()
	if !ok {
		return nil
	}
	vals, err := arr.Values()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(vals))
	for _, e := range vals {
		if s, ok := e.StringValueOK(); ok {
			out = append(out, s)
		}
	}
	return out
}

func docArray(r bson.Raw, path ...string) []bson.Raw {
	v, err := r.LookupErr(path...)
	if err != nil {
		return nil
	}
	arr, ok := v.ArrayOK()
	if !ok {
		return nil
	}
	vals, err := arr.Values()
	if err != nil {
		return nil
	}
	out := make([]bson.Raw, 0, len(vals))
	for _, e := range vals {
		if d, ok := e.DocumentOK(); ok {
			out = append(out, d)
		}
	}
	return out
}

// flatten turns nested sub-documents into dotted keys. Arrays and scalars are
// leaves. Keys listed in stop are not descended into and are returned whole.
func flatten(r bson.Raw, prefix string, out map[string]json.RawMessage, stop map[string]bool) {
	elems, err := r.Elements()
	if err != nil {
		return
	}
	for _, e := range elems {
		key := e.Key()
		if prefix != "" {
			key = prefix + "." + key
		}
		v := e.Value()
		if d, ok := v.DocumentOK(); ok && !stop[key] {
			flatten(d, key, out, stop)
			continue
		}
		out[key] = relaxedJSON(v)
	}
}

// hostsFromShardString parses "rs0/h1:27017,h2:27017" (or a bare host list).
func hostsFromShardString(s string) (setName string, hosts []string) {
	if name, rest, ok := strings.Cut(s, "/"); ok {
		setName, s = name, rest
	}
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return setName, hosts
}
