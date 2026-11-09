package collect

import (
	"net/url"
	"strings"
)

// ConnTemplate turns a connection string into a per-host template without
// secrets: the password becomes "****", the host list becomes "{host}", and
// options that only make sense for the whole deployment (replicaSet,
// directConnection, loadBalanced) are dropped. mongodb+srv:// becomes
// mongodb:// with tls=true, since SRV implies TLS. Returns "" when the
// string cannot be parsed.
func ConnTemplate(uri string) string {
	srv := strings.HasPrefix(uri, "mongodb+srv://")
	rest, ok := strings.CutPrefix(uri, "mongodb://")
	if srv {
		rest, ok = strings.CutPrefix(uri, "mongodb+srv://")
	}
	if !ok {
		return ""
	}
	user := ""
	if at := strings.LastIndex(strings.SplitN(rest, "/", 2)[0], "@"); at >= 0 {
		info := rest[:at]
		rest = rest[at+1:]
		name, _, hasPass := strings.Cut(info, ":")
		user = name
		if hasPass {
			user += ":****"
		}
		user += "@"
	}
	path, query := "/", ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		tail := rest[i:]
		if q := strings.Index(tail, "?"); q >= 0 {
			path, query = tail[:q], tail[q+1:]
		} else {
			path = tail
		}
		if path == "" {
			path = "/"
		}
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	for _, k := range []string{"replicaSet", "directConnection", "loadBalanced"} {
		vals.Del(k)
	}
	if srv && vals.Get("tls") == "" && vals.Get("ssl") == "" {
		vals.Set("tls", "true")
	}
	out := "mongodb://" + user + "{host}" + path
	if enc := encodeKeepingSlashes(vals); enc != "" {
		out += "?" + enc
	}
	return out
}

// encodeKeepingSlashes encodes query values but keeps '/' readable so file
// paths (tlsCAFile=/etc/ssl/ca.pem) stay copy-pasteable.
func encodeKeepingSlashes(v url.Values) string {
	return strings.ReplaceAll(v.Encode(), "%2F", "/")
}
