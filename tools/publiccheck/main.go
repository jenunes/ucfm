// Command publiccheck fails when the repository would publish something that
// must stay private: local-only files (lab, agent and tracker files), personal
// paths or e-mail addresses, real host names in test snapshots, and commits
// that are not authored with a GitHub noreply address or that carry tool
// attribution.
//
//	go run ./tools/publiccheck              # tracked files
//	go run ./tools/publiccheck -commits HEAD # also every commit reachable from HEAD
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	commits := flag.String("commits", "", "also check the author, committer and message of every commit in this revision range")
	flag.Parse()

	out, err := exec.Command("git", "ls-files", "-z").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "publiccheck: git ls-files:", err)
		os.Exit(2)
	}
	files := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	var problems []string
	for _, f := range files {
		if f == "" {
			continue
		}
		if ForbiddenPath(f) {
			problems = append(problems, f+": local-only file is tracked")
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			continue // deleted in the work tree
		}
		problems = append(problems, ContentProblems(f, data)...)
		if IsSnapshot(f) {
			problems = append(problems, SnapshotProblems(f, data)...)
		}
	}
	if *commits != "" {
		log, err := exec.Command("git", "log", "--format=%H%x00%ae%x00%ce%x00%B%x1e", *commits).Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, "publiccheck: git log:", err)
			os.Exit(2)
		}
		problems = append(problems, CommitProblems(string(log))...)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "publiccheck: %d problem(s)\n", len(problems))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "publiccheck: %d file(s), nothing private\n", len(files))
}

// Paths that exist only on the maintainer's machine.
var forbiddenPrefixes = []string{
	"tools/lab/", "tools/labtest/", "tools/devlab/", "testdata/lab/",
	".beads/", ".cursor/", ".claude/", ".agents/", ".codex/",
}

var forbiddenFiles = map[string]bool{
	"AGENTS.md": true, "CLAUDE.md": true, "CLAUDE.local.md": true,
	"docs/integration-lab.md": true,
}

// ForbiddenPath reports whether a tracked path must stay local.
func ForbiddenPath(p string) bool {
	if forbiddenFiles[p] {
		return true
	}
	for _, pre := range forbiddenPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

var (
	homePath = regexp.MustCompile(`/(home|Users)/[A-Za-z0-9._-]+`)
	email    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}`)
)

// ContentProblems finds personal paths and e-mail addresses in a text file.
func ContentProblems(path string, data []byte) []string {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	var out []string
	for i, line := range strings.Split(string(data), "\n") {
		if m := homePath.FindString(line); m != "" {
			out = append(out, fmt.Sprintf("%s:%d: personal path %q", path, i+1, m))
		}
		for _, m := range email.FindAllString(line, -1) {
			if !allowedEmail(m) {
				out = append(out, fmt.Sprintf("%s:%d: e-mail address %q", path, i+1, m))
			}
		}
	}
	return out
}

// allowedEmail accepts GitHub noreply addresses and the reserved example
// domains (RFC 2606).
func allowedEmail(addr string) bool {
	domain := strings.ToLower(addr[strings.LastIndex(addr, "@")+1:])
	if domain == "users.noreply.github.com" || addr == "noreply@github.com" {
		return true
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "example" {
			return true
		}
	}
	return false
}

// IsSnapshot reports whether a file holds collected deployment data.
func IsSnapshot(p string) bool {
	return filepath.Ext(p) == ".json" && strings.Contains(p, "testdata/") && !strings.HasPrefix(p, "internal/catalog/")
}

var neutralHost = regexp.MustCompile(`^(localhost|(db|node|cfg|mongos|shard|sh|rs|s)\d*|` +
	`(127|10)\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|` +
	`[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.example(\.[a-z]+)?)$`)

var hostKeys = map[string]bool{"hostname": true, "saslHostName": true, "host": true, "me": true, "primary": true}
var hostListKeys = map[string]bool{"hosts": true, "passives": true, "arbiters": true}

// SnapshotProblems finds host names in a snapshot that are not neutral test
// names, private addresses or reserved example domains.
func SnapshotProblems(path string, data []byte) []string {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	check := func(v string) {
		for _, h := range hostNames(v) {
			if !neutralHost.MatchString(h) && !seen[h] {
				seen[h] = true
				out = append(out, fmt.Sprintf("%s: host name %q is not a neutral test name (use db1, cfg1, mongos1, ...)", path, h))
			}
		}
	}
	var walk func(any)
	walk = func(o any) {
		switch t := o.(type) {
		case map[string]any:
			for k, v := range t {
				if s, ok := v.(string); ok && hostKeys[k] {
					check(s)
				}
				if l, ok := v.([]any); ok && hostListKeys[k] {
					for _, x := range l {
						if s, ok := x.(string); ok {
							check(s)
						}
					}
				}
				walk(v)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(doc)
	return out
}

var port = regexp.MustCompile(`:\d+$`)

// hostNames splits "rs0/db1:27017,db2:27017" into its host names.
func hostNames(v string) []string {
	if i := strings.Index(v, "/"); i >= 0 {
		v = v[i+1:]
	}
	var out []string
	for _, h := range strings.Split(v, ",") {
		if h = port.ReplaceAllString(strings.TrimSpace(h), ""); h != "" {
			out = append(out, h)
		}
	}
	return out
}

var attribution = regexp.MustCompile(`(?i)co-authored-by:|generated with`)

// CommitProblems checks records of "hash NUL author-email NUL committer-email
// NUL message RS".
func CommitProblems(log string) []string {
	var out []string
	for _, rec := range strings.Split(log, "\x1e") {
		f := strings.SplitN(strings.TrimLeft(rec, "\n"), "\x00", 4)
		if len(f) < 4 {
			continue
		}
		short := f[0]
		if len(short) > 7 {
			short = short[:7]
		}
		for _, e := range []struct{ who, addr string }{{"author", f[1]}, {"committer", f[2]}} {
			if !strings.HasSuffix(e.addr, "@users.noreply.github.com") && e.addr != "noreply@github.com" {
				out = append(out, fmt.Sprintf("commit %s: %s e-mail %q is not a GitHub noreply address", short, e.who, e.addr))
			}
		}
		if attribution.MatchString(f[3]) {
			out = append(out, fmt.Sprintf("commit %s: message carries tool attribution", short))
		}
	}
	return out
}
