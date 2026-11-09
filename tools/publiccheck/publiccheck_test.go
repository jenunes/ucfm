package main

import (
	"strings"
	"testing"
)

// Inputs are split so that this file passes the check it tests.
const (
	at   = "@"
	home = "/ho" + "me/"
)

func TestForbiddenPath(t *testing.T) {
	for p, want := range map[string]bool{
		"tools/lab/envs/6.0.yaml":      true,
		"tools/labtest/main.go":        true,
		"testdata/lab/scenarios.yaml":  true,
		"docs/integration-lab.md":      true,
		"AGENTS.md":                    true,
		".beads/issues.jsonl":          true,
		"tools/linkcheck/main.go":      false,
		"testdata/snapshots/rs80.json": false,
		"docs/README.md":               false,
	} {
		if got := ForbiddenPath(p); got != want {
			t.Errorf("ForbiddenPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestContentProblems(t *testing.T) {
	text := strings.Join([]string{
		"cd " + home + "alice/src",
		"mail bob" + at + "gmail.com",
		"ok alice" + at + "example.com, p" + at + "cluster.example, 1+me" + at + "users.noreply.github.com",
		"mongodb://ucfm" + at + "db1:27017/?authSource=admin",
	}, "\n")
	got := ContentProblems("f.md", []byte(text))
	if len(got) != 2 || !strings.Contains(got[0], "f.md:1: personal path") || !strings.Contains(got[1], "f.md:2: e-mail") {
		t.Errorf("problems = %q", got)
	}
	if p := ContentProblems("logo.jpg", []byte("x\x00"+home+"alice")); p != nil {
		t.Errorf("binary files are skipped, got %q", p)
	}
}

func TestSnapshotProblems(t *testing.T) {
	doc := `{"members": [{"hostname": "laptop:28100", "saslHostName": "db1"},
		{"host": "sh1/db1:28201,172.18.0.3:27017", "me": "node0:27017", "primary": "10.0.0.5:27017"},
		{"hosts": ["mongos1.example:27017", "laptop:28101"]}]}`
	got := SnapshotProblems("testdata/snapshots/x.json", []byte(doc))
	if len(got) != 1 || !strings.Contains(got[0], `"laptop"`) {
		t.Errorf("problems = %q", got)
	}
	if !IsSnapshot("testdata/snapshots/x.json") || !IsSnapshot("tools/linkcheck/testdata/a.json") || IsSnapshot("internal/catalog/data/community-8.0.json") {
		t.Error("IsSnapshot")
	}
}

func TestCommitProblems(t *testing.T) {
	ok := "1+me" + at + "users.noreply.github.com"
	log := "aaaaaaaa1\x00" + ok + "\x00noreply" + at + "github.com\x00Fix a rule\n\x1e\n" +
		"bbbbbbbb2\x00me" + at + "mail.test\x00" + ok + "\x00Add a check\n\nCo-Authored-By: someone\n\x1e\n"
	got := CommitProblems(log)
	if len(got) != 2 || !strings.Contains(got[0], "commit bbbbbbb: author") || !strings.Contains(got[1], "tool attribution") {
		t.Errorf("problems = %q", got)
	}
}
