package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeInfo struct{ mode fs.FileMode }

func (f fakeInfo) Name() string       { return "uri" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }

func src(env map[string]string, file string, mode fs.FileMode, pw *string) (uriSource, *bytes.Buffer) {
	var warn bytes.Buffer
	s := uriSource{
		getenv:   func(k string) string { return env[k] },
		readFile: func(string) ([]byte, error) { return []byte(file), nil },
		stat:     func(string) (os.FileInfo, error) { return fakeInfo{mode}, nil },
		warn:     &warn,
	}
	if pw != nil {
		s.prompt = func(string) (string, error) { return *pw, nil }
	}
	return s, &warn
}

func TestURIPrecedenceAndSources(t *testing.T) {
	env := map[string]string{envURI: "mongodb://env:e@h/"}
	c := connFlags{uri: "mongodb://flag:f@h/"}
	s, _ := src(env, "mongodb://file:x@h/\n", 0o600, nil)
	if err := c.resolveURI(s); err != nil || c.uri != "mongodb://flag:f@h/" {
		t.Fatalf("--uri wins: %q %v", c.uri, err)
	}
	c = connFlags{uriFile: "/secret"}
	if err := c.resolveURI(s); err != nil || c.uri != "mongodb://file:x@h/" {
		t.Fatalf("--uri-file next: %q %v", c.uri, err)
	}
	c = connFlags{}
	if err := c.resolveURI(s); err != nil || c.uri != "mongodb://env:e@h/" {
		t.Fatalf("UCFM_URI last: %q %v", c.uri, err)
	}
	c = connFlags{uri: "x", uriFile: "y"}
	if err := c.resolveURI(s); err == nil {
		t.Fatal("--uri with --uri-file must fail")
	}
}

func TestURIFileCommentsAndPermissions(t *testing.T) {
	s, warn := src(nil, "# lab\n\n  mongodb://u:p@h/  \n", 0o644, nil)
	c := connFlags{uriFile: "/tmp/uri"}
	if err := c.resolveURI(s); err != nil || c.uri != "mongodb://u:p@h/" {
		t.Fatalf("got %q %v", c.uri, err)
	}
	if !strings.Contains(warn.String(), "chmod 600 /tmp/uri") {
		t.Errorf("readable file must warn, got %q", warn.String())
	}
	s, warn = src(nil, "mongodb://u:p@h/", 0o600, nil)
	c = connFlags{uriFile: "/tmp/uri"}
	_ = c.resolveURI(s)
	if warn.Len() != 0 {
		t.Errorf("a 0600 file must not warn: %q", warn.String())
	}
	s, _ = src(nil, "# only a comment\n", 0o600, nil)
	c = connFlags{uriFile: "/tmp/uri"}
	if err := c.resolveURI(s); err == nil {
		t.Error("an empty file must fail")
	}
}

func TestPasswordPrompt(t *testing.T) {
	pw := "p@ss:w/rd é"
	s, _ := src(nil, "", 0, &pw)
	c := connFlags{uri: "mongodb://ucfm@db1:27017,db2:27017/?authSource=admin&replicaSet=rs0"}
	if err := c.resolveURI(s); err != nil {
		t.Fatal(err)
	}
	if want := "mongodb://ucfm:p%40ss%3Aw%2Frd%20%C3%A9@db1:27017,db2:27017/?authSource=admin&replicaSet=rs0"; c.uri != want {
		t.Fatalf("got  %s\nwant %s", c.uri, want)
	}
	// No terminal: a clear error instead of a hang.
	s, _ = src(nil, "", 0, nil)
	c = connFlags{uri: "mongodb://ucfm@db1/"}
	if err := c.resolveURI(s); err == nil || !strings.Contains(err.Error(), envURI) {
		t.Fatalf("got %v", err)
	}
	// Passwordless mechanisms and URIs without a user never prompt.
	called := false
	s.prompt = func(string) (string, error) { called = true; return "", errors.New("no") }
	for _, u := range []string{
		"mongodb://CN=client@db1/?authMechanism=MONGODB-X509&tls=true",
		"mongodb+srv://cluster.example.net/?tls=true",
		"mongodb://u:p@db1/",
		"mongodb://db1/?replicaSet=rs0",
	} {
		c = connFlags{uri: u}
		if err := c.resolveURI(s); err != nil || c.uri != u || called {
			t.Errorf("%s: got %q %v prompted=%v", u, c.uri, err, called)
		}
	}
}
