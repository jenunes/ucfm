package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Getting started": "getting-started",
		"2. Plan":         "2-plan",
		"Why does a 6.0 → 9.0 check only cover?": "why-does-a-60--90-check-only-cover",
		"`--local` and **host** checks":          "--local-and-host-checks",
		"[Link text](x.md) here":                 "link-text-here",
		"snake_case_name":                        "snake_case_name",
	} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnchorsRepeatsAndIDs(t *testing.T) {
	a := Anchors("# Title\n## Notes\n## Notes\n<a id=\"Custom\"></a>\n```\n## Not a heading\n```\n")
	for _, want := range []string{"title", "notes", "notes-1", "custom"} {
		if !a[want] {
			t.Errorf("missing anchor %q in %v", want, a)
		}
	}
	if a["not-a-heading"] {
		t.Error("headings inside code fences are not anchors")
	}
}

func TestLinksSkipCode(t *testing.T) {
	md := "See [a](a.md#x) and `[b](b.md)`.\n```\n[c](c.md)\n```\n<img src=\"logo.png\"> ![d](d.png \"title\")\n"
	var got []string
	for _, l := range Links(md) {
		got = append(got, l.Target)
	}
	if want := []string{"a.md#x", "d.png", "logo.png"}; !reflect.DeepEqual(got, want) {
		t.Errorf("links %v, want %v", got, want)
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("docs/guide.md", "# Guide\n## Install it\n")
	write("logo.png", "x")
	readme := write("README.md", strings.Join([]string{
		"[ok](docs/guide.md#install-it)",
		"[self](#readme)",
		"# Readme",
		"[web](https://example.com/missing)",
		"![logo](logo.png)",
		"[missing file](docs/nope.md)",
		"[missing anchor](docs/guide.md#nope)",
	}, "\n"))
	got := Check([]string{readme})
	if len(got) != 2 || !strings.Contains(got[0], "docs/nope.md: file not found") || !strings.Contains(got[1], `no heading or id "nope"`) {
		t.Errorf("problems:\n%s", strings.Join(got, "\n"))
	}
}
