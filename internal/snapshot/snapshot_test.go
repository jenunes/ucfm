package snapshot

import (
	"path/filepath"
	"testing"
)

func TestMajorMinor(t *testing.T) {
	cases := map[string]string{
		"8.0.12":    "8.0",
		"8.0.12-4":  "8.0",
		"7.0.29":    "7.0",
		"r9.0.4":    "9.0",
		"8.3.0-rc1": "8.3",
		"garbage":   "",
		"":          "",
	}
	for in, want := range cases {
		if got := MajorMinor(in); got != want {
			t.Errorf("MajorMinor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"8.0", "8.3", -1},
		{"9.0", "8.3", 1},
		{"7.0.9", "7.0.29", -1},
		{"8.0.12-4", "8.0.12", 0},
		{"6.0", "6.0.0", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSourceVersionAndFlavor(t *testing.T) {
	s := &Snapshot{Nodes: []Node{
		{Host: "a", Version: "8.0.12-4", Flavor: "psmdb"},
		{Host: "b", Version: "7.0.29", Flavor: "community"},
	}}
	if got := s.SourceVersion(); got != "7.0" {
		t.Errorf("SourceVersion = %q, want 7.0", got)
	}
	if got := s.Flavor(); got != "psmdb" {
		t.Errorf("Flavor = %q, want psmdb", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	s := &Snapshot{SchemaVersion: SchemaVersion, EntryHost: "h:27017", Topology: Topology{Kind: KindReplicaSet}}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.EntryHost != "h:27017" || got.Topology.Kind != KindReplicaSet {
		t.Errorf("round trip mismatch: %+v", got)
	}

	s.SchemaVersion = 99
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("expected schema version error")
	}
}
