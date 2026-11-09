package rules

import (
	"regexp"
	"strings"
	"testing"
)

var (
	majorRe  = regexp.MustCompile(`^[0-9]+$`)
	ubuntuRe = regexp.MustCompile(`^[0-9]{2}\.(04|10)$`)
)

func TestPlatformDataWellFormed(t *testing.T) {
	for flavor, releases := range supportedOS {
		if flavor != "community" && flavor != "psmdb" {
			t.Errorf("unknown flavor %q", flavor)
		}
		for rel, entries := range releases {
			if len(entries) == 0 {
				t.Errorf("%s %s: empty list", flavor, rel)
			}
			src := supportedOSSources[flavor][rel]
			if !strings.HasPrefix(src, "https://") {
				t.Errorf("%s %s: missing source URL", flavor, rel)
			}
			seen := map[string]bool{}
			for _, e := range entries {
				key := e.Family + " " + e.Version
				if seen[key] {
					t.Errorf("%s %s: duplicate %s", flavor, rel, key)
				}
				seen[key] = true
				switch e.Family {
				case "rhel", "debian":
					if !majorRe.MatchString(e.Version) {
						t.Errorf("%s %s: %s version %q is not a major version", flavor, rel, e.Family, e.Version)
					}
				case "ubuntu":
					if !ubuntuRe.MatchString(e.Version) {
						t.Errorf("%s %s: ubuntu version %q is not YY.MM", flavor, rel, e.Version)
					}
				default:
					t.Errorf("%s %s: unknown family %q", flavor, rel, e.Family)
				}
				if len(e.Arches) == 0 {
					t.Errorf("%s %s: %s has no architectures", flavor, rel, key)
				}
				for _, a := range e.Arches {
					if a != "x86_64" && a != "arm64" {
						t.Errorf("%s %s: %s has unknown arch %q", flavor, rel, key, a)
					}
				}
			}
		}
	}
	for flavor, srcs := range supportedOSSources {
		for rel := range srcs {
			if _, ok := supportedOS[flavor][rel]; !ok {
				t.Errorf("source without data: %s %s", flavor, rel)
			}
		}
	}
}

func TestPlatformCoverage(t *testing.T) {
	for _, rel := range []string{"6.0", "7.0", "8.0", "8.3", "9.0"} {
		if _, ok := supportedOS["community"][rel]; !ok {
			t.Errorf("community %s missing", rel)
		}
	}
	for _, rel := range []string{"7.0", "8.0", "8.3"} {
		if _, ok := supportedOS["psmdb"][rel]; !ok {
			t.Errorf("psmdb %s missing", rel)
		}
	}
	if _, ok := supportedOS["psmdb"]["6.0"]; ok {
		t.Error("psmdb 6.0 is not published and must stay absent")
	}
}
