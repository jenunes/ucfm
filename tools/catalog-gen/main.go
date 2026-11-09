// Command catalog-gen builds the per-version catalogs embedded in ucfm.
//
// For every requested release series it picks the newest GA tag of the
// upstream repository (MongoDB Community: mongodb/mongo; PSMDB:
// percona/percona-server-mongodb), does a blobless sparse checkout of the IDL,
// releases.yml and C++ sources, and extracts startup options, server
// parameters, commands, auth action types, aggregation stages/expressions and
// FCV compatibility into internal/catalog/data/<flavor>-<series>.json.
//
// Usage:
//
//	go run ./tools/catalog-gen -out internal/catalog/data
//	go run ./tools/catalog-gen -report internal/catalog/data
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jenunes/ucfm/internal/catalog"
)

var repos = map[string]string{
	catalog.FlavorCommunity: "https://github.com/mongodb/mongo",
	catalog.FlavorPSMDB:     "https://github.com/percona/percona-server-mongodb",
}

var (
	// r8.0.19, r8.3.0-rc2, r9.0.0-alpha1
	reCommunityTag = regexp.MustCompile(`^r(\d+\.\d+)\.(\d+)(-(rc|alpha|beta)(\d+))?$`)
	// psmdb-8.0.12-4, psmdb-8.3.0-rc1
	rePSMDBTag = regexp.MustCompile(`^psmdb-(\d+\.\d+)\.(\d+)(?:-(rc|alpha|beta)?(\d+))?$`)
)

// sparse-checkout patterns (non-cone, gitignore syntax).
var sparsePatterns = []string{
	"/src/**/*.idl",
	"/src/mongo/util/version/releases.yml",
	"/src/mongo/**/*.cpp",
	"/src/mongo/**/*.h",
	"!/src/third_party/**",
	"!/src/mongo/**/*_test.cpp",
	"!/src/mongo/**/*_test.h",
	"!/src/mongo/**/*_test_*.cpp",
	"!/src/mongo/**/*_bm.cpp",
	"!/src/mongo/dbtests/**",
	"!/src/mongo/unittest/**",
}

func main() {
	out := flag.String("out", "internal/catalog/data", "output directory for catalog JSON files")
	versions := flag.String("versions", "6.0,7.0,8.0,8.3,9.0", "comma-separated release series")
	flavors := flag.String("flavors", "community,psmdb", "comma-separated flavors")
	workdir := flag.String("workdir", filepath.Join(os.TempDir(), "ucfm-catalog-src"), "directory for source checkouts (reused between runs)")
	tagsFlag := flag.String("tags", "", "explicit tags, e.g. community:8.0=r8.0.19,psmdb:8.0=psmdb-8.0.34-15 (overrides discovery)")
	clean := flag.Bool("clean", false, "delete each checkout after parsing")
	report := flag.String("report", "", "print stats and per-hop diffs for catalogs in this directory, then exit")
	flag.Parse()

	if *report != "" {
		if err := printReport(*report); err != nil {
			log.Fatal(err)
		}
		return
	}

	explicit := map[string]string{}
	for _, kv := range splitList(*tagsFlag) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			log.Fatalf("bad -tags entry %q", kv)
		}
		explicit[k] = v
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	for _, flavor := range splitList(*flavors) {
		repo, ok := repos[flavor]
		if !ok {
			log.Fatalf("unknown flavor %q", flavor)
		}
		var tags []string
		if len(explicit) == 0 {
			var err error
			if tags, err = listTags(repo); err != nil {
				log.Fatal(err)
			}
		}
		for _, series := range splitList(*versions) {
			tag, provisional := explicit[flavor+":"+series], false
			if tag == "" {
				tag, provisional = pickTag(flavor, series, tags)
			}
			if tag == "" {
				log.Printf("%s %s: no tag found, skipping", flavor, series)
				continue
			}
			dir := filepath.Join(*workdir, tag)
			if err := fetch(repo, tag, dir); err != nil {
				log.Fatalf("%s: %v", tag, err)
			}
			c, st, err := Parse(dir, flavor, series, tag)
			if err != nil {
				log.Fatalf("%s: %v", tag, err)
			}
			c.Provisional = provisional
			log.Printf("%s %s (%s, provisional=%v): %d IDL files (%d failed), %d C++ files; options=%d params=%d commands=%d actions=%d stages=%d exprs=%d fcv=%+v",
				flavor, series, tag, provisional, st.IDLFiles, len(st.IDLFailures), st.CppFiles,
				len(c.StartupOptions), len(c.ServerParameters), len(c.Commands), len(c.ActionTypes),
				len(c.AggStages), len(c.AggExpressions), c.FCV)
			for _, f := range st.IDLFailures {
				log.Printf("  IDL parse failure: %s", f)
			}
			if !st.ReleasesYAML {
				log.Fatalf("%s: releases.yml missing", tag)
			}
			if err := writeCatalog(filepath.Join(*out, catalog.FileName(flavor, series)), c); err != nil {
				log.Fatal(err)
			}
			if *clean {
				_ = os.RemoveAll(dir)
			}
		}
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, stderr.String())
	}
	return nil
}

func listTags(repo string) ([]string, error) {
	out, err := exec.Command("git", "ls-remote", "--tags", "--refs", repo).Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote %s: %w", repo, err)
	}
	var tags []string
	for _, line := range strings.Split(string(out), "\n") {
		if _, ref, ok := strings.Cut(line, "\t"); ok {
			tags = append(tags, strings.TrimPrefix(ref, "refs/tags/"))
		}
	}
	return tags, nil
}

type tagVer struct {
	tag        string
	patch      int
	prerelease bool
	pre        int
	build      int
}

// pickTag returns the newest GA tag for the series, or the newest pre-release
// (provisional) when no GA tag exists.
func pickTag(flavor, series string, tags []string) (string, bool) {
	var cands []tagVer
	for _, t := range tags {
		var tv tagVer
		switch flavor {
		case catalog.FlavorCommunity:
			m := reCommunityTag.FindStringSubmatch(t)
			if m == nil || m[1] != series {
				continue
			}
			tv.patch, _ = strconv.Atoi(m[2])
			if m[4] != "" {
				tv.prerelease = true
				tv.pre, _ = strconv.Atoi(m[5])
			}
		case catalog.FlavorPSMDB:
			m := rePSMDBTag.FindStringSubmatch(t)
			if m == nil || m[1] != series {
				continue
			}
			tv.patch, _ = strconv.Atoi(m[2])
			if m[3] != "" {
				tv.prerelease = true
				tv.pre, _ = strconv.Atoi(m[4])
			} else {
				tv.build, _ = strconv.Atoi(m[4])
			}
		}
		tv.tag = t
		cands = append(cands, tv)
	}
	if len(cands) == 0 {
		return "", false
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.prerelease != b.prerelease {
			return a.prerelease // GA sorts last (newest)
		}
		if a.patch != b.patch {
			return a.patch < b.patch
		}
		if a.pre != b.pre {
			return a.pre < b.pre
		}
		return a.build < b.build
	})
	best := cands[len(cands)-1]
	return best.tag, best.prerelease
}

// fetch makes a blobless, shallow, sparse checkout of tag into dir. An
// existing checkout of the same tag is reused (its sparse patterns are
// re-applied so pattern changes take effect).
func fetch(repo, tag, dir string) error {
	sparse := append([]string{"sparse-checkout", "set", "--no-cone"}, sparsePatterns...)
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return run(dir, "git", sparse...)
	}
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	log.Printf("cloning %s %s", repo, tag)
	if err := run("", "git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", "--depth", "1", "--branch", tag, repo, dir); err != nil {
		return err
	}
	if err := run(dir, "git", sparse...); err != nil {
		return err
	}
	return run(dir, "git", "checkout", "--quiet", tag)
}

func writeCatalog(path string, c *catalog.Catalog) error {
	b, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
