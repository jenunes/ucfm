package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// passNotOnFixtures lists rules that never pass on the fixtures below, with
// why: "unit test <TestName>" (which asserts the summary on a passing
// input) or "always reports" (the rule always emits a finding by design).
var passNotOnFixtures = map[string]string{}

// TestEveryPassingCheckSaysWhatItChecked runs every fixture against every
// target (all steps), the audit, and a clean synthetic deployment, and
// requires each passing check to carry a summary.
func TestEveryPassingCheckSaysWhatItChecked(t *testing.T) {
	missing := map[string]bool{}
	passed := map[string]bool{}
	visit := func(cs []CheckResult) {
		for _, c := range cs {
			if c.Status != StatusOK {
				continue
			}
			passed[c.RuleID] = true
			if strings.TrimSpace(c.Summary) == "" {
				missing[c.RuleID] = true
			} else if !strings.HasSuffix(c.Summary, ".") {
				t.Errorf("%s: summary must end with a period: %q", c.RuleID, c.Summary)
			}
		}
	}
	fixtures, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "snapshots", "*.json"))
	if len(fixtures) == 0 {
		t.Fatal("no fixtures")
	}
	run := func(name string, load func() (*Result, *AuditResult)) {
		res, audit := load()
		if res != nil {
			visit(res.Checks)
			for _, h := range res.Hops {
				visit(h.Checks)
			}
		}
		if audit != nil {
			visit(audit.Checks)
		}
		_ = name
	}
	for _, f := range fixtures {
		f := f
		if _, err := os.Stat(f); err != nil {
			continue
		}
		for _, target := range []string{"7.0", "8.0", "8.3", "9.0"} {
			run(f+" "+target, func() (*Result, *AuditResult) {
				res, err := Run(loadFixture(t, filepath.Base(f)), target, Options{SeeTheFuture: true})
				if err != nil {
					return nil, nil
				}
				return res, nil
			})
		}
		run(f+" audit", func() (*Result, *AuditResult) {
			a, err := Audit(loadFixture(t, filepath.Base(f)))
			if err != nil {
				return nil, nil
			}
			return nil, a
		})
	}
	for _, target := range []string{"7.0", "8.0", "8.3", "9.0"} {
		run("base "+target, func() (*Result, *AuditResult) {
			res, err := Run(base(), target, Options{SeeTheFuture: true})
			if err != nil {
				return nil, nil
			}
			return res, nil
		})
	}
	run("base audit", func() (*Result, *AuditResult) {
		a, err := Audit(base())
		if err != nil {
			return nil, nil
		}
		return nil, a
	})

	if len(missing) > 0 {
		t.Errorf("passing checks without a summary (use c.Checked): %s", strings.Join(boolKeys(missing), ", "))
	}
	var never []string
	for _, r := range All() {
		if !passed[r.ID] && passNotOnFixtures[r.ID] == "" {
			never = append(never, r.ID)
		}
	}
	sort.Strings(never)
	if len(never) > 0 {
		t.Errorf("rules that never pass on the fixtures (add a unit test asserting the summary, or mark them as always reporting, in passNotOnFixtures): %s", strings.Join(never, ", "))
	}
}

func boolKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
