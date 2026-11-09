package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jenunes/ucfm/internal/rules"
	"github.com/jenunes/ucfm/internal/snapshot"
)

func result(t *testing.T, fixture, target string) *rules.Result {
	t.Helper()
	snap, err := snapshot.Load(filepath.Join("..", "..", "testdata", "snapshots", fixture))
	if err != nil {
		t.Fatal(err)
	}
	res, err := rules.Run(snap, target, rules.Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func render(t *testing.T, res *rules.Result, format string, o Options) string {
	t.Helper()
	var b bytes.Buffer
	if err := Write(&b, res, format, o); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

var entryRe = regexp.MustCompile(`(?m)^(\d+)\) `)

func TestTextLayoutLikeMySQLChecker(t *testing.T) {
	res := result(t, "psmdb60-planted.json", "7.0")
	out := render(t, res, FormatText, Options{})

	if !strings.HasPrefix(out, "The MongoDB deployment at 172.21.0.2:27017 (replica set rs0, 3 members), Percona\nServer for MongoDB 6.0.29-23, will now be checked for compatibility issues for\nupgrade to MongoDB 7.0 (path 6.0 → 7.0)...") {
		t.Errorf("unexpected introduction:\n%s", out[:300])
	}
	// One numbered entry per check, numbered 1..N without gaps across sections.
	nums := entryRe.FindAllStringSubmatch(out, -1)
	total := len(res.Checks)
	for _, h := range res.Hops {
		total += len(h.Checks)
	}
	if len(nums) != total {
		t.Fatalf("%d numbered entries, want %d", len(nums), total)
	}
	for i, m := range nums {
		if m[1] != itoa(i+1) {
			t.Fatalf("entry %d numbered %s", i+1, m[1])
		}
	}
	for _, want := range []string{
		"\n" + strings.Repeat("=", 80) + "\nDeployment-wide checks\n" + strings.Repeat("=", 80) + "\n",
		"\nUpgrade 6.0 → 7.0\nChecked against Percona Server for MongoDB 7.0, psmdb-7.0.45-24\n" + strings.Repeat("=", 80) + "\n",
		"\n3) featureCompatibilityVersion (fcv-matches-binary)\n   Error: The featureCompatibilityVersion is lower",
		"   No issues found: ",
		"   Not applicable: not a sharded cluster.\n",
		"\n   Solution:\n   - After confirming you will not need to downgrade, run on the primary (or\n      through mongos):\n        db.adminCommand({setFeatureCompatibilityVersion: \"6.0\"})\n",
		"\n   More information:\n     https://www.mongodb.com/docs/manual/reference/command/setFeatureCompatibilityVersion/\n",
		"\nChecks with errors:\n   - 3) featureCompatibilityVersion (fcv-matches-binary)\n",
		"\nErrors:   ",
		"\nWarnings: ",
		"\nNotices:  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
	if flat := strings.Join(strings.Fields(out), " "); !strings.Contains(flat, "errors were found. Correct them before upgrading to avoid compatibility issues.") {
		t.Error("footer advice missing")
	}
	if strings.Contains(strings.ToLower(out), "blocked") {
		t.Error("output must not claim the upgrade is blocked")
	}
	for _, line := range strings.Split(out, "\n") {
		if len([]rune(line)) > 80 && !strings.HasPrefix(line, "    ") {
			t.Errorf("line longer than 80 columns: %q", line)
		}
	}
}

func TestIssuesOnlyHidesPassingChecks(t *testing.T) {
	res := result(t, "psmdb60-planted.json", "7.0")
	out := render(t, res, FormatText, Options{IssuesOnly: true})
	if strings.Contains(out, "No issues found") || strings.Contains(out, "Not applicable:") {
		t.Error("--issues-only must hide passing and not-applicable checks")
	}
	if !strings.Contains(out, "Error: The featureCompatibilityVersion") {
		t.Error("--issues-only must keep checks with findings")
	}
	if !strings.HasPrefix(entryRe.FindString(out), "1) ") {
		t.Error("visible checks are renumbered from 1")
	}
}

func TestMarkdownAndJSON(t *testing.T) {
	res := result(t, "psmdb60-planted.json", "7.0")
	md := render(t, res, FormatMarkdown, Options{})
	for _, want := range []string{"# Upgrade readiness report", "## Deployment-wide checks", "### 1) Upgrade path", "**Error:** ", "| Errors | Warnings | Notices |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	var doc struct {
		SchemaVersion int            `json:"schemaVersion"`
		Summary       map[string]int `json:"summary"`
		Checks        []struct {
			RuleID string `json:"ruleId"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"checks"`
		Hops []struct {
			Checks []struct {
				Status string `json:"status"`
			} `json:"checks"`
		} `json:"hops"`
	}
	if err := json.Unmarshal([]byte(render(t, res, FormatJSON, Options{})), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != JSONSchemaVersion || JSONSchemaVersion != 1 {
		t.Errorf("JSON schemaVersion = %d, want %d", doc.SchemaVersion, JSONSchemaVersion)
	}
	statuses := map[string]bool{}
	for _, c := range doc.Checks {
		statuses[c.Status] = true
	}
	for _, s := range []string{"ok", "issues", "notApplicable"} {
		if !statuses[s] {
			t.Errorf("JSON checks have no %q status", s)
		}
	}
	if doc.Summary["errors"] == 0 || len(doc.Hops) != 1 {
		t.Errorf("summary/hops: %+v %d", doc.Summary, len(doc.Hops))
	}
}

func TestNotCheckedReason(t *testing.T) {
	// The planted fixture has no host facts: host checks must say how to run them.
	res := result(t, "psmdb60-planted.json", "8.0")
	out := render(t, res, FormatText, Options{})
	if !strings.Contains(out, "   Not checked: To run this check, run ucfm on the database host with --local.\n") {
		t.Error("host checks without --local must explain how to run them")
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestPassingCheckSaysWhatWasChecked(t *testing.T) {
	out := render(t, result(t, "psmdb60-planted.json", "7.0"), FormatText, Options{})
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "1) Upgrade path (upgrade-path) No issues found: from 6.0 (current) to 7.0 (target) is a supported upgrade path.") {
		t.Errorf("upgrade path summary missing:\n%s", out[:600])
	}
}

func TestNextStepOnlyIntroAndProjectionSubtitles(t *testing.T) {
	snap, err := snapshot.Load(filepath.Join("..", "..", "testdata", "snapshots", "psmdb60-planted.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := rules.Run(snap, "9.0", rules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := render(t, res, FormatText, Options{})
	if !strings.Contains(strings.Join(strings.Fields(out), " "), "for upgrade to MongoDB 7.0, the next step of the path 6.0 → 7.0 → 8.0 → 9.0...") {
		t.Errorf("intro:\n%s", out[:400])
	}
	if strings.Count(out, "\nUpgrade ") != 1 || strings.Contains(out, "projection") {
		t.Error("the default report must have one step section and no projection")
	}
	future := render(t, result(t, "psmdb60-planted.json", "9.0"), FormatText, Options{})
	if strings.Count(strings.Join(strings.Fields(future), " "), "(projection: assumes the previous steps are done)") != 2 {
		t.Error("steps after the first must be marked as projection")
	}
}

// TestLayoutPattern checks the invariants every check follows, on every
// fixture: lines fit 80 columns (except commands and links), and a line at
// the body indent always starts a new element.
func TestLayoutPattern(t *testing.T) {
	starts := []string{"No issues found", "Not applicable: ", "Not checked: ", "Error: ", "Warning: ", "Notice: ", "- ", "Solution:", "More information:"}
	for _, fx := range []string{"psmdb60-planted.json", "psmdb70sh.json", "rs80.json", "sh80.json", "psmdb60-local.json"} {
		for _, target := range []string{"8.0", "9.0"} {
			out := render(t, result(t, fx, target), FormatText, Options{})
			for i, line := range strings.Split(out, "\n") {
				trimmed := strings.TrimLeft(line, " ")
				indent := len(line) - len(trimmed)
				isCmdOrURL := indent == 8 || indent == 5 && strings.HasPrefix(trimmed, "http")
				if n := len([]rune(line)); n > 80 && !isCmdOrURL {
					t.Errorf("%s %s line %d is %d columns: %q", fx, target, i+1, n, line)
				}
				if indent != 3 || trimmed == "" {
					continue
				}
				ok := false
				for _, p := range starts {
					if strings.HasPrefix(trimmed, p) {
						ok = true
					}
				}
				if !ok {
					t.Errorf("%s %s line %d sits at the body indent but starts no element: %q", fx, target, i+1, line)
				}
			}
		}
	}
}
