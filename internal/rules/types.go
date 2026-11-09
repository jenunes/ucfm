// Package rules holds the checks ucfm runs and the engine that runs them per
// upgrade hop.
package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jenunes/ucfm/internal/catalog"
	"github.com/jenunes/ucfm/internal/snapshot"
	"github.com/jenunes/ucfm/internal/upgradepath"
)

// Severity of a finding, ordered.
type Severity int

const (
	Notice  Severity = 1 // informational; no action required
	Warning Severity = 2 // behavior change or risk; review and act
	Error   Severity = 3 // must be fixed before upgrading (startup or compatibility failure)
)

func (s Severity) String() string {
	switch s {
	case Notice:
		return "NOTICE"
	case Warning:
		return "WARNING"
	case Error:
		return "ERROR"
	}
	return fmt.Sprintf("Severity(%d)", int(s))
}

// MarshalJSON writes the severity name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON reads a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	switch strings.ToUpper(name) {
	case "NOTICE":
		*s = Notice
	case "WARNING":
		*s = Warning
	case "ERROR":
		*s = Error
	default:
		return fmt.Errorf("unknown severity %q", name)
	}
	return nil
}

// Scope says whether a rule runs once per check or once per hop.
type Scope int

const (
	ScopeGlobal Scope = iota // deployment-wide (health, FCV, versions)
	ScopeHop                 // per upgrade hop (catalog diffs, curated hop rules)
	// ScopeProduction rules belong to `ucfm audit` (production notes and
	// operations checklist). rules.Run never executes them.
	ScopeProduction
)

// Rule is one check.
type Rule struct {
	ID       string // stable identifier, e.g. "fcv-matches-binary"
	Title    string
	Category string // path, topology, config, parameters, commands, data, security, platform, host
	Scope    Scope
	// Severity is the highest severity this rule can emit (for list-rules).
	Severity Severity
	// Hops limits a hop rule to specific hops ("7.0→8.0"); empty = every hop.
	Hops []upgradepath.Hop
	// Flavors limits the rule to "community" / "psmdb"; empty = all.
	Flavors []string
	DocURL  string
	Check   func(*Context) []Finding
}

// AppliesTo reports whether a hop rule applies to hop h.
func (r Rule) AppliesTo(h upgradepath.Hop) bool {
	if len(r.Hops) == 0 {
		return true
	}
	for _, x := range r.Hops {
		if x == h {
			return true
		}
	}
	return false
}

// AppliesToFlavor reports whether the rule applies to the flavor.
func (r Rule) AppliesToFlavor(f string) bool {
	if len(r.Flavors) == 0 {
		return true
	}
	for _, x := range r.Flavors {
		if x == f {
			return true
		}
	}
	return false
}

// Finding is one action item.
type Finding struct {
	RuleID   string   `json:"ruleId"`
	Severity Severity `json:"severity"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Hop      string   `json:"hop,omitempty"`
	Message  string   `json:"message"`
	// Items are the affected objects (hosts, options, namespaces, roles...).
	Items  []string `json:"items,omitempty"`
	Action string   `json:"action,omitempty"`
	DocURL string   `json:"docUrl,omitempty"`
	// DocURLs are further links, after DocURL (one per upgrade step, ...).
	DocURLs []string `json:"docUrls,omitempty"`
	// Commands are command lines to copy as part of the solution; the text
	// report prints them on their own lines and never wraps them.
	Commands []string `json:"commands,omitempty"`
}

// Context is what a rule's Check sees.
type Context struct {
	Snap   *snapshot.Snapshot
	Source string // effective source series, e.g. "7.0"
	Target string // series the checks run against: the next step, or the final target with SeeTheFuture
	Flavor string // catalog flavor: community | psmdb
	Hops   []upgradepath.Hop

	// Set for hop-scoped rules only.
	Hop  upgradepath.Hop
	From *catalog.Catalog
	To   *catalog.Catalog
	// ToFallback is set when there is no catalog of the deployment's flavor
	// for the hop target, and To is the Community catalog instead.
	// FromCommunity is then the Community catalog of the hop source, used to
	// tell flavor-specific options apart.
	ToFallback    bool
	FromCommunity *catalog.Catalog

	out *outcome // set by the engine while a rule runs

	// hostSkipped is the name of the machine whose --local facts were
	// dropped because it is not a host of this deployment.
	hostSkipped string
}

// localReason says how to make a host check run.
func (c *Context) localReason() string {
	if c.hostSkipped != "" {
		return fmt.Sprintf("ucfm ran with --local on %s, which is not a host of this deployment, so its settings were not used. %s", c.hostSkipped, needLocal)
	}
	return needLocal
}

// CheckStatus is the outcome of one check.
type CheckStatus string

const (
	StatusOK            CheckStatus = "ok"            // checked, no issues found
	StatusIssues        CheckStatus = "issues"        // findings reported
	StatusNotApplicable CheckStatus = "notApplicable" // does not apply to this deployment
	StatusNotChecked    CheckStatus = "notChecked"    // could not run; Reason says what is needed
)

// CheckResult is one numbered entry of a report.
type CheckResult struct {
	RuleID   string      `json:"ruleId"`
	Title    string      `json:"title"`
	Category string      `json:"category"`
	Hop      string      `json:"hop,omitempty"`
	Status   CheckStatus `json:"status"`
	Reason   string      `json:"reason,omitempty"`
	// Summary says what was checked and found when there is no issue; the
	// report shows it instead of "No issues found".
	Summary  string    `json:"summary,omitempty"`
	DocURL   string    `json:"docUrl,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

// outcome is what a rule reports besides findings.
type outcome struct {
	status  CheckStatus
	reason  string
	summary string
}

// NotApplicable marks the running check as not applying to this deployment
// (for example a sharding check on a replica set). It returns nil so a rule
// can `return c.NotApplicable("...")`.
func (c *Context) NotApplicable(reason string) []Finding {
	if c.out != nil {
		c.out.status, c.out.reason = StatusNotApplicable, reason
	}
	return nil
}

// NotChecked marks the running check as impossible with the collected facts;
// how tells the user what to do so it can run.
func (c *Context) NotChecked(how string) []Finding {
	if c.out != nil {
		c.out.status, c.out.reason = StatusNotChecked, how
	}
	return nil
}

// Checked records what the running check looked at when it found nothing
// to report; the report prints "No issues found: <summary>". It returns nil
// so a passing rule can `return c.Checked("...")`. The summary is one clause
// that reads after the colon: what was checked, its scope (members,
// namespaces, counters window) and the result, ending with a period.
func (c *Context) Checked(format string, a ...any) []Finding {
	if c.out != nil {
		c.out.summary = fmt.Sprintf(format, a...)
	}
	return nil
}

// Common reasons.
const (
	needLocal    = "To run this check, run ucfm on the database host with --local."
	needSecurity = "To run this check, the ucfm user needs viewUser and viewRole (see the Requirements page)."
	needData     = "To run this check, ucfm must list databases and collections (do not use --skip-data; readAnyDatabase is required)."
	notSharded   = "not a sharded cluster"
)

// runCheck runs one rule and turns its findings and outcome into a result.
func runCheck(r Rule, c *Context, hop string) CheckResult {
	c.out = &outcome{}
	fs := r.Check(c)
	res := CheckResult{RuleID: r.ID, Title: r.Title, Category: r.Category, Hop: hop, DocURL: r.DocURL, Status: StatusOK}
	switch {
	case len(fs) > 0:
		res.Status = StatusIssues
		for i := range fs {
			fs[i].Hop = hop
		}
		sortFindings(fs)
		res.Findings = fs
	case c.out.status != "":
		res.Status, res.Reason = c.out.status, c.out.reason
	default:
		res.Summary = c.out.summary
	}
	c.out = nil
	return res
}

// finding builds a Finding pre-filled from the rule.
func (r Rule) finding(sev Severity, msg string, items []string, action string) Finding {
	return Finding{
		RuleID:   r.ID,
		Severity: sev,
		Category: r.Category,
		Title:    r.Title,
		Message:  msg,
		Items:    items,
		Action:   action,
		DocURL:   r.DocURL,
	}
}
