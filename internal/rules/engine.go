package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jenunes/ucfm/internal/catalog"
	"github.com/jenunes/ucfm/internal/snapshot"
	"github.com/jenunes/ucfm/internal/upgradepath"
)

var registry []Rule

// register adds rules at init time. IDs must be unique.
func register(rs ...Rule) {
	for _, r := range rs {
		for _, x := range registry {
			if x.ID == r.ID {
				panic("duplicate rule id " + r.ID)
			}
		}
		registry = append(registry, r)
	}
}

// categoryOrder is the reading order of a report: upgrade path first,
// procedural reminders (backup, collection gaps) last.
var categoryOrder = map[string]int{
	"path": 0, "topology": 1, "platform": 2, "config": 3, "parameters": 4,
	"commands": 5, "data": 6, "security": 7, "behavior": 8, "host": 9, "procedure": 10,
}

func categoryRank(c string) int {
	if r, ok := categoryOrder[c]; ok {
		return r
	}
	return len(categoryOrder)
}

// All returns every registered rule sorted by scope, category and ID.
func All() []Rule {
	out := append([]Rule(nil), registry...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		if ri, rj := categoryRank(out[i].Category), categoryRank(out[j].Category); ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// HopResult groups the checks of one upgrade step.
type HopResult struct {
	Hop         upgradepath.Hop `json:"hop"`
	Catalog     string          `json:"catalog"` // e.g. "psmdb 8.0 (psmdb-8.0.34-15)"
	Provisional bool            `json:"provisional,omitempty"`
	Checks      []CheckResult   `json:"checks"`
}

// Findings returns the findings of all checks of the step.
func (h HopResult) Findings() []Finding { return findingsOf(h.Checks) }

// Result is the outcome of a check.
type Result struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	Flavor     string `json:"flavor"`
	Topology   string `json:"topology"`
	EntryHost  string `json:"entryHost"`
	Deployment string `json:"deployment"` // e.g. "replica set rs0, 3 members"
	Versions   string `json:"versions"`   // e.g. "Percona Server for MongoDB 6.0.29-23"
	// CheckedTarget is the version the checks ran against: the next step of
	// the path, or Target with SeeTheFuture.
	CheckedTarget string `json:"checkedTarget"`
	// PlannedPath is every step from Source to Target; Hops holds only the
	// steps that were checked.
	PlannedPath  []upgradepath.Hop       `json:"plannedPath"`
	SeeTheFuture bool                    `json:"seeTheFuture,omitempty"`
	Checks       []CheckResult           `json:"checks"` // deployment-wide checks
	Hops         []HopResult             `json:"hops"`
	NotChecked   []snapshot.CollectError `json:"collectionErrors,omitempty"`
}

func findingsOf(cs []CheckResult) []Finding {
	var out []Finding
	for _, c := range cs {
		out = append(out, c.Findings...)
	}
	return out
}

func countFindings(fs []Finding) map[Severity]int {
	c := map[Severity]int{}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}

func maxSeverity(fs []Finding) Severity {
	var m Severity
	for _, f := range fs {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// Counts returns how many findings there are per severity.
func (r *Result) Counts() map[Severity]int { return countFindings(r.AllFindings()) }

// Max returns the highest severity found (0 when there are no findings).
func (r *Result) Max() Severity { return maxSeverity(r.AllFindings()) }

// AllFindings returns deployment-wide findings followed by step findings.
func (r *Result) AllFindings() []Finding {
	out := findingsOf(r.Checks)
	for _, h := range r.Hops {
		out = append(out, h.Findings()...)
	}
	return out
}

// catalogFlavor maps a deployment flavor to the catalog flavor.
func catalogFlavor(f string) string {
	if f == "psmdb" {
		return catalog.FlavorPSMDB
	}
	return catalog.FlavorCommunity
}

// loadCatalog loads flavor/version, falling back to community when there is
// no PSMDB catalog for that series yet.
func loadCatalog(flavor, version string) (*catalog.Catalog, bool, error) {
	c, err := catalog.Load(flavor, version)
	if err == nil {
		return c, false, nil
	}
	if flavor != catalog.FlavorCommunity {
		if c, err2 := catalog.Load(catalog.FlavorCommunity, version); err2 == nil {
			return c, true, nil
		}
	}
	return nil, false, err
}

// Options change what Run checks.
type Options struct {
	// SeeTheFuture checks every step to the target. By default only the next
	// major upgrade is checked: later steps depend on a deployment that does
	// not exist yet.
	SeeTheFuture bool
}

// Run checks snap against target and returns the findings.
func Run(snap *snapshot.Snapshot, target string, o Options) (*Result, error) {
	source := snap.SourceVersion()
	if source == "" {
		return nil, fmt.Errorf("could not determine the running version from the snapshot (no node answered buildInfo)")
	}
	guarded, skipped := guardHost(snap)
	ctx := &Context{
		Snap:        guarded,
		Source:      source,
		Target:      target,
		Flavor:      catalogFlavor(snap.Flavor()),
		hostSkipped: skipped,
	}
	res := &Result{
		Source:     source,
		Target:     target,
		Flavor:     snap.Flavor(),
		Topology:   snap.Topology.Kind,
		EntryHost:  snap.EntryHost,
		Deployment: DescribeDeployment(snap),
		Versions:   DescribeVersions(snap),
		NotChecked: snap.Errors,
		Checks:     []CheckResult{},
		Hops:       []HopResult{},
	}

	hops, perr := upgradepath.Plan(source, target)
	checked := hops
	if len(hops) > 1 && !o.SeeTheFuture {
		checked = hops[:1]
	}
	res.PlannedPath, res.SeeTheFuture, res.CheckedTarget = hops, o.SeeTheFuture, target
	if len(checked) > 0 {
		res.CheckedTarget = checked[len(checked)-1].To
	}
	ctx.Hops, ctx.Target = checked, res.CheckedTarget
	res.Checks = append(res.Checks, pathCheck(source, target, hops, perr, snap.Topology.Kind, o.SeeTheFuture))

	for _, r := range All() {
		if r.Scope != ScopeGlobal || !r.AppliesToFlavor(ctx.Flavor) {
			continue
		}
		res.Checks = append(res.Checks, runCheck(r, ctx, ""))
	}

	for _, h := range checked {
		hr := HopResult{Hop: h, Checks: []CheckResult{}}
		from, _, err1 := loadCatalog(ctx.Flavor, h.From)
		to, fallback, err2 := loadCatalog(ctx.Flavor, h.To)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("catalogs for hop %s: %v %v", h, err1, err2)
		}
		hr.Catalog = fmt.Sprintf("%s %s, %s", ProductName(to.Flavor), to.Version, to.SourceTag)
		hr.Provisional = to.Provisional
		if fallback {
			hr.Checks = append(hr.Checks, CheckResult{
				RuleID: "catalog-fallback", Title: "Release catalog for the target", Category: "path",
				Hop: h.String(), Status: StatusIssues,
				Findings: []Finding{{
					RuleID: "catalog-fallback", Severity: Notice, Category: "path",
					Title: "Release catalog for the target", Hop: h.String(),
					Message: fmt.Sprintf("There is no Percona Server for MongoDB %s source release yet, so this step was checked against MongoDB Community %s (%s). PSMDB-specific options may be reported incorrectly.",
						h.To, h.To, to.SourceTag),
				}},
			})
		}
		hctx := *ctx
		hctx.Hop, hctx.From, hctx.To = h, from, to
		if fallback {
			hctx.ToFallback = true
			hctx.FromCommunity, _ = catalog.Load(catalog.FlavorCommunity, h.From)
		}
		for _, r := range All() {
			if r.Scope != ScopeHop || !r.AppliesTo(h) || !r.AppliesToFlavor(ctx.Flavor) {
				continue
			}
			hr.Checks = append(hr.Checks, runCheck(r, &hctx, h.String()))
		}
		res.Hops = append(res.Hops, hr)
	}
	return res, nil
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}

// pathCheck reports the upgrade path as the first check. When the target is
// more than one major upgrade away, only the next step is checked and the
// check is an ERROR; with seeTheFuture every step is checked and it is a
// WARNING that links the upgrade procedure of each step.
func pathCheck(source, target string, hops []upgradepath.Hop, err error, kind string, seeTheFuture bool) CheckResult {
	c := CheckResult{RuleID: "upgrade-path", Title: "Upgrade path", Category: "path", Status: StatusOK,
		DocURL: "https://www.mongodb.com/docs/manual/release-notes/"}
	finding := Finding{RuleID: "upgrade-path", Category: "path", Title: "Upgrade path"}
	switch {
	case err != nil:
		finding.Severity, finding.Message, finding.DocURL = Error, err.Error(), c.DocURL
		finding.Action = "Choose a target the deployment can reach through supported releases (6.0, 7.0, 8.0, 8.3, 9.0)."
	case len(hops) == 0:
		c.Status, c.Reason = StatusNotApplicable, fmt.Sprintf("the deployment already runs %s", source)
		return c
	case len(hops) == 1:
		c.Summary = fmt.Sprintf("from %s (current) to %s (target) is a supported upgrade path.", source, target)
		return c
	case !seeTheFuture:
		next := hops[0]
		finding.Severity = Error
		finding.Message = fmt.Sprintf("MongoDB %s is %d upgrades away: %s. Only the next step, %s, was checked; the later steps depend on a deployment that does not exist yet.",
			target, len(hops), hopPath(hops), next)
		finding.Action = fmt.Sprintf("Upgrade to %s, then run ucfm again with --target %s.", next.To, hops[1].To)
		if hops[1].To != target {
			finding.Action = fmt.Sprintf("Upgrade to %s, then run ucfm again (--target %s, or --target %s to continue the path).", next.To, hops[1].To, target)
		}
		finding.DocURL = UpgradeDoc(next.To, kind)
	default:
		var docs []string
		for _, h := range hops {
			docs = append(docs, UpgradeDoc(h.To, kind))
		}
		finding.Severity = Warning
		finding.Message = fmt.Sprintf("From %s (current) to %s (target) is a supported upgrade path, but it takes %d upgrades in sequence: %s. Each one is a rolling binary upgrade. The steps after %s are a projection.",
			source, target, len(hops), hopPath(hops), hops[0])
		finding.Action = "Do the upgrades one at a time."
		finding.DocURL, finding.DocURLs = docs[0], docs[1:]
	}
	c.Status, c.Findings = StatusIssues, []Finding{finding}
	return c
}

// hopPath writes hops as "6.0 → 7.0 → 8.0".
func hopPath(hops []upgradepath.Hop) string {
	parts := []string{hops[0].From}
	for _, h := range hops {
		parts = append(parts, h.To)
	}
	return strings.Join(parts, " → ")
}

// ProductName is the display name of a flavor.
func ProductName(flavor string) string {
	switch flavor {
	case "psmdb":
		return "Percona Server for MongoDB"
	case "enterprise":
		return "MongoDB Enterprise"
	}
	return "MongoDB Community"
}

// DescribeDeployment summarizes the topology: "replica set rs0, 3 members",
// "sharded cluster, 2 shards, 1 mongos" or "standalone".
func DescribeDeployment(s *snapshot.Snapshot) string {
	switch s.Topology.Kind {
	case snapshot.KindReplicaSet:
		if len(s.Topology.ReplSets) > 0 {
			rs := s.Topology.ReplSets[0]
			return fmt.Sprintf("replica set %s, %d members", rs.Name, len(rs.Members))
		}
		return "replica set"
	case snapshot.KindSharded:
		shards, mongos := 0, 0
		for _, rs := range s.Topology.ReplSets {
			if rs.Role == "shard" {
				shards++
			}
		}
		if s.Sharding != nil && len(s.Sharding.Shards) > shards {
			shards = len(s.Sharding.Shards)
		}
		for _, n := range s.Nodes {
			if n.Role == snapshot.RoleMongos {
				mongos++
			}
		}
		return fmt.Sprintf("sharded cluster, %s, %d mongos", count(shards, "shard", "shards"), mongos)
	}
	return "standalone"
}

// DescribeVersions lists the distinct product versions found:
// "Percona Server for MongoDB 6.0.29-23" or "MongoDB Community 7.0.12, 7.0.29".
func DescribeVersions(s *snapshot.Snapshot) string {
	seen := map[string]bool{}
	var vs []string
	for _, n := range s.Nodes {
		if n.Version != "" && !seen[n.Version] {
			seen[n.Version] = true
			vs = append(vs, n.Version)
		}
	}
	sort.Slice(vs, func(i, j int) bool { return snapshot.CompareVersions(vs[i], vs[j]) < 0 })
	return strings.TrimSpace(ProductName(s.Flavor()) + " " + strings.Join(vs, ", "))
}

// guardHost returns the snapshot the rules may see: when the --local facts
// come from a machine that is not a host of this deployment (ucfm run from
// another machine), they are hidden so no rule judges that machine's
// settings, and the machine's name is returned for the "not checked" reason.
func guardHost(snap *snapshot.Snapshot) (*snapshot.Snapshot, string) {
	h := snap.Host
	if h == nil || hostIsMember(snap, h) {
		return snap, ""
	}
	cp := *snap
	cp.Host = nil
	name := h.Hostname
	if name == "" {
		name = "this machine"
	}
	return &cp, name
}

// hostIsMember reports whether the --local facts belong to a member. Newer
// snapshots record the match at collection time (Node, with LocalAddrs);
// older ones fall back to comparing host names.
func hostIsMember(snap *snapshot.Snapshot, h *snapshot.HostInfo) bool {
	if h.Node != "" {
		return true
	}
	if len(h.LocalAddrs) > 0 {
		return false // matched at collection time, and nothing matched
	}
	for _, n := range snap.DataNodes() {
		if localHostCovers(h, n) {
			return true
		}
	}
	return false
}
