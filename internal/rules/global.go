package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Deployment-wide rules: versions, FCV, topology health, sharding state.

var (
	ruleMixedVersions = Rule{
		ID: "binary-versions-consistent", Title: "Server versions across members",
		Category: "path", Scope: ScopeGlobal, Severity: Error, DocURL: docsBase,
	}
	ruleFCV = Rule{
		ID: "fcv-matches-binary", Title: "featureCompatibilityVersion",
		Category: "path", Scope: ScopeGlobal, Severity: Error, DocURL: docSetFCV,
	}
	ruleNoPrimary = Rule{
		ID: "replset-has-primary", Title: "Replica set primary",
		Category: "topology", Scope: ScopeGlobal, Severity: Error, DocURL: docReplStatus,
	}
	ruleMemberHealth = Rule{
		ID: "replset-members-healthy", Title: "Replica set member health and replication lag",
		Category: "topology", Scope: ScopeGlobal, Severity: Warning, DocURL: docReplStatus,
	}
	ruleArbiters = Rule{
		ID: "replset-arbiters", Title: "Arbiters (PSA architecture)",
		Category: "topology", Scope: ScopeGlobal, Severity: Warning, DocURL: docArbiters,
	}
	ruleBalancer = Rule{
		ID: "sharding-balancer", Title: "Balancer state",
		Category: "topology", Scope: ScopeGlobal, Severity: Warning, DocURL: docBalancer,
	}
	ruleResharding = Rule{
		ID: "sharding-no-resharding", Title: "Resharding operations in progress",
		Category: "topology", Scope: ScopeGlobal, Severity: Error, DocURL: docResharding,
	}
	ruleMigrations = Rule{
		ID: "sharding-no-migrations", Title: "Chunk migrations and draining shards",
		Category: "topology", Scope: ScopeGlobal, Severity: Warning, DocURL: docBalancer,
	}
	ruleStartupWarnings = Rule{
		ID: "startup-warnings", Title: "Server startup warnings",
		Category: "procedure", Scope: ScopeGlobal, Severity: Notice, DocURL: docProdNotes,
	}
	ruleNotChecked = Rule{
		ID: "collection-gaps", Title: "Facts that could not be collected",
		Category: "procedure", Scope: ScopeGlobal, Severity: Warning,
	}
	ruleBackup = Rule{
		ID: "backup-before-upgrade", Title: "Backup before upgrading",
		Category: "procedure", Scope: ScopeGlobal, Severity: Notice, DocURL: docPBMCompat,
	}
	ruleDrivers = Rule{
		ID: "driver-compatibility", Title: "Connected driver versions",
		Category: "platform", Scope: ScopeGlobal, Severity: Notice, DocURL: docDrivers,
	}
)

func init() {
	ruleMixedVersions.Check = checkMixedVersions
	ruleFCV.Check = checkFCV
	ruleNoPrimary.Check = checkNoPrimary
	ruleMemberHealth.Check = checkMemberHealth
	ruleArbiters.Check = checkArbiters
	ruleBalancer.Check = checkBalancer
	ruleResharding.Check = checkResharding
	ruleMigrations.Check = checkMigrations
	ruleStartupWarnings.Check = checkStartupWarnings
	ruleNotChecked.Check = checkNotChecked
	ruleBackup.Check = checkBackup
	ruleDrivers.Check = checkDrivers
	register(ruleMixedVersions, ruleFCV, ruleNoPrimary, ruleMemberHealth, ruleArbiters,
		ruleBalancer, ruleResharding, ruleMigrations, ruleStartupWarnings, ruleNotChecked,
		ruleBackup, ruleDrivers)
}

func checkMixedVersions(c *Context) []Finding {
	series := map[string][]string{}
	patches := map[string][]string{}
	for _, n := range c.Snap.Nodes {
		if n.Version == "" {
			continue
		}
		series[snapshot.MajorMinor(n.Version)] = append(series[snapshot.MajorMinor(n.Version)], n.Host)
		patches[n.Version] = append(patches[n.Version], n.Host)
	}
	if len(series) > 1 {
		return []Finding{ruleMixedVersions.finding(Error,
			"Members run different release series. A previous upgrade is incomplete; finish it (including setFeatureCompatibilityVersion) before starting a new one.",
			groupItems(series), fmt.Sprintf("Bring every member to the %s series, then set FCV to %s.", maxKey(series), maxKey(series)))}
	}
	if len(patches) > 1 {
		return []Finding{ruleMixedVersions.finding(Notice,
			"Members run different patch releases of the same series.",
			groupItems(patches), "Align patch versions (latest patch of the current series) before the major upgrade.")}
	}
	for v, hosts := range patches {
		if len(hosts) == 1 {
			return c.Checked("the only member that reported its version runs %s.", v)
		}
		return c.Checked("all %s run %s.", members(len(hosts)), v)
	}
	return c.NotChecked("no member reported its version.")
}

func checkFCV(c *Context) []Finding {
	var wrong []string
	fcvs := map[string]bool{}
	checked := 0
	for _, n := range c.Snap.DataNodes() {
		if n.FCV == "" {
			continue
		}
		checked++
		fcvs[n.FCV] = true
		bin := snapshot.MajorMinor(n.Version)
		if n.FCV != bin {
			wrong = append(wrong, fmt.Sprintf("%s: binary %s, FCV %s", n.Host, bin, n.FCV))
		}
	}
	if len(wrong) == 0 {
		switch {
		case checked == 0:
			return c.NotChecked("no member reported its featureCompatibilityVersion.")
		case len(fcvs) == 1:
			for v := range fcvs {
				return c.Checked("FCV is %s on %s, the same as their binaries.", v, members(checked))
			}
		}
		return c.Checked("FCV matches the binary series on %s.", members(checked))
	}
	f := ruleFCV.finding(Error,
		"The featureCompatibilityVersion is lower than the running binaries. The next binary upgrade will refuse to start until FCV equals the current release.",
		wrong, "After confirming you will not need to downgrade, run on the primary (or through mongos):")
	f.Commands = []string{fmt.Sprintf(`db.adminCommand({setFeatureCompatibilityVersion: "%s"%s})`, c.Source, confirmArg(c.Source))}
	return []Finding{f}
}

// confirmArg returns the confirm:true argument required since 7.0.
func confirmArg(v string) string {
	if snapshot.CompareVersions(v, "7.0") >= 0 {
		return ", confirm: true"
	}
	return ""
}

func checkNoPrimary(c *Context) []Finding {
	if len(c.Snap.Topology.ReplSets) == 0 {
		return c.NotApplicable("not a replica set")
	}
	var sets []string
	for _, rs := range c.Snap.Topology.ReplSets {
		has := false
		for _, m := range rs.Members {
			if m.State == snapshot.RolePrimary {
				has = true
			}
		}
		if !has {
			sets = append(sets, rs.Name)
		}
	}
	if len(sets) == 0 {
		if rs := c.Snap.Topology.ReplSets; len(rs) == 1 {
			return c.Checked("replica set %s has a primary.", rs[0].Name)
		}
		return c.Checked("all %d replica sets have a primary.", len(c.Snap.Topology.ReplSets))
	}
	return []Finding{ruleNoPrimary.finding(Error, "Replica sets without a primary cannot be upgraded with a rolling procedure.", sets,
		"Restore a healthy primary before upgrading.")}
}

const maxLagSeconds = 60

func checkMemberHealth(c *Context) []Finding {
	if len(c.Snap.Topology.ReplSets) == 0 {
		return c.NotApplicable("not a replica set")
	}
	var bad []string
	total := 0
	for _, rs := range c.Snap.Topology.ReplSets {
		for _, m := range rs.Members {
			total++
			switch {
			case m.Health == 0:
				bad = append(bad, fmt.Sprintf("%s/%s: unreachable (%s)", rs.Name, m.Host, m.State))
			case m.State != snapshot.RolePrimary && m.State != snapshot.RoleSecondary && m.State != snapshot.RoleArbiter:
				bad = append(bad, fmt.Sprintf("%s/%s: state %s", rs.Name, m.Host, m.State))
			case m.LagSeconds > maxLagSeconds && !m.Delayed:
				bad = append(bad, fmt.Sprintf("%s/%s: %.0fs behind the primary", rs.Name, m.Host, m.LagSeconds))
			}
		}
	}
	if len(bad) == 0 {
		where := fmt.Sprintf("%d replica sets", len(c.Snap.Topology.ReplSets))
		if len(c.Snap.Topology.ReplSets) == 1 {
			where = "replica set " + c.Snap.Topology.ReplSets[0].Name
		}
		return c.Checked("all %s of %s are reachable, in a normal state and less than %ds behind the primary.",
			members(total), where, maxLagSeconds)
	}
	return []Finding{ruleMemberHealth.finding(Warning,
		"Unhealthy or lagging members reduce redundancy while each member restarts during the rolling upgrade.",
		bad, "Fix member health and replication lag before upgrading.")}
}

func checkArbiters(c *Context) []Finding {
	if len(c.Snap.Topology.ReplSets) == 0 {
		return c.NotApplicable("not a replica set")
	}
	var items []string
	for _, rs := range c.Snap.Topology.ReplSets {
		for _, m := range rs.Members {
			if m.ArbiterOnly {
				items = append(items, rs.Name+"/"+m.Host)
			}
		}
	}
	if len(items) == 0 {
		if rs := c.Snap.Topology.ReplSets; len(rs) == 1 {
			return c.Checked("replica set %s has no arbiter.", rs[0].Name)
		}
		return c.Checked("none of the %d replica sets has an arbiter.", len(c.Snap.Topology.ReplSets))
	}
	return []Finding{ruleArbiters.finding(Warning,
		"Replica sets with an arbiter (PSA) lose the ability to acknowledge majority writes while a data-bearing member is down, which happens at every restart of a rolling upgrade. Majority reads and writes can stall and the WiredTiger cache can grow.",
		items, "Plan the restarts for a low-traffic window, or replace the arbiter with a data-bearing member before upgrading.")}
}

func checkBalancer(c *Context) []Finding {
	si := c.Snap.Sharding
	if c.Snap.Topology.Kind != snapshot.KindSharded || si == nil {
		return c.NotApplicable(notSharded)
	}
	if si.BalancerMode == "off" {
		return c.Checked("the balancer is stopped (mode \"off\").")
	}
	state := "enabled"
	if si.BalancerRunning {
		state = "enabled and currently in a balancing round"
	}
	return []Finding{ruleBalancer.finding(Warning,
		fmt.Sprintf("The balancer is %s (mode %q). Chunk migrations must not run while binaries and FCV change.", state, si.BalancerMode),
		nil, "Run sh.stopBalancer() before the upgrade and sh.startBalancer() after FCV is set.")}
}

func checkResharding(c *Context) []Finding {
	si := c.Snap.Sharding
	if si == nil {
		return c.NotApplicable(notSharded)
	}
	if si.ActiveResharding == 0 {
		return c.Checked("no resharding operation is in progress.")
	}
	return []Finding{ruleResharding.finding(Error,
		fmt.Sprintf("%s in progress. FCV changes abort or are blocked by resharding.", count(si.ActiveResharding, "resharding operation is", "resharding operations are")),
		nil, "Wait for resharding to finish (or abort it with abortReshardCollection) before upgrading.")}
}

func checkMigrations(c *Context) []Finding {
	si := c.Snap.Sharding
	if si == nil {
		return c.NotApplicable(notSharded)
	}
	var items []string
	if si.ActiveMigrations > 0 {
		items = append(items, count(si.ActiveMigrations, "active migration coordinator", "active migration coordinators"))
	}
	for _, s := range si.Shards {
		if s.Draining {
			items = append(items, "shard "+s.ID+" is draining")
		}
	}
	if len(items) == 0 {
		if len(si.Shards) == 1 {
			return c.Checked("no chunk migration is running and the only shard is not draining.")
		}
		return c.Checked("no chunk migration is running and none of the %d shards is draining.", len(si.Shards))
	}
	return []Finding{ruleMigrations.finding(Warning,
		"Chunk migrations or shard removals are in progress.", items,
		"Let migrations finish and complete or cancel shard removal before upgrading.")}
}

func checkStartupWarnings(c *Context) []Finding {
	byMsg := map[string][]string{}
	for _, n := range c.Snap.Nodes {
		for _, w := range n.StartupWarnings {
			msg := warningMessage(w)
			byMsg[msg] = append(byMsg[msg], n.Host)
		}
	}
	if len(byMsg) == 0 {
		return c.Checked("the startup logs of %s have no warnings.", members(len(c.Snap.Nodes)))
	}
	var items []string
	osRelated := false
	for msg, hosts := range byMsg {
		item := fmt.Sprintf("%s [%s]", msg, summarizeHosts(hosts))
		if hc := relatedHostCheck(msg); hc != "" {
			osRelated = true
			item += " (host check: " + hc + ")"
		}
		items = append(items, item)
	}
	sort.Strings(items)
	text := "The servers logged warnings at startup. Review them; some (THP, ulimits, access control) matter more on newer releases."
	if osRelated {
		if c.Snap.Host == nil {
			text += " Warnings marked with a host check are about the operating system; run the host checks to verify those settings (see \"Host checks coverage\" for the commands)."
		} else {
			text += " Warnings marked with a host check are about the operating system; that check reports the current setting."
		}
	}
	return []Finding{ruleStartupWarnings.finding(Notice, text, items, "")}
}

// warningMessage extracts msg (+ a short attr hint) from a structured log line.
func warningMessage(line string) string {
	var l struct {
		Msg  string          `json:"msg"`
		Attr json.RawMessage `json:"attr"`
	}
	if err := json.Unmarshal([]byte(line), &l); err != nil || l.Msg == "" {
		return strings.TrimSpace(line)
	}
	var attr map[string]any
	if json.Unmarshal(l.Attr, &attr) == nil {
		for _, k := range []string{"filepath", "path", "option", "parameter"} {
			if v, ok := attr[k].(string); ok {
				return fmt.Sprintf("%s (%s)", l.Msg, v)
			}
		}
	}
	return l.Msg
}

func checkNotChecked(c *Context) []Finding {
	if fs := gapFindings(c, ruleNotChecked); fs != nil {
		return fs
	}
	return c.Checked("%s", gapSummary(c))
}

// gapSummary says what was collected when nothing failed.
func gapSummary(c *Context) string {
	s := fmt.Sprintf("every fact was collected from %s", members(len(c.Snap.Nodes)))
	if c.Snap.Host != nil {
		s += " and from the local host"
	}
	return s + "."
}

// gapFindings reports collection failures, from the database and from the
// local host, so a partial check is always visible.
func gapFindings(c *Context, r Rule) []Finding {
	errs := append([]snapshot.CollectError(nil), c.Snap.Errors...)
	if c.Snap.Host != nil {
		errs = append(errs, c.Snap.Host.Errors...)
	}
	if len(errs) == 0 {
		return nil
	}
	var items []string
	for _, e := range errs {
		msg := e.Message
		if len(msg) > 160 {
			msg = msg[:160] + "…"
		}
		items = append(items, fmt.Sprintf("%s %s: %s", e.Scope, e.Command, msg))
	}
	action := "Grant the ucfm user the roles listed in the Requirements page (clusterMonitor, readAnyDatabase, ucfmViewSecurity), make every member reachable, run --local as a user that can read the host files, then re-run."
	for _, e := range errs {
		if strings.HasPrefix(e.Scope, "replset:") && strings.Contains(e.Message, "Authentication failed") && c.Snap.Topology.Kind == snapshot.KindSharded {
			action = "Shard members rejected the login; see \"Access to every shard\". " + action
			break
		}
	}
	return []Finding{r.finding(Warning,
		"Some facts could not be collected, so the checks that depend on them are incomplete. Missing privileges, unreachable members or unreadable host files are the usual causes.",
		items, action)}
}

func checkBackup(c *Context) []Finding {
	msg := "A binary upgrade with an FCV change is one-way in practice: downgrading after setFeatureCompatibilityVersion requires a documented downgrade procedure, and some changes are irreversible."
	action := "Take a full backup and test a restore before starting."
	if c.Flavor == "psmdb" {
		action += " With Percona Backup for MongoDB, confirm the PBM version supports both the source and the target server versions, and re-check PITR after the upgrade."
	}
	return []Finding{ruleBackup.finding(Notice, msg, nil, action)}
}

func checkDrivers(c *Context) []Finding {
	// On a replica set the drivers come from every member inspected.
	where := c.Snap.EntryHost
	if c.Snap.Topology.Kind == snapshot.KindReplicaSet && !c.Snap.Collection.EntryOnly {
		where = "the " + count(len(c.Snap.DataNodes()), "replica set member", "replica set members")
	}
	if len(c.Snap.Clients) == 0 {
		if where != c.Snap.EntryHost {
			return c.Checked("no application driver was connected to any of %s when the snapshot was taken.", where)
		}
		return c.Checked("no application driver was connected to %s when the snapshot was taken.", where)
	}
	var items []string
	for _, d := range c.Snap.Clients {
		s := fmt.Sprintf("%s %s (%s)", d.DriverName, d.DriverVersion, plural64(int64(d.Connections), "connection", "connections"))
		if len(d.AppNames) > 0 {
			s += " apps: " + strings.Join(d.AppNames, ", ")
		}
		if len(d.SeenOn) > 0 && where != c.Snap.EntryHost {
			s += " on " + strings.Join(d.SeenOn, ", ")
		}
		items = append(items, s)
	}
	return []Finding{ruleDrivers.finding(Notice,
		fmt.Sprintf("These drivers were connected to %s when the snapshot was taken. Check each against the driver compatibility matrix for MongoDB %s.", where, c.Target),
		items, "Upgrade drivers that do not list the target release as supported before upgrading the servers.")}
}

func groupItems(m map[string][]string) []string {
	var out []string
	for k, hosts := range m {
		out = append(out, fmt.Sprintf("%s: %s", k, summarizeHosts(hosts)))
	}
	sort.Strings(out)
	return out
}

func summarizeHosts(hosts []string) string {
	sort.Strings(hosts)
	if len(hosts) > 4 {
		return fmt.Sprintf("%s and %d more", strings.Join(hosts[:4], ", "), len(hosts)-4)
	}
	return strings.Join(hosts, ", ")
}

func maxKey(m map[string][]string) string {
	best := ""
	for k := range m {
		if best == "" || snapshot.CompareVersions(k, best) > 0 {
			best = k
		}
	}
	return best
}
