package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Hop rules generated from the per-version catalogs: anything the deployment
// uses that exists in the hop's "from" release but not in its "to" release.
// Attributing by diff means each removal is reported once, at the hop where
// it happens, and parse gaps present in both catalogs cancel out.

var (
	ruleOptRemoved = Rule{
		ID: "config-option-removed", Title: "Removed startup options",
		Category: "config", Scope: ScopeHop, Severity: Error, DocURL: docConfigOpts,
	}
	ruleOptDeprecated = Rule{
		ID: "config-option-deprecated", Title: "Deprecated or renamed startup options",
		Category: "config", Scope: ScopeHop, Severity: Warning, DocURL: docConfigOpts,
	}
	ruleParamRemoved = Rule{
		ID: "parameter-removed", Title: "Removed server parameters",
		Category: "parameters", Scope: ScopeHop, Severity: Error, DocURL: docServerParams,
	}
	ruleParamDeprecated = Rule{
		ID: "parameter-renamed", Title: "Renamed server parameters",
		Category: "parameters", Scope: ScopeHop, Severity: Warning, DocURL: docServerParams,
	}
	ruleCmdRemoved = Rule{
		ID: "command-removed-in-use", Title: "Usage of removed commands",
		Category: "commands", Scope: ScopeHop, Severity: Warning,
	}
	ruleAggRemoved = Rule{
		ID: "agg-operator-removed", Title: "Removed aggregation operators in views and validators",
		Category: "data", Scope: ScopeHop, Severity: Error, DocURL: docAggPipeline,
	}
	ruleActionRemoved = Rule{
		ID: "role-action-removed", Title: "Removed privilege actions in custom roles",
		Category: "security", Scope: ScopeHop, Severity: Error, DocURL: docCustomRoles,
	}
)

func init() {
	ruleOptRemoved.Check = checkOptRemoved
	ruleOptDeprecated.Check = checkOptDeprecated
	ruleParamRemoved.Check = checkParamRemoved
	ruleParamDeprecated.Check = checkParamDeprecated
	ruleCmdRemoved.Check = checkCmdRemoved
	ruleAggRemoved.Check = checkAggRemoved
	ruleActionRemoved.Check = checkActionRemoved
	register(ruleOptRemoved, ruleOptDeprecated, ruleParamRemoved, ruleParamDeprecated,
		ruleCmdRemoved, ruleAggRemoved, ruleActionRemoved)
}

// nodeOptions returns option name -> hosts, from getCmdLineOpts of every
// node plus the local config file when collected.
func nodeOptions(s *snapshot.Snapshot) map[string][]string {
	out := map[string][]string{}
	for _, n := range s.Nodes {
		for k := range n.Options {
			out[k] = append(out[k], n.Host)
		}
	}
	if s.Host != nil {
		for k := range s.Host.ConfigOptions {
			if k == "setParameter" || strings.HasPrefix(k, "setParameter.") {
				continue
			}
			out[k] = append(out[k], configLabel(s.Host))
		}
	}
	return out
}

func startupParams(s *snapshot.Snapshot) map[string][]string {
	out := map[string][]string{}
	for _, n := range s.Nodes {
		for k := range n.StartupParameters {
			out[k] = append(out[k], n.Host)
		}
	}
	if s.Host != nil {
		for k := range s.Host.ConfigOptions {
			if p, ok := strings.CutPrefix(k, "setParameter."); ok {
				out[p] = append(out[p], configLabel(s.Host))
			}
		}
	}
	return out
}

func checkOptRemoved(c *Context) []Finding {
	if !optionsReported(c.Snap) {
		return c.NotChecked(noOptions)
	}
	var items, flavorOnly []string
	opts := nodeOptions(c.Snap)
	for name, hosts := range opts {
		if _, _, okFrom := c.From.ResolveOption(name); !okFrom {
			continue // unknown to the source catalog: not attributable to this hop
		}
		if _, _, okTo := c.To.ResolveOption(name); okTo {
			continue
		}
		item := fmt.Sprintf("%s [%s]", name, summarizeHosts(hosts))
		if c.ToFallback && c.FromCommunity != nil {
			if _, _, inCommunity := c.FromCommunity.ResolveOption(name); !inCommunity {
				flavorOnly = append(flavorOnly, item)
				continue
			}
		}
		items = append(items, item)
	}
	var out []Finding
	if len(items) > 0 {
		sort.Strings(items)
		f := ruleOptRemoved.finding(Error,
			fmt.Sprintf("These options are set on the deployment but do not exist in %s. mongod/mongos will refuse to start with an unrecognized option.", c.Hop.To),
			items, "Remove the options from the configuration file / command line before restarting on the new binary.")
		f.DocURL = compatDoc(c.Hop.To)
		out = append(out, f)
	}
	if len(flavorOnly) > 0 {
		sort.Strings(flavorOnly)
		f := ruleOptRemoved.finding(Warning,
			fmt.Sprintf("These Percona Server for MongoDB options are not in MongoDB Community %s, and PSMDB %s is not released yet, so whether PSMDB %s keeps them is unknown.", c.Hop.To, c.Hop.To, c.Hop.To),
			flavorOnly, fmt.Sprintf("Check the PSMDB %s release notes for these options before upgrading.", c.Hop.To))
		f.DocURL = "https://docs.percona.com/percona-server-for-mongodb/"
		out = append(out, f)
	}
	if len(out) == 0 {
		return c.Checked("checked %s set on %s against %s; none was removed.",
			count(len(opts), "startup option", "startup options"), members(len(c.Snap.Nodes)), c.Hop.To)
	}
	return out
}

func checkOptDeprecated(c *Context) []Finding {
	if !optionsReported(c.Snap) {
		return c.NotChecked(noOptions)
	}
	var items []string
	opts := nodeOptions(c.Snap)
	for name, hosts := range opts {
		canonFrom, depFrom, okFrom := c.From.ResolveOption(name)
		canonTo, depTo, okTo := c.To.ResolveOption(name)
		if !okFrom || !okTo || !depTo || depFrom && canonFrom == canonTo {
			continue
		}
		items = append(items, fmt.Sprintf("%s → %s [%s]", name, canonTo, summarizeHosts(hosts)))
	}
	if len(items) == 0 {
		return c.Checked("checked %s set on %s against %s; none is a deprecated alias there.",
			count(len(opts), "startup option", "startup options"), members(len(c.Snap.Nodes)), c.Hop.To)
	}
	sort.Strings(items)
	f := ruleOptDeprecated.finding(Warning,
		fmt.Sprintf("These options still work in %s but only as deprecated aliases.", c.Hop.To),
		items, "Switch to the new option names.")
	f.DocURL = compatDoc(c.Hop.To)
	return []Finding{f}
}

func checkParamRemoved(c *Context) []Finding {
	if !optionsReported(c.Snap) {
		return c.NotChecked(noOptions)
	}
	var items []string
	params := startupParams(c.Snap)
	for name, hosts := range params {
		if _, _, okFrom := c.From.ResolveParameter(name); !okFrom {
			continue
		}
		if _, _, okTo := c.To.ResolveParameter(name); !okTo {
			items = append(items, fmt.Sprintf("%s [%s]", name, summarizeHosts(hosts)))
		}
	}
	if len(items) == 0 {
		if len(params) == 0 {
			return c.Checked("no server parameter is set at startup on %s.", members(len(c.Snap.Nodes)))
		}
		return c.Checked("checked %s set at startup on %s against %s; none was removed.",
			count(len(params), "parameter", "parameters"), members(len(c.Snap.Nodes)), c.Hop.To)
	}
	sort.Strings(items)
	f := ruleParamRemoved.finding(Error,
		fmt.Sprintf("These server parameters are set at startup but do not exist in %s. The server fails to start with an unknown setParameter.", c.Hop.To),
		items, "Remove them from setParameter in the configuration file / command line.")
	f.DocURL = compatDoc(c.Hop.To)
	return []Finding{f}
}

func checkParamDeprecated(c *Context) []Finding {
	if !optionsReported(c.Snap) {
		return c.NotChecked(noOptions)
	}
	var items []string
	params := startupParams(c.Snap)
	for name, hosts := range params {
		canonFrom, depFrom, okFrom := c.From.ResolveParameter(name)
		canonTo, depTo, okTo := c.To.ResolveParameter(name)
		if !okFrom || !okTo || !depTo || depFrom && canonFrom == canonTo {
			continue
		}
		items = append(items, fmt.Sprintf("%s → %s [%s]", name, canonTo, summarizeHosts(hosts)))
	}
	if len(items) == 0 {
		if len(params) == 0 {
			return c.Checked("no server parameter is set at startup on %s.", members(len(c.Snap.Nodes)))
		}
		return c.Checked("checked %s set at startup on %s against %s; none was renamed.",
			count(len(params), "parameter", "parameters"), members(len(c.Snap.Nodes)), c.Hop.To)
	}
	sort.Strings(items)
	f := ruleParamDeprecated.finding(Warning,
		fmt.Sprintf("These server parameters were renamed in %s; the old name is a deprecated alias.", c.Hop.To),
		items, "Use the new parameter names.")
	f.DocURL = compatDoc(c.Hop.To)
	return []Finding{f}
}

func checkCmdRemoved(c *Context) []Finding {
	if !countersReported(c.Snap) {
		return c.NotChecked(noCounters)
	}
	used := map[string]int64{}
	var uptime int64
	for _, n := range c.Snap.Nodes {
		for cmd, count := range n.CommandCounters {
			used[cmd] += count
		}
		if n.UptimeSeconds > uptime {
			uptime = n.UptimeSeconds
		}
	}
	var items []string
	for cmd, count := range used {
		if count == 0 || strings.HasPrefix(cmd, "_") {
			continue // internal commands are issued by the servers themselves
		}
		if _, ok := c.From.ResolveCommand(cmd); !ok {
			continue
		}
		if _, ok := c.To.ResolveCommand(cmd); !ok {
			items = append(items, fmt.Sprintf("%s (%s)", cmd, plural64(count, "call", "calls")))
		}
	}
	if len(items) == 0 {
		return c.Checked("no command removed in %s was called on %s since the servers started (longest uptime %s).",
			c.Hop.To, members(len(c.Snap.Nodes)), humanDuration(uptime))
	}
	sort.Strings(items)
	f := ruleCmdRemoved.finding(Warning,
		fmt.Sprintf("Clients ran these commands since the servers started (longest uptime %s); %s no longer implements them and will answer CommandNotFound.", humanDuration(uptime), c.Hop.To),
		items, "Find the applications or tools issuing these commands (profiler, logs, $currentOp) and update them before upgrading.")
	f.DocURL = compatDoc(c.Hop.To)
	return []Finding{f}
}

func checkAggRemoved(c *Context) []Finding {
	if !dataCollected(c.Snap) {
		return c.NotChecked(needData)
	}
	var items []string
	views, validators := pipelineCounts(c.Snap)
	for _, db := range c.Snap.Data.Databases {
		for _, coll := range db.Collections {
			ns := db.Name + "." + coll.Name
			for _, src := range []struct {
				what string
				raw  json.RawMessage
			}{{"view pipeline", coll.Pipeline}, {"validator", coll.Validator}} {
				for _, op := range dollarKeys(src.raw) {
					inFrom := c.From.HasAggStage(op) || c.From.HasAggExpression(op)
					inTo := c.To.HasAggStage(op) || c.To.HasAggExpression(op)
					if inFrom && !inTo {
						items = append(items, fmt.Sprintf("%s: %s in %s", ns, op, src.what))
					}
				}
			}
		}
	}
	if len(items) == 0 {
		if views+validators == 0 {
			return c.Checked("the deployment has no views or validators.")
		}
		return c.Checked("checked %s and %s; none uses an aggregation stage or operator removed in %s.",
			count(views, "view pipeline", "view pipelines"), count(validators, "validator", "validators"), c.Hop.To)
	}
	sort.Strings(items)
	f := ruleAggRemoved.finding(Error,
		fmt.Sprintf("These views or validators reference aggregation stages/operators that %s does not recognize. Queries on the views (or writes validated by the validators) will fail.", c.Hop.To),
		items, "Rewrite the view pipelines / validators (collMod) without these operators before upgrading.")
	f.DocURL = compatDoc(c.Hop.To)
	return []Finding{f}
}

func checkActionRemoved(c *Context) []Finding {
	if !securityCollected(c.Snap) {
		return c.NotChecked(needSecurity)
	}
	var items []string
	for _, r := range c.Snap.Security.Roles {
		for _, p := range r.Privileges {
			for _, a := range p.Actions {
				if c.From.HasActionType(a) && !c.To.HasActionType(a) {
					items = append(items, fmt.Sprintf("%s.%s: %s", r.DB, r.Role, a))
				}
			}
		}
	}
	if len(items) == 0 {
		if len(c.Snap.Security.Roles) == 0 {
			return c.Checked("the deployment has no custom roles.")
		}
		return c.Checked("checked %s; none grants a privilege action removed in %s.",
			count(len(c.Snap.Security.Roles), "custom role", "custom roles"), c.Hop.To)
	}
	sort.Strings(items)
	f := ruleActionRemoved.finding(Error,
		fmt.Sprintf("These user-defined roles grant privilege actions that do not exist in %s. Role documents with unknown actions fail validation after the upgrade.", c.Hop.To),
		items, "Remove the actions with revokePrivilegesFromRole before upgrading.")
	f.DocURL = compatDoc(c.Hop.To)
	return []Finding{f}
}

// dollarKeys returns every distinct "$name" object key in a JSON document
// (aggregation stages and operators), sorted.
func dollarKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	seen := map[string]bool{}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if strings.HasPrefix(k, "$") && len(k) > 1 && !isExtJSONKey(k) {
					seen[k] = true
				}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isExtJSONKey filters relaxed extended JSON type wrappers.
func isExtJSONKey(k string) bool {
	switch k {
	case "$oid", "$date", "$numberLong", "$numberDecimal", "$numberDouble", "$numberInt",
		"$binary", "$timestamp", "$regularExpression", "$minKey", "$maxKey", "$undefined",
		"$symbol", "$code", "$scope", "$dbPointer", "$uuid":
		return true
	}
	return false
}

func humanDuration(sec int64) string {
	switch {
	case sec >= 86400:
		return fmt.Sprintf("%dd", sec/86400)
	case sec >= 3600:
		return fmt.Sprintf("%dh", sec/3600)
	case sec >= 60:
		return fmt.Sprintf("%dm", sec/60)
	}
	return fmt.Sprintf("%ds", sec)
}

// dataCollected reports whether databases and collections were listed.
func dataCollected(s *snapshot.Snapshot) bool {
	if s.Collection.SkipData {
		return false
	}
	for _, e := range s.Errors {
		if e.Command == "listDatabases" {
			return false
		}
	}
	return true
}

// securityCollected reports whether users and roles were read.
func securityCollected(s *snapshot.Snapshot) bool {
	if s.Collection.SkipSecurity {
		return false
	}
	for _, e := range s.Errors {
		if strings.HasPrefix(e.Scope, "security") {
			return false
		}
	}
	return true
}

// configLabel names the local configuration file and the member it belongs to.
func configLabel(h *snapshot.HostInfo) string {
	if h.Node != "" {
		return h.ConfigFile + " on " + h.Node
	}
	return h.ConfigFile
}

// pipelineCounts returns how many view pipelines and validators the snapshot
// holds (the objects the pipeline-based rules inspect).
func pipelineCounts(s *snapshot.Snapshot) (views, validators int) {
	pipelines(s, func(_, what string, _ json.RawMessage) {
		if what == "view pipeline" {
			views++
		} else {
			validators++
		}
	})
	return views, validators
}

// Group B rules report Not checked, never "No issues found", when the facts
// they compare were not collected.
const (
	noOptions  = "no member reported its startup options (getCmdLineOpts)."
	noCounters = "no member reported its command counters (serverStatus)."
)

// optionsReported reports whether any member returned its startup options
// (or the local configuration file was read).
func optionsReported(s *snapshot.Snapshot) bool {
	for _, n := range s.Nodes {
		if len(n.Options) > 0 {
			return true
		}
	}
	return s.Host != nil && len(s.Host.ConfigOptions) > 0
}

// countersReported reports whether any member returned command counters.
func countersReported(s *snapshot.Snapshot) bool {
	for _, n := range s.Nodes {
		if n.CommandCounters != nil {
			return true
		}
	}
	return false
}

// operatorCountersReported reports whether any member returned
// metrics.operatorCounters.
func operatorCountersReported(s *snapshot.Snapshot) bool {
	for _, n := range s.Nodes {
		if n.OperatorCounters != nil {
			return true
		}
	}
	return false
}
