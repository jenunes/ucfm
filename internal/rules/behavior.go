package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Documented behavior changes, each verified against the deployment instead
// of being listed for the user to check by hand. Evidence comes from:
//   - server usage counters (serverStatus operatorCounters, aggStageCounters,
//     command counters), which cover the time since each server started;
//   - redacted profiler evidence, when profiling is enabled;
//   - collected configuration, namespaces and indexes;
//   - --deep-check document sampling, for changes that depend on stored data.
//
// Every rule quotes the official page it is based on.

// needCounters is the reason given when a snapshot predates usage counters.
const needCounters = "To run this check, collect the snapshot with this version of ucfm from the live deployment (server usage counters are missing)."

// counterHit sums one usage counter across the nodes that reported it.
type counterHit struct {
	total  int64
	byHost map[string]int64
	uptime int64 // longest uptime among the reporting nodes
	known  bool  // at least one node reported the counter group
	nodes  int   // nodes that reported the counter group
}

func (h *counterHit) add(n snapshot.Node, v int64, reported bool) {
	if !reported {
		return
	}
	h.known = true
	h.nodes++
	if n.UptimeSeconds > h.uptime {
		h.uptime = n.UptimeSeconds
	}
	if v > 0 {
		if h.byHost == nil {
			h.byHost = map[string]int64{}
		}
		h.byHost[n.Host] += v
		h.total += v
	}
}

// opCounter sums serverStatus metrics.operatorCounters.<group>.<op>.
func opCounter(s *snapshot.Snapshot, group, op string) counterHit {
	var h counterHit
	for _, n := range s.Nodes {
		g, ok := n.OperatorCounters[group]
		h.add(n, g[op], ok)
	}
	return h
}

// stageCounter sums serverStatus metrics.aggStageCounters.<stage>.
func stageCounter(s *snapshot.Snapshot, stage string) counterHit {
	var h counterHit
	for _, n := range s.Nodes {
		h.add(n, n.AggStageCounters[stage], n.AggStageCounters != nil)
	}
	return h
}

// cmdCounter sums serverStatus metrics.commands.<cmd>.total over the nodes
// accepted by keep (nil = all nodes).
func cmdCounter(s *snapshot.Snapshot, cmd string, keep func(snapshot.Node) bool) counterHit {
	var h counterHit
	for _, n := range s.Nodes {
		if keep != nil && !keep(n) {
			continue
		}
		h.add(n, n.CommandCounters[cmd], n.CommandCounters != nil)
	}
	return h
}

// describe renders "name: N uses since startup 3d ago [a:27017 40, b:27017 2]".
func (h counterHit) describe(name string) string {
	hosts := sortedKeys(h.byHost)
	sort.SliceStable(hosts, func(i, j int) bool { return h.byHost[hosts[i]] > h.byHost[hosts[j]] })
	var parts []string
	for i, host := range hosts {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("%d more", len(hosts)-3))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", host, h.byHost[host]))
	}
	return fmt.Sprintf("%s: %s since startup %s ago [%s]", name, plural64(h.total, "use", "uses"), humanDuration(h.uptime), strings.Join(parts, ", "))
}

// unused writes the passing summary of a counter: "compact was not run on
// 3 members since startup 3d ago." (verb: "used", "run", ...).
func (h counterHit) unused(name, verb string) string {
	return fmt.Sprintf("%s was not %s on %s since startup %s ago.", name, verb, members(h.nodes), humanDuration(h.uptime))
}

// usageSummary is the passing summary of usageEvidence: which sources were
// checked for ops (counters, views and validators, profiler) and found none.
func usageSummary(s *snapshot.Snapshot, group string, ops []string, name string) string {
	var h counterHit
	for _, n := range s.Nodes {
		_, ok := n.OperatorCounters[group]
		h.add(n, 0, ok)
	}
	var parts []string
	if h.known {
		parts = append(parts, fmt.Sprintf("on %s since startup %s ago", members(h.nodes), humanDuration(h.uptime)))
	}
	if dataCollected(s) {
		parts = append(parts, "in any view or validator")
	}
	if profilerOn(s) {
		parts = append(parts, "in the profiled operations")
	}
	verb := "was"
	if len(ops) > 1 {
		verb = "were"
	}
	switch len(parts) {
	case 0:
		return fmt.Sprintf("%s %s not used.", name, verb)
	case 1:
		return fmt.Sprintf("%s %s not used %s.", name, verb, parts[0])
	}
	return fmt.Sprintf("%s %s not used %s, nor %s.", name, verb, strings.Join(parts[:len(parts)-1], ", "), parts[len(parts)-1])
}

// collectionCount counts the collections and views that were listed.
func collectionCount(s *snapshot.Snapshot) int {
	n := 0
	for _, db := range s.Data.Databases {
		n += len(db.Collections)
	}
	return n
}

// profilerOn reports whether profiler evidence was collected.
func profilerOn(s *snapshot.Snapshot) bool {
	return s.Profiler != nil && len(s.Profiler.DatabasesProfiled) > 0
}

// profilerEvidence returns the profiler evidence for key, or nil.
func profilerEvidence(s *snapshot.Snapshot, key string) *snapshot.ProfilerEvidence {
	if s.Profiler == nil {
		return nil
	}
	if e := s.Profiler.Evidence[key]; e != nil && e.Count > 0 {
		return e
	}
	return nil
}

// profilerItems renders profiler evidence as report items.
func profilerItems(what string, e *snapshot.ProfilerEvidence) []string {
	items := []string{fmt.Sprintf("profiler: %d %s", e.Count, what)}
	for _, ex := range e.Examples {
		items = append(items, "  e.g. "+ex)
	}
	return items
}

// viewOps lists views/validators that use any of ops.
func viewOps(s *snapshot.Snapshot, ops ...string) []string {
	var items []string
	pipelines(s, func(ns, what string, raw json.RawMessage) {
		for _, op := range dollarKeys(raw) {
			for _, want := range ops {
				if op == want {
					items = append(items, fmt.Sprintf("%s: %s in %s", ns, op, what))
				}
			}
		}
	})
	sort.Strings(items)
	return items
}

// usageEvidence gathers counters, views and profiler evidence for operators.
// It returns the items and whether any source could be checked at all.
func usageEvidence(s *snapshot.Snapshot, group string, ops []string) (items []string, checked bool) {
	for _, op := range ops {
		h := opCounter(s, group, op)
		checked = checked || h.known
		if h.total > 0 {
			items = append(items, h.describe(op))
		}
	}
	if dataCollected(s) {
		checked = true
		items = append(items, viewOps(s, ops...)...)
	}
	if profilerOn(s) {
		checked = true
		for _, op := range ops {
			if e := profilerEvidence(s, snapshot.EvidenceOpPrefix+op); e != nil {
				items = append(items, profilerItems("operations use "+op, e)...)
			}
		}
	}
	return items, checked
}

// indexesOfType lists ns.index for indexes with a key of the given type
// ("2dsphere", "text").
func indexesOfType(s *snapshot.Snapshot, typ string) []string {
	var out []string
	for _, db := range s.Data.Databases {
		for _, coll := range db.Collections {
			for _, ix := range coll.Indexes {
				for _, k := range ix.Key {
					if jsonScalar(k.Value) == typ {
						out = append(out, fmt.Sprintf("%s.%s: %s", db.Name, coll.Name, ix.Name))
						break
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// shardMembers returns the data-bearing shard members in the snapshot.
func shardMembers(s *snapshot.Snapshot) []snapshot.Node {
	var out []snapshot.Node
	for _, n := range s.DataNodes() {
		if n.ShardName != "" && !n.IsConfig {
			out = append(out, n)
		}
	}
	return out
}

// directShardClients lists application drivers connected straight to shard
// members, bypassing mongos. ok is false when shard members were not seen.
func directShardClients(c *Context) (items []string, ok bool, reason string) {
	if c.Snap.Collection.EntryOnly {
		return nil, false, "To run this check, run ucfm without --entry-only so it can inspect the shard members."
	}
	members := shardMembers(c.Snap)
	if len(members) == 0 {
		return nil, false, "No shard member could be inspected; run ucfm from a host that can reach the shard members."
	}
	for _, n := range members {
		for _, d := range n.Clients {
			s := fmt.Sprintf("%s: %s %s (%s)", n.Host, d.DriverName, d.DriverVersion, plural64(int64(d.Connections), "connection", "connections"))
			if len(d.AppNames) > 0 {
				s += " apps: " + strings.Join(d.AppNames, ", ")
			}
			items = append(items, s)
		}
	}
	sort.Strings(items)
	return items, true, ""
}

// shardMembersPhrase writes "the shard member inspected" or "any of the 9
// shard members inspected".
func shardMembersPhrase(s *snapshot.Snapshot) string {
	if n := len(shardMembers(s)); n != 1 {
		return fmt.Sprintf("any of the %d shard members inspected", n)
	}
	return "the shard member inspected"
}

func sharded(s *snapshot.Snapshot) bool {
	return s.Topology.Kind == snapshot.KindSharded && s.Sharding != nil
}

func behaviorRule(id, title string, names []string, sev Severity, doc string, check func(*Context) []Finding) Rule {
	return Rule{ID: id, Title: title, Category: "behavior", Scope: ScopeHop, Severity: sev, DocURL: doc, Hops: hops(names...), Check: check}
}

func bf(id string, sev Severity, msg string, items []string, action string) []Finding {
	return []Finding{rule(id).finding(sev, msg, items, action)}
}

var (
	into83 = []string{hop80to83, hop80to90}
	into90 = []string{hop80to90, hop83to90}
)

func init() {
	register(
		// ---------------------------------------------------------- 7.0
		// 7.0-compatibility: "The $add expression no longer accounts for
		// floating-point rounding errors."
		behaviorRule("add-rounding", "Floating-point rounding in $add", []string{hop60to70}, Warning, docCompat70, checkAddRounding),
		// 7.0-compatibility: "Starting in MongoDB 6.0.3, automatic chunk
		// splitting is not performed." "Auto-splitting commands still exist,
		// but do not perform an operation."
		behaviorRule("autosplit-removed", "Automatic chunk splitting", []string{hop60to70}, Notice, docCompat70, checkAutosplit),
		// 7.0-compatibility: "you must set value between 1 and 1024
		// (inclusive) when inserting or updating documents with the _id:
		// chunksize field in the config.settings collection."
		behaviorRule("chunksize-range", "chunksize setting range", []string{hop60to70}, Error, docCompat70, checkChunkSize),
		// 7.0-compatibility: "Starting in version 6.2, MongoDB removes the
		// maxSize field from the addShard command."
		behaviorRule("addshard-maxsize", "addShard maxSize setting", []string{hop60to70}, Warning, docCompat70, checkMaxSize),
		// 7.0-compatibility: "After MongoDB 7.0, if you pass any value other
		// than 1 and -1 to $natural, MongoDB returns an error."
		behaviorRule("natural-hint-values", "$natural hint and sort values", []string{hop60to70}, Warning, docCompat70, checkNatural),
		// 7.0-compatibility: "Active setClusterParameter parameter operations
		// prevent feature Compatibility Version (FCV) from successful
		// completion."
		behaviorRule("setclusterparameter-active", "Active setClusterParameter operations", []string{hop60to70}, Warning, docCompat70, checkSetClusterParameter),

		// ---------------------------------------------------------- 8.0
		// 8.0-compatibility: "Starting in MongoDB 8.0, comparisons to null in
		// equality match expressions don't match undefined values."
		behaviorRule("null-undefined-match", "Null equality matches on undefined values", []string{hop70to80}, Warning, docCompat80, checkNullUndefined),
		// 8.0-compatibility: "write operations that use the "majority" write
		// concern return an acknowledgment when the majority of replica set
		// members have written the oplog entry for the change."
		behaviorRule("majority-write-ack", "Majority write concern acknowledgment", []string{hop70to80}, Notice, docCompat80, checkMajorityAck),
		// 8.0-compatibility: "To run a non-supported database command
		// directly against a node in a sharded cluster, you must either
		// connect to mongos or have the maintenance-only directShardOperations
		// role."
		behaviorRule("direct-shard-operations", "Commands run directly on shard members", []string{hop70to80}, Warning, docCompat80, checkDirectShardOps),
		// 8.0-compatibility: "Queries that specify the read preference nearest
		// no longer use hedged reads by default."
		behaviorRule("hedged-reads-default", "Hedged reads", []string{hop70to80}, Notice, docCompat80, checkHedgedReads),
		// 8.0-compatibility: "MongoDB 8.0.4 and earlier: You must drop or
		// rename system.buckets collections that aren't time-series
		// collections before you upgrade."
		behaviorRule("system-buckets-orphans", "system.buckets collections that are not time series", []string{hop70to80}, Warning, docCompat80, checkBucketOrphans),
		// 8.0-compatibility: "if you try to run multiple concurrent compact
		// commands on the same collection, MongoDB returns an error."
		behaviorRule("compact-concurrency", "Concurrent compact operations", []string{hop70to80}, Notice, docCompat80, checkCompact),
		// 8.0-compatibility (Deprecations): "Starting in MongoDB 8.0, use of
		// the timeField as a shard key in a time series collection is
		// deprecated." The 8.0 server logs (shard_key_util.cpp, id 8864700):
		// "Please reshard your collection using metaField as recommended in
		// our time-series sharding documentation."
		behaviorRule("timeseries-shardkey-timefield", "Time series collections sharded on the timeField", []string{hop70to80}, Warning, docCompat80, checkTimeseriesShardKey),

		// ---------------------------------------------------------- 8.3
		// 8.3 release notes: "Starting in MongoDB 8.3, you can only run DDL
		// operations and applyOps on a mongos for all sharded clusters."
		behaviorRule("ddl-via-mongos", "DDL operations and applyOps on shard members", into83, Warning, docRelease83, checkDDLViaMongos),
		// 8.3-compatibility: "Starting in MongoDB 8.3, 2dsphereIndexVersion is
		// set to version 4 by default." "If you need to downgrade the FCV to
		// anything below 8.3, you must first drop the 2dsphere version 4
		// indexes."
		behaviorRule("2dsphere-index-v4", "2dsphere index version 4", into83, Notice, docCompat83, check2dsphereV4),
		// 8.3 release notes: "MongoDB 8.3 increases the default value of
		// diagnosticDataCollectionDirectorySizeMB from 200 to 500 MiB."
		behaviorRule("ftdc-directory-size", "FTDC directory size", into83, Notice, docRelease83, checkFTDCSize),
		// 8.3 release notes: "the length of the string you provide to chars
		// is limited to 4096 characters." and "the query engine limits the
		// TextOr stage memory usage to 100 megabytes."
		behaviorRule("trim-limits", "$trim chars limit and text search memory", into83, Notice, docRelease83, checkTrimLimits),
		// 8.3 release notes: "if unit is not "millisecond" in $dateAdd or
		// $dateSubtract and the input date is before
		// ISODate("1970-01-01T00:00:00Z"), the result will be one second
		// greater than in previous versions of MongoDB."
		behaviorRule("dateadd-preepoch", "$dateAdd and $dateSubtract on pre-epoch dates", into83, Notice, docRelease83, checkDateAddPreEpoch),

		// ---------------------------------------------------------- 9.0
		// 9.0-compatibility: "a change stream opened with a readPreference of
		// primary or secondary returns the resumable error
		// InterruptedDueToReplStateChange (error code 11602) from getMore"
		// and "Manual getMore loops and mongosh must resume with resumeAfter."
		behaviorRule("changestream-getmore-errors", "Change stream getMore errors after elections", into90, Warning, docCompat90, checkChangeStreams),
		// 9.0-compatibility: "2dsphere index key-extraction failures return
		// the named error codes 510 (GeoKeyExtractionFailed) and 511
		// (GeoKeyExtractionFailedTimeseries)."
		behaviorRule("2dsphere-error-codes", "2dsphere key-extraction error codes", into90, Notice, docCompat90, check2dsphereCodes),
		// 9.0-compatibility: "when you rename a collection between different
		// databases on a replica set, the renameCollection command holds an
		// exclusive lock on the source and target collections." "The change
		// affects replica sets only."
		behaviorRule("rename-cross-db-locks", "Cross-database renameCollection locking", into90, Notice, docCompat90, checkRenameLocks),
		// 9.0-compatibility: "the $queryStats key for aggregate commands
		// includes the allowPartialResults option when the option is
		// explicitly set." "Downstream consumers that match on keyHash might
		// observe different values for these queries."
		behaviorRule("querystats-keys", "$queryStats keys for aggregate commands", into90, Notice, docCompat90, checkQueryStats),
		// 9.0-compatibility: "if an indexed field becomes a multikey field
		// while a query that references the field is running, the query
		// might fail with a QueryKilledError."
		behaviorRule("multikey-query-killed", "Queries on fields that become multikey", into90, Notice, docCompat90, checkMultikey),
	)
}

// ---------------------------------------------------------------- 7.0

func checkAddRounding(c *Context) []Finding {
	items, checked := usageEvidence(c.Snap, "expressions", []string{"$add"})
	if len(items) > 0 {
		return bf("add-rounding", Warning,
			"$add is in use. From 6.1, $add no longer compensates for floating-point rounding errors, so sums of several floating-point values can return slightly different results.",
			items, "Check calculations that add floating-point values (money, measurements). Use Decimal128 where exact results matter.")
	}
	if !checked {
		return c.NotChecked(needCounters)
	}
	return c.Checked("%s", usageSummary(c.Snap, "expressions", []string{"$add"}, "$add"))
}

func checkAutosplit(c *Context) []Finding {
	if !sharded(c.Snap) {
		return c.NotApplicable(notSharded)
	}
	si := c.Snap.Sharding
	var items []string
	if si.ShardedCollections > 0 {
		items = append(items, count(si.ShardedCollections, "sharded collection", "sharded collections"))
	}
	if si.AutoSplit != nil {
		items = append(items, fmt.Sprintf("config.settings autosplit enabled = %v (ignored from 6.0.3)", *si.AutoSplit))
	}
	if len(items) == 0 {
		return c.Checked("there is no sharded collection and no autosplit setting in config.settings.")
	}
	return bf("autosplit-removed", Notice,
		"Chunks are no longer split automatically; the balancer distributes data by data size, and sh.enableAutoSplit()/sh.disableAutoSplit() do nothing.",
		items, "Remove scripts or runbooks that depend on auto-splitting; check chunk distribution with sh.status() after the upgrade.")
}

func checkChunkSize(c *Context) []Finding {
	if !sharded(c.Snap) {
		return c.NotApplicable(notSharded)
	}
	mb := c.Snap.Sharding.ChunkSizeMB
	if mb == 0 {
		return c.Checked("config.settings has no chunksize setting, so the default applies.")
	}
	if mb >= 1 && mb <= 1024 {
		return c.Checked("config.settings chunksize is %d MB, between 1 and 1024 MB.", mb)
	}
	return bf("chunksize-range", Error,
		fmt.Sprintf("config.settings chunksize is %d MB. From 6.2 the value must be between 1 and 1024 MB; out-of-range values set earlier stay in place.", mb),
		nil, `Set a valid value through mongos: db.getSiblingDB("config").settings.updateOne({_id: "chunksize"}, {$set: {value: 128}}, {upsert: true}).`)
}

// needShardKeys is the reason given when config.collections was not read.
const needShardKeys = "To run this check, ucfm must read config.collections through mongos (do not use --skip-data; clusterMonitor is required)."

func checkTimeseriesShardKey(c *Context) []Finding {
	if !sharded(c.Snap) {
		return c.NotApplicable(notSharded)
	}
	si := c.Snap.Sharding
	if !si.CollectionsRead {
		return c.NotChecked(needShardKeys)
	}
	var items []string
	shardedColls, tsColls := 0, 0
	for _, sc := range si.Collections {
		if !sc.Unsplittable {
			shardedColls++
		}
		if sc.TimeField == "" || sc.Unsplittable {
			continue
		}
		tsColls++
		onTime := false
		var fields []string
		for _, k := range sc.Key {
			f := strings.TrimPrefix(k.Field, "control.min.")
			if k.Field == sc.TimeField || k.Field == "control.min."+sc.TimeField {
				onTime = true
			}
			if k.Field == "meta" && sc.MetaField != "" {
				f = sc.MetaField
			} else if strings.HasPrefix(k.Field, "meta.") && sc.MetaField != "" {
				f = sc.MetaField + strings.TrimPrefix(k.Field, "meta")
			}
			fields = append(fields, fmt.Sprintf("%s: %s", f, string(k.Value)))
		}
		if onTime {
			items = append(items, fmt.Sprintf("%s (shard key {%s})", strings.Replace(sc.NS, ".system.buckets.", ".", 1), strings.Join(fields, ", ")))
		}
	}
	if len(items) == 0 {
		if si.CollectionsTruncated {
			return c.NotChecked("Only part of config.collections was read (--max-namespaces); raise the limit to check every sharded collection.")
		}
		return c.Checked("checked %s in config.collections (%d time series); none is sharded on its timeField.",
			count(shardedColls, "sharded collection", "sharded collections"), tsColls)
	}
	msg := "These time series collections are sharded on their timeField. Starting in 8.0 a timeField shard key is deprecated and will not be supported in a future version."
	if si.CollectionsTruncated {
		msg += " Only part of config.collections was read (--max-namespaces), so the list may be incomplete."
	}
	return bf("timeseries-shardkey-timefield", Warning, msg, items,
		"The collections keep working after the upgrade. Plan to reshard them on the metaField (reshardCollection), as the time series sharding documentation recommends.")
}

func checkMaxSize(c *Context) []Finding {
	if !sharded(c.Snap) {
		return c.NotApplicable(notSharded)
	}
	var items []string
	for _, s := range c.Snap.Sharding.Shards {
		if s.MaxSizeMB > 0 {
			items = append(items, fmt.Sprintf("%s: maxSize %d MB", s.ID, s.MaxSizeMB))
		}
	}
	if len(items) == 0 {
		if n := len(c.Snap.Sharding.Shards); n != 1 {
			return c.Checked("none of the %d shards has maxSize set.", n)
		}
		return c.Checked("the only shard has no maxSize set.")
	}
	return bf("addshard-maxsize", Warning,
		"These shards were added with maxSize. From 6.2 addShard no longer accepts maxSize (InvalidOptions error), and the setting no longer limits the shard.",
		items, "Remove maxSize from scripts that add shards, and plan capacity without it.")
}

func checkNatural(c *Context) []Finding {
	if !profilerOn(c.Snap) {
		return c.NotChecked("To run this check, enable the database profiler (db.setProfilingLevel(1)) on the application databases for a representative period, then run ucfm again.")
	}
	e := profilerEvidence(c.Snap, snapshot.EvidenceNatural)
	if e == nil {
		return c.Checked("the profiler on %s recorded no $natural hint or sort with a value other than 1 or -1.",
			count(len(c.Snap.Profiler.DatabasesProfiled), "database", "databases"))
	}
	return bf("natural-hint-values", Warning,
		"Queries pass $natural values other than 1 or -1. From 7.0 such values return an error.",
		profilerItems("operations use $natural with a value other than 1/-1", e),
		"Change the hints and sorts to {$natural: 1} or {$natural: -1}.")
}

func checkSetClusterParameter(c *Context) []Finding {
	if n := c.Snap.ActiveSetClusterParameter; n > 0 {
		return bf("setclusterparameter-active", Warning,
			fmt.Sprintf("%s running when the snapshot was taken. Active setClusterParameter operations prevent setFeatureCompatibilityVersion from completing.", count(n, "setClusterParameter operation was", "setClusterParameter operations were")),
			nil, "Let them finish before setting the featureCompatibilityVersion.")
	}
	return c.Checked("no setClusterParameter operation was running when the snapshot was taken.")
}

// ---------------------------------------------------------------- 8.0

func checkNullUndefined(c *Context) []Finding {
	var items []string
	if e := profilerEvidence(c.Snap, snapshot.EvidenceNullEq); e != nil {
		items = append(items, profilerItems("queries match on null", e)...)
	}
	dc := c.Snap.DeepCheck
	if dc == nil || !dc.Ran {
		return bf("null-undefined-match", Warning,
			"This change affects queries that match null on documents storing the deprecated BSON undefined type. Stored documents were not inspected.",
			items, "Run ucfm check again with --deep-check to sample documents for undefined values.")
	}
	var found []string
	for _, u := range dc.Undefined {
		found = append(found, fmt.Sprintf("%s: %s (%s in the sample)", u.NS, u.Path, plural64(int64(u.Count), "document", "documents")))
	}
	if len(found) == 0 {
		return c.Checked("the --deep-check sample of %s from %s has no BSON undefined value.",
			count(dc.Documents, "document", "documents"), count(dc.Collections, "collection", "collections"))
	}
	sort.Strings(found)
	return bf("null-undefined-match", Warning,
		fmt.Sprintf("Sampled documents store the deprecated BSON undefined type (%s from %s sampled). From 8.0, equality matches on null no longer match undefined values.", count(dc.Documents, "document", "documents"), count(dc.Collections, "collection", "collections")),
		append(found, items...),
		"Replace undefined values with null (or remove the fields) before upgrading, or change queries that rely on {field: null} matching them.")
}

func checkMajorityAck(c *Context) []Finding {
	d := c.Snap.DefaultRWConcern
	if d == nil {
		return c.NotChecked("To run this check, collect the snapshot with this version of ucfm from the live deployment (default read/write concern is missing).")
	}
	wc := strings.TrimSpace(string(d.WriteConcern))
	if wc == "" || wc == "null" {
		wc = `{"w": "majority"} (implicit default)`
	}
	src := d.WriteConcernSource
	if src == "" {
		src = "unknown"
	}
	return bf("majority-write-ack", Notice,
		"Writes with \"majority\" write concern are acknowledged once a majority of members have written the oplog entry, instead of after they applied it. A read on a secondary right after an acknowledged write may not see it yet.",
		[]string{fmt.Sprintf("cluster-wide default write concern: %s (source: %s)", wc, src)},
		"For read-your-writes on secondaries, use causally consistent sessions or read concern \"majority\".")
}

func checkDirectShardOps(c *Context) []Finding {
	if !sharded(c.Snap) {
		return c.NotApplicable(notSharded)
	}
	items, ok, reason := directShardClients(c)
	if !ok {
		return c.NotChecked(reason)
	}
	if len(items) == 0 {
		return c.Checked("no application driver is connected directly to %s.", shardMembersPhrase(c.Snap))
	}
	return bf("direct-shard-operations", Warning,
		"Applications are connected directly to shard members. From 8.0 many commands no longer run directly on a shard member unless you connect through mongos or hold the maintenance-only directShardOperations role.",
		items, "Point these applications at mongos.")
}

func checkHedgedReads(c *Context) []Finding {
	if !sharded(c.Snap) {
		return c.NotApplicable(notSharded)
	}
	var h counterHit
	for _, n := range c.Snap.Nodes {
		if n.Role != snapshot.RoleMongos {
			continue
		}
		var v int64
		if n.Hedging != nil {
			v = n.Hedging.NumTotalHedgedOperations
		}
		h.add(n, v, n.Hedging != nil)
	}
	if !h.known {
		return c.NotChecked(needCounters)
	}
	if h.total == 0 {
		return c.Checked("%s performed no hedged read since startup %s ago.", count(h.nodes, "mongos", "mongos"), humanDuration(h.uptime))
	}
	return bf("hedged-reads-default", Notice,
		"The routers performed hedged reads. From 8.0 hedged reads are deprecated and reads with read preference nearest no longer hedge by default.",
		[]string{h.describe("hedged reads")}, "If you rely on hedging for latency, review read preference settings after the upgrade.")
}

func checkBucketOrphans(c *Context) []Finding {
	if !dataCollected(c.Snap) {
		return c.NotChecked(needData)
	}
	var items []string
	buckets := 0
	for _, db := range c.Snap.Data.Databases {
		buckets += len(db.BucketCollections)
		ts := map[string]bool{}
		for _, coll := range db.Collections {
			if coll.Type == "timeseries" {
				ts[coll.Name] = true
			}
		}
		for _, b := range db.BucketCollections {
			if !ts[strings.TrimPrefix(b, "system.buckets.")] {
				items = append(items, db.Name+"."+b)
			}
		}
	}
	if len(items) == 0 {
		if buckets == 0 {
			return c.Checked("no system.buckets collection exists in the %s listed.", count(len(c.Snap.Data.Databases), "database", "databases"))
		}
		if buckets == 1 {
			return c.Checked("the only system.buckets collection belongs to a time series collection.")
		}
		return c.Checked("all %d system.buckets collections belong to a time series collection.", buckets)
	}
	sort.Strings(items)
	return bf("system-buckets-orphans", Warning,
		"These system.buckets collections have no matching time-series collection. Upgrading to 8.0.4 or earlier requires dropping or renaming them first; from 8.0.5 they must be dropped or renamed after the upgrade.",
		items, "Drop or rename them (after checking they hold nothing you need).")
}

func checkCompact(c *Context) []Finding {
	h := cmdCounter(c.Snap, "compact", nil)
	if !h.known {
		return c.NotChecked(needCounters)
	}
	if h.total == 0 {
		return c.Checked("%s", h.unused("compact", "run"))
	}
	return bf("compact-concurrency", Notice,
		"compact is used. From 8.0, running several compact commands concurrently on the same collection returns an error.",
		[]string{h.describe("compact")}, "Make sure maintenance scripts run one compact per collection at a time.")
}

// ---------------------------------------------------------------- 8.3

func checkDDLViaMongos(c *Context) []Finding {
	if !sharded(c.Snap) {
		return c.NotApplicable(notSharded)
	}
	items, ok, reason := directShardClients(c)
	if !ok {
		return c.NotChecked(reason)
	}
	ap := cmdCounter(c.Snap, "applyOps", func(n snapshot.Node) bool { return n.ShardName != "" && !n.IsConfig })
	if ap.total > 0 {
		items = append(items, ap.describe("applyOps on shard members"))
	}
	if len(items) == 0 {
		msg := "no application driver is connected directly to " + shardMembersPhrase(c.Snap)
		if ap.known {
			msg += fmt.Sprintf(", and applyOps was not run on them since startup %s ago", humanDuration(ap.uptime))
		}
		return c.Checked("%s.", msg)
	}
	return bf("ddl-via-mongos", Warning,
		"Applications connect directly to shard members, or applyOps runs on them. From 8.3, DDL operations and applyOps can only run through mongos on sharded clusters.",
		items, "Run DDL (create/drop/rename collections, indexes, collMod) and applyOps through mongos.")
}

func check2dsphereV4(c *Context) []Finding {
	if !dataCollected(c.Snap) {
		return c.NotChecked(needData)
	}
	ix := indexesOfType(c.Snap, "2dsphere")
	if len(ix) == 0 {
		return c.Checked("no 2dsphere index exists in the %s listed.", count(collectionCount(c.Snap), "collection", "collections"))
	}
	return bf("2dsphere-index-v4", Notice,
		fmt.Sprintf("The deployment has %d 2dsphere index(es). From 8.3 new 2dsphere indexes use version 4, and they must be dropped before the featureCompatibilityVersion can go below 8.3.", len(ix)),
		ix, "If you may need to downgrade, create new 2dsphere indexes with {2dsphereIndexVersion: 3} until you are sure.")
}

func checkFTDCSize(c *Context) []Finding {
	// Members that leave the parameter at their build's default: 200 MiB up
	// to 8.0.9, 250 MiB from 8.0.10 (SERVER-101001), 500 MiB from 8.3.
	byValue := map[int][]string{}
	known := false
	reporting := 0
	for _, n := range c.Snap.Nodes {
		raw, ok := n.Parameters["diagnosticDataCollectionDirectorySizeMB"]
		if !ok {
			continue
		}
		known = true
		reporting++
		if _, set := n.StartupParameters["diagnosticDataCollectionDirectorySizeMB"]; set {
			continue
		}
		if mb, err := strconv.Atoi(jsonScalar(raw)); err == nil && mb < 500 {
			byValue[mb] = append(byValue[mb], n.Host)
		}
	}
	if !known {
		return c.NotChecked(needCounters)
	}
	if len(byValue) == 0 {
		return c.Checked("diagnosticDataCollectionDirectorySizeMB is set at startup or already 500 MiB or more on %s.", members(reporting))
	}
	values := make([]int, 0, len(byValue))
	for mb := range byValue {
		values = append(values, mb)
	}
	sort.Ints(values)
	var items []string
	for _, mb := range values {
		items = append(items, fmt.Sprintf("using the default of %d MiB: %s", mb, summarizeHosts(byValue[mb])))
	}
	if h := c.Snap.Host; h != nil && h.DBPath != "" {
		items = append(items, fmt.Sprintf("%s: %d MB free on the dbPath filesystem (diagnostic.data lives under dbPath)", hostLabel(h), h.DBPathFreeMB))
	}
	return bf("ftdc-directory-size", Notice,
		"The default diagnosticDataCollectionDirectorySizeMB grows to 500 MiB in 8.3 (from 200 MiB, or 250 MiB since 8.0.10), so each member's diagnostic.data directory can use up to 300 MiB more disk.",
		items, "Make sure the dbPath filesystem has room, or set diagnosticDataCollectionDirectorySizeMB explicitly.")
}

func checkTrimLimits(c *Context) []Finding {
	ops := []string{"$trim", "$ltrim", "$rtrim"}
	items, checked := usageEvidence(c.Snap, "expressions", ops)
	if dataCollected(c.Snap) {
		pipelines(c.Snap, func(ns, what string, raw json.RawMessage) {
			if n := longestTrimChars(raw); n > 4096 {
				items = append(items, fmt.Sprintf("%s: chars of %d characters in %s (limit 4096)", ns, n, what))
			}
		})
		if ix := indexesOfType(c.Snap, "text"); len(ix) > 0 {
			items = append(items, fmt.Sprintf("%d text index(es): text search ($text with OR terms) is limited to 100 MB of memory unless allowDiskUse is true", len(ix)))
		}
	}
	if len(items) > 0 {
		return bf("trim-limits", Notice,
			"From 8.3 the chars argument of $trim, $ltrim and $rtrim is limited to 4096 characters, and the TextOr stage of text search is limited to 100 MB of memory (it spills with allowDiskUse, otherwise fails).",
			items, "Keep chars under 4096 characters; set allowDiskUse on large text searches.")
	}
	if !checked {
		return c.NotChecked(needCounters)
	}
	msg := strings.TrimSuffix(usageSummary(c.Snap, "expressions", ops, "$trim, $ltrim and $rtrim"), ".")
	if dataCollected(c.Snap) {
		msg += ", and there is no text index"
	}
	return c.Checked("%s.", msg)
}

// longestTrimChars returns the longest literal chars string of a
// $trim/$ltrim/$rtrim in a pipeline or validator.
func longestTrimChars(raw json.RawMessage) int {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return 0
	}
	best := 0
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if k == "$trim" || k == "$ltrim" || k == "$rtrim" {
					if args, ok := val.(map[string]any); ok {
						if s, ok := args["chars"].(string); ok && len([]rune(s)) > best {
							best = len([]rune(s))
						}
					}
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
	return best
}

func checkDateAddPreEpoch(c *Context) []Finding {
	items, checked := usageEvidence(c.Snap, "expressions", []string{"$dateAdd", "$dateSubtract"})
	if len(items) > 0 {
		return bf("dateadd-preepoch", Notice,
			"$dateAdd or $dateSubtract is in use. From 8.3, when the unit is not millisecond and the input date is before 1970-01-01, the result is one second greater than before (this also affects $setWindowFields and $densify time calculations).",
			items, "Check calculations on dates before 1970.")
	}
	if !checked {
		return c.NotChecked(needCounters)
	}
	return c.Checked("%s", usageSummary(c.Snap, "expressions", []string{"$dateAdd", "$dateSubtract"}, "$dateAdd and $dateSubtract"))
}

// ---------------------------------------------------------------- 9.0

func checkChangeStreams(c *Context) []Finding {
	h := stageCounter(c.Snap, "$changeStream")
	if !h.known {
		return c.NotChecked(needCounters)
	}
	if h.total == 0 {
		return c.Checked("%s", h.unused("$changeStream", "used"))
	}
	return bf("changestream-getmore-errors", Warning,
		"Change streams are in use. From 9.0, a change stream opened with read preference primary or secondary returns the resumable error InterruptedDueToReplStateChange (11602) from getMore after a replica set state change. Drivers and mongos resume automatically; manual getMore loops must resume with resumeAfter.",
		[]string{h.describe("$changeStream")}, "Check that change stream consumers use a current driver or resume on error 11602.")
}

func check2dsphereCodes(c *Context) []Finding {
	if !dataCollected(c.Snap) {
		return c.NotChecked(needData)
	}
	ix := indexesOfType(c.Snap, "2dsphere")
	if len(ix) == 0 {
		return c.Checked("no 2dsphere index exists in the %s listed.", count(collectionCount(c.Snap), "collection", "collections"))
	}
	return bf("2dsphere-error-codes", Notice,
		"The deployment has 2dsphere indexes. From 9.0 key-extraction failures return error codes 510 (GeoKeyExtractionFailed) and 511 (GeoKeyExtractionFailedTimeseries) instead of 16755, 16756, 183934 and 183493.",
		ix, "Update application code that matches on the old error codes.")
}

func checkRenameLocks(c *Context) []Finding {
	if c.Snap.Topology.Kind != snapshot.KindReplicaSet {
		return c.NotApplicable("the change affects replica sets only")
	}
	h := cmdCounter(c.Snap, "renameCollection", nil)
	if !h.known {
		return c.NotChecked(needCounters)
	}
	if h.total == 0 {
		return c.Checked("%s", h.unused("renameCollection", "run"))
	}
	return bf("rename-cross-db-locks", Notice,
		"renameCollection is used. From 9.0, renaming a collection across databases on a replica set holds an exclusive lock on the source and target collections for the whole operation, blocking writes and DDL on both.",
		[]string{h.describe("renameCollection")}, "Schedule cross-database renames for quiet periods.")
}

func checkQueryStats(c *Context) []Finding {
	h := stageCounter(c.Snap, "$queryStats")
	if !h.known {
		return c.NotChecked(needCounters)
	}
	if h.total == 0 {
		return c.Checked("%s", h.unused("$queryStats", "used"))
	}
	return bf("querystats-keys", Notice,
		"$queryStats is in use. From 9.0 the key and keyHash of aggregate commands that set allowPartialResults change (queryShapeHash does not).",
		[]string{h.describe("$queryStats")}, "Update tools that match query statistics on keyHash.")
}

func checkMultikey(c *Context) []Finding {
	return bf("multikey-query-killed", Notice,
		"This cannot be verified from server state. From 9.0, a query can fail with QueryKilledError when an indexed field it references becomes multikey (an insert or update stores an array in it) while the query runs.",
		nil, "Make sure applications retry queries that fail with QueryKilledError, especially on indexed fields that can receive array values.")
}
