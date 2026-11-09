package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// psmdbVersion matches PSMDB build versions such as "8.0.12-4".
var psmdbVersion = regexp.MustCompile(`^\d+\.\d+\.\d+-\d+$`)

// addNode collects per-process facts from the node the client points at.
func (c *Collector) addNode(ctx context.Context, cl *mongo.Client, host, shard string, isConfig bool) {
	if c.seen[host] {
		return
	}
	c.seen[host] = true
	c.opts.Log("collecting node %s", host)
	scope := "node:" + host
	n := snapshot.Node{Host: host, ShardName: shard, IsConfig: isConfig}

	hello, err := c.run(ctx, cl, "admin", bson.D{{Key: "hello", Value: 1}})
	if err != nil {
		// Unreachable: one error is enough, and the node is not listed.
		c.snap.AddError(scope, "connect", err)
		return
	}
	{
		n.ReplSet = str(hello, "setName")
		switch {
		case str(hello, "msg") == "isdbgrid":
			n.Role = snapshot.RoleMongos
		case boolean(hello, "arbiterOnly"):
			n.Role = snapshot.RoleArbiter
		case boolean(hello, "isWritablePrimary") && n.ReplSet != "":
			n.Role = snapshot.RolePrimary
		case boolean(hello, "secondary"):
			n.Role = snapshot.RoleSecondary
		case n.ReplSet == "":
			n.Role = snapshot.RoleStandalone
		default:
			n.Role = "OTHER"
		}
	}

	if bi, err := c.run(ctx, cl, "admin", bson.D{{Key: "buildInfo", Value: 1}}); err != nil {
		c.snap.AddError(scope, "buildInfo", err)
	} else {
		n.Version = str(bi, "version")
		n.GitVersion = str(bi, "gitVersion")
		n.Modules = strArray(bi, "modules")
		n.PSMDBVersion = str(bi, "psmdbVersion")
		switch {
		case n.PSMDBVersion != "" || psmdbVersion.MatchString(n.Version):
			n.Flavor = "psmdb"
		case contains(n.Modules, "enterprise"):
			n.Flavor = "enterprise"
		default:
			n.Flavor = "community"
		}
	}

	// Arbiters reject most authenticated reads; buildInfo/hello is enough.
	if n.Role == snapshot.RoleArbiter {
		c.snap.Nodes = append(c.snap.Nodes, n)
		return
	}

	if opts, err := c.run(ctx, cl, "admin", bson.D{{Key: "getCmdLineOpts", Value: 1}}); err != nil {
		c.snap.AddError(scope, "getCmdLineOpts", err)
	} else {
		n.Argv = strArray(opts, "argv")
		parsed := doc(opts, "parsed")
		n.Options = map[string]json.RawMessage{}
		flatten(parsed, "", n.Options, map[string]bool{"setParameter": true})
		if sp, ok := n.Options["setParameter"]; ok {
			delete(n.Options, "setParameter")
			n.StartupParameters = map[string]json.RawMessage{}
			_ = json.Unmarshal(sp, &n.StartupParameters)
		}
		if cf, ok := n.Options["config"]; ok {
			n.ConfigFile = trimJSONString(cf)
			delete(n.Options, "config")
		}
	}

	if params, err := c.run(ctx, cl, "admin", bson.D{{Key: "getParameter", Value: "*"}}); err != nil {
		c.snap.AddError(scope, "getParameter", err)
	} else if elems, err := params.Elements(); err == nil {
		n.Parameters = map[string]json.RawMessage{}
		for _, e := range elems {
			if e.Key() == "ok" || strings.HasPrefix(e.Key(), "$") || e.Key() == "operationTime" {
				continue
			}
			n.Parameters[e.Key()] = relaxedJSON(e.Value())
		}
		if fcv := doc(params, "featureCompatibilityVersion"); fcv != nil {
			n.FCV = str(fcv, "version")
		}
	}

	if ss, err := c.run(ctx, cl, "admin", bson.D{{Key: "serverStatus", Value: 1}}); err != nil {
		c.snap.AddError(scope, "serverStatus", err)
	} else {
		n.UptimeSeconds = num(ss, "uptime")
		n.StorageEngine = str(ss, "storageEngine", "name")
		if conn := doc(ss, "connections"); conn != nil {
			n.Connections = &snapshot.Connections{Current: num(conn, "current"), Available: num(conn, "available")}
		}
		n.CommandCounters = commandCounters(doc(ss, "metrics", "commands"))
		n.TCMalloc = tcmallocInfo(doc(ss, "tcmalloc"))
		n.AggStageCounters = counterMap(doc(ss, "metrics", "aggStageCounters"))
		if oc := doc(ss, "metrics", "operatorCounters"); oc != nil {
			n.OperatorCounters = map[string]map[string]int64{}
			for _, g := range []string{"expressions", "match", "groupAccumulators", "windowAccumulators"} {
				if m := counterMap(doc(oc, g)); len(m) > 0 {
					n.OperatorCounters[g] = m
				}
			}
		}
		if hm := doc(ss, "hedgingMetrics"); hm != nil {
			n.Hedging = &snapshot.HedgingMetrics{
				NumTotalOperations:                num(hm, "numTotalOperations"),
				NumTotalHedgedOperations:          num(hm, "numTotalHedgedOperations"),
				NumAdvantageouslyHedgedOperations: num(hm, "numAdvantageouslyHedgedOperations"),
			}
		}
		if od := doc(ss, "opcountersDeprecated"); od != nil {
			n.OpcountersDeprecated = map[string]int64{}
			if elems, err := od.Elements(); err == nil {
				for _, e := range elems {
					if v, ok := e.Value().AsInt64OK(); ok {
						n.OpcountersDeprecated[e.Key()] = v
					}
				}
			}
		}
	}

	if lg, err := c.run(ctx, cl, "admin", bson.D{{Key: "getLog", Value: "startupWarnings"}}); err != nil {
		c.snap.AddError(scope, "getLog", err)
	} else {
		for _, w := range strArray(lg, "log") {
			if w = strings.TrimSpace(w); w != "" {
				n.StartupWarnings = append(n.StartupWarnings, w)
			}
		}
	}

	if hi, err := c.run(ctx, cl, "admin", bson.D{{Key: "hostInfo", Value: 1}}); err != nil {
		c.snap.AddError(scope, "hostInfo", err)
	} else {
		n.HostInfo = snapshot.HostInfoCmd{
			Hostname:      str(hi, "system", "hostname"),
			CPUArch:       str(hi, "system", "cpuArch"),
			NumCores:      int(num(hi, "system", "numCores")),
			MemSizeMB:     num(hi, "system", "memSizeMB"),
			NUMAEnabled:   boolean(hi, "system", "numaEnabled"),
			OSType:        str(hi, "os", "type"),
			OSName:        str(hi, "os", "name"),
			OSVersion:     str(hi, "os", "version"),
			LibcVersion:   str(hi, "extra", "libcVersion"),
			KernelVersion: str(hi, "extra", "kernelVersion"),
			CPUFeatures:   str(hi, "extra", "cpuFeatures"),
			MemLimitMB:    num(hi, "system", "memLimitMB"),
		}
		// config.mongos and replica set configs may name this process by
		// its hostname rather than the address we used.
		// hostInfo omits the port when it is the default one.
		if hn := n.HostInfo.Hostname; hn != "" {
			c.seen[hn] = true
			if !strings.Contains(hn, ":") {
				if i := strings.LastIndex(host, ":"); i >= 0 {
					c.seen[hn+host[i:]] = true
				}
			}
		}
	}

	if n.ReplSet != "" && (n.Role == snapshot.RolePrimary || n.Role == snapshot.RoleSecondary) {
		n.Oplog = c.oplogInfo(ctx, cl, scope)
	}

	// Profiler evidence lives on each data-bearing member.
	if n.Role != snapshot.RoleMongos && n.Role != snapshot.RoleArbiter {
		c.collectProfiler(ctx, cl, host, scope)
	}

	// On sharded clusters, applications should connect only through mongos:
	// record application connections that reach shard members directly. On a
	// replica set, applications may connect to any member (secondary reads),
	// so every data-bearing member is inspected.
	shardMember := shard != "" && !isConfig && c.snap.Topology.Kind == snapshot.KindSharded
	rsMember := shard == "" && c.snap.Topology.Kind == snapshot.KindReplicaSet &&
		(n.Role == snapshot.RolePrimary || n.Role == snapshot.RoleSecondary)
	if shardMember || rsMember {
		if cds, err := c.clientDrivers(ctx, cl, host); err != nil {
			c.snap.AddError(scope, "$currentOp", err)
		} else {
			n.Clients = cds
		}
	}

	c.snap.Nodes = append(c.snap.Nodes, n)
}

// counterMap reads a flat {name: number} counter document, such as
// metrics.aggStageCounters or a metrics.operatorCounters group. Zero
// counters are kept so "used 0 times" is distinguishable from "unknown".
func counterMap(r bson.Raw) map[string]int64 {
	if r == nil {
		return nil
	}
	elems, err := r.Elements()
	if err != nil {
		return nil
	}
	out := map[string]int64{}
	for _, e := range elems {
		if n, ok := e.Value().AsInt64OK(); ok {
			out[e.Key()] = n
		} else if f, ok := e.Value().DoubleOK(); ok {
			out[e.Key()] = int64(f)
		}
	}
	return out
}

// commandCounters walks metrics.commands. Most entries are
// {name: {failed, total}}; some nest further (e.g. update.arrayFilters),
// and "<UNKNOWN>" is a plain counter that is ignored.
func commandCounters(r bson.Raw) map[string]int64 {
	if r == nil {
		return nil
	}
	out := map[string]int64{}
	elems, err := r.Elements()
	if err != nil {
		return out
	}
	for _, e := range elems {
		d, ok := e.Value().DocumentOK()
		if !ok {
			continue
		}
		if v, err := d.LookupErr("total"); err == nil {
			if n, ok := v.AsInt64OK(); ok {
				out[e.Key()] = n
			}
		}
	}
	return out
}

func trimJSONString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// redact hides the password part of a connection string.
func redact(uri string) string {
	re := regexp.MustCompile(`(mongodb(?:\+srv)?://[^:/@]+):[^/]*@`)
	return re.ReplaceAllString(uri, "$1:***@")
}

// oplogInfo reads the oplog size and the time span it covers (the oplog
// window). Needs read access to local.oplog.rs (clusterMonitor has it);
// failures are recorded, never guessed.
func (c *Collector) oplogInfo(ctx context.Context, cl *mongo.Client, scope string) *snapshot.OplogInfo {
	stats, err := c.run(ctx, cl, "local", bson.D{{Key: "collStats", Value: "oplog.rs"}})
	if err != nil {
		c.snap.AddError(scope, "collStats local.oplog.rs", err)
		return nil
	}
	o := &snapshot.OplogInfo{MaxSizeMB: num(stats, "maxSize") / (1 << 20), UsedMB: num(stats, "size") / (1 << 20)}
	// Each member's own oplog: read the member cl points at.
	edge := func(dir int) (time.Time, error) {
		cctx, cancel := c.deadline(ctx)
		defer cancel()
		cur, err := cursorCmd(cctx, cl.Database("local"), findCmd("oplog.rs", nil,
			bson.D{{Key: "ts", Value: 1}}, bson.D{{Key: "$natural", Value: dir}}, 1), nodeReadPref())
		if err != nil {
			return time.Time{}, err
		}
		defer func() { _ = cur.Close(cctx) }()
		if !cur.Next(cctx) {
			if err := cur.Err(); err != nil {
				return time.Time{}, err
			}
			return time.Time{}, fmt.Errorf("the oplog is empty")
		}
		raw := cur.Current
		if sec, _, ok := raw.Lookup("ts").TimestampOK(); ok {
			return time.Unix(int64(sec), 0).UTC(), nil
		}
		return time.Time{}, fmt.Errorf("oplog entry without ts")
	}
	if o.First, err = edge(1); err != nil {
		c.snap.AddError(scope, "find local.oplog.rs", err)
		return o
	}
	if o.Last, err = edge(-1); err != nil {
		c.snap.AddError(scope, "find local.oplog.rs", err)
		return o
	}
	o.WindowHours = o.Last.Sub(o.First).Hours()
	return o
}

// tcmallocInfo reads the per-CPU cache state of serverStatus tcmalloc. Only
// the 8.0+ TCMalloc reports usingPerCPUCaches; older servers return nil.
func tcmallocInfo(tc bson.Raw) *snapshot.TCMallocInfo {
	if tc == nil {
		return nil
	}
	v, err := tc.LookupErr("usingPerCPUCaches")
	if err != nil {
		return nil
	}
	using, ok := v.BooleanOK()
	if !ok {
		return nil
	}
	return &snapshot.TCMallocInfo{
		UsingPerCPUCaches:       using,
		MaxPerCPUCacheSizeBytes: num(tc, "maxPerCPUCacheSizeBytes"),
		CPUFreeBytes:            num(tc, "tcmalloc", "cpu_free"),
	}
}
