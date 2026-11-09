// Package collect builds a snapshot from a live deployment using read-only
// commands only. Every failure is recorded in the snapshot instead of aborting,
// so a partially privileged user still gets a useful (and honest) report.
package collect

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Options control what is collected.
type Options struct {
	URI            string
	EntryOnly      bool // do not fan out to members / shards
	MaxNamespaces  int  // stop listing collections after this many (0 = default)
	SkipData       bool // skip databases/collections/indexes
	SkipSecurity   bool // skip users/roles
	DeepCheck      bool // sample documents of every collection (reads data)
	CommandTimeout time.Duration
	ToolVersion    string
	Log            func(format string, args ...any)
}

const defaultMaxNamespaces = 20000

// Collector holds the entry connection.
type Collector struct {
	opts  Options
	entry *mongo.Client
	snap  *snapshot.Snapshot
	seen  map[string]bool // hosts already collected as nodes
}

// Run connects, collects and returns the snapshot. Only a failure to reach
// the entry host is fatal.
func Run(ctx context.Context, o Options) (*snapshot.Snapshot, error) {
	if o.MaxNamespaces == 0 {
		o.MaxNamespaces = defaultMaxNamespaces
	}
	if o.CommandTimeout == 0 {
		o.CommandTimeout = 60 * time.Second
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}

	// --entry-only inspects exactly the node in --uri: connect to it directly
	// instead of following replica set discovery to the primary.
	var entryHosts []string
	if o.EntryOnly && !strings.HasPrefix(o.URI, "mongodb+srv://") {
		if h := firstHost(o.URI); h != "entry" {
			entryHosts = []string{h}
		}
	}
	client, err := connect(o.URI, entryHosts, "", len(entryHosts) > 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := client.Ping(pctx, readpref.PrimaryPreferred()); err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", redact(o.URI), err)
	}

	c := &Collector{
		opts:  o,
		entry: client,
		seen:  map[string]bool{},
		snap: &snapshot.Snapshot{
			SchemaVersion: snapshot.SchemaVersion,
			CollectedAt:   time.Now().UTC(),
			ToolVersion:   o.ToolVersion,
			Collection: snapshot.CollectionInfo{
				EntryOnly:    o.EntryOnly,
				SkipData:     o.SkipData,
				SkipSecurity: o.SkipSecurity,
				DeepCheck:    o.DeepCheck,
				ConnTemplate: ConnTemplate(o.URI),
			},
		},
	}
	c.collect(ctx)
	return c.snap, nil
}

func (c *Collector) collect(ctx context.Context) {
	hello, err := c.run(ctx, c.entry, "admin", bson.D{{Key: "hello", Value: 1}})
	if err != nil {
		// Very old servers only know isMaster; supported versions all have hello.
		c.snap.AddError("entry", "hello", err)
		return
	}
	c.snap.EntryHost = str(hello, "me")
	if c.snap.EntryHost == "" { // mongos and standalones do not report "me"
		c.snap.EntryHost = firstHost(c.opts.URI)
	}

	switch {
	case str(hello, "msg") == "isdbgrid":
		c.snap.Topology.Kind = snapshot.KindSharded
		c.collectSharded(ctx)
	case str(hello, "setName") != "":
		c.snap.Topology.Kind = snapshot.KindReplicaSet
		rs := c.collectReplSet(ctx, c.entry, "replset", "")
		if !c.opts.EntryOnly {
			c.collectMembers(ctx, rs, "")
		} else {
			c.addNode(ctx, c.entry, c.snap.EntryHost, "", false)
		}
	default:
		c.snap.Topology.Kind = snapshot.KindStandalone
		c.addNode(ctx, c.entry, c.snap.EntryHost, "", false)
	}

	c.collectRWConcern(ctx)
	c.collectActiveSetClusterParameter(ctx)

	if !c.opts.SkipData {
		c.collectData(ctx)
		if c.snap.Sharding != nil {
			c.collectShardKeys(ctx, c.snap.Sharding)
		}
	}
	if c.opts.DeepCheck {
		c.collectDeepCheck(ctx)
	}
	if !c.opts.SkipSecurity {
		c.collectSecurity(ctx)
	}
	c.collectClients(ctx)

	sort.Slice(c.snap.Nodes, func(i, j int) bool { return c.snap.Nodes[i].Host < c.snap.Nodes[j].Host })
}

// collectReplSet reads replSetGetStatus/replSetGetConfig through client and
// appends the set to the topology.
func (c *Collector) collectReplSet(ctx context.Context, client *mongo.Client, role, shard string) *snapshot.ReplSet {
	status, err := c.run(ctx, client, "admin", bson.D{{Key: "replSetGetStatus", Value: 1}})
	if err != nil {
		c.snap.AddError("replset:"+shard, "replSetGetStatus", err)
		return nil
	}
	cfgDoc, err := c.run(ctx, client, "admin", bson.D{{Key: "replSetGetConfig", Value: 1}})
	if err != nil {
		c.snap.AddError("replset:"+shard, "replSetGetConfig", err)
	}

	rs := snapshot.ReplSet{Name: str(status, "set"), Role: role}
	cfgByHost := map[string]bson.Raw{}
	for _, m := range docArray(cfgDoc, "config", "members") {
		cfgByHost[str(m, "host")] = m
	}

	var primaryOptime time.Time
	statusMembers := docArray(status, "members")
	for _, m := range statusMembers {
		if str(m, "stateStr") == snapshot.RolePrimary {
			primaryOptime = timeVal(m, "optimeDate")
		}
	}
	for _, m := range statusMembers {
		host := str(m, "name")
		mem := snapshot.Member{
			Host:       host,
			State:      str(m, "stateStr"),
			Health:     flt(m, "health"),
			OptimeDate: timeVal(m, "optimeDate"),
		}
		if cm, ok := cfgByHost[host]; ok {
			mem.Priority = flt(cm, "priority")
			mem.Votes = int(num(cm, "votes"))
			mem.ArbiterOnly = boolean(cm, "arbiterOnly")
			mem.Hidden = boolean(cm, "hidden")
			mem.Delayed = num(cm, "secondaryDelaySecs") > 0
		}
		if !primaryOptime.IsZero() && !mem.OptimeDate.IsZero() && mem.State == snapshot.RoleSecondary {
			mem.LagSeconds = primaryOptime.Sub(mem.OptimeDate).Seconds()
		}
		rs.Members = append(rs.Members, mem)
	}
	c.snap.Topology.ReplSets = append(c.snap.Topology.ReplSets, rs)
	return &c.snap.Topology.ReplSets[len(c.snap.Topology.ReplSets)-1]
}

// collectMembers connects directly to every member of rs and collects it.
func (c *Collector) collectMembers(ctx context.Context, rs *snapshot.ReplSet, shard string) {
	if rs == nil {
		return
	}
	isConfig := rs.Role == "config"
	for _, m := range rs.Members {
		if c.seen[m.Host] {
			continue
		}
		if m.Health == 0 {
			c.snap.AddError("node:"+m.Host, "connect", fmt.Errorf("member is not healthy (state %s); skipped", m.State))
			continue
		}
		cl, err := connect(c.opts.URI, []string{m.Host}, "", true)
		if err != nil {
			c.snap.AddError("node:"+m.Host, "connect", err)
			continue
		}
		c.addNode(ctx, cl, m.Host, shard, isConfig)
		_ = cl.Disconnect(context.Background())
	}
}

func (c *Collector) collectSharded(ctx context.Context) {
	si := &snapshot.ShardingInfo{}
	c.snap.Sharding = si

	if res, err := c.run(ctx, c.entry, "admin", bson.D{{Key: "listShards", Value: 1}}); err != nil {
		c.snap.AddError("sharding", "listShards", err)
	} else {
		for _, s := range docArray(res, "shards") {
			si.Shards = append(si.Shards, snapshot.Shard{ID: str(s, "_id"), Host: str(s, "host"), Draining: boolean(s, "draining"), MaxSizeMB: num(s, "maxSize")})
		}
	}
	if res, err := c.run(ctx, c.entry, "admin", bson.D{{Key: "balancerStatus", Value: 1}}); err != nil {
		c.snap.AddError("sharding", "balancerStatus", err)
	} else {
		si.BalancerMode = str(res, "mode")
		si.BalancerRunning = boolean(res, "inBalancerRound")
	}

	cfgDB := c.entry.Database("config")
	if n, err := c.count(ctx, cfgDB.Collection("collections"), shardedCollectionsFilter); err != nil {
		c.snap.AddError("sharding", "config.collections", err)
	} else {
		si.ShardedCollections = int(n)
	}
	if n, err := c.count(ctx, cfgDB.Collection("reshardingOperations"), bson.D{}); err != nil {
		c.snap.AddError("sharding", "config.reshardingOperations", err)
	} else {
		si.ActiveResharding = int(n)
	}
	c.collectMongosList(ctx)
	c.collectBalancerSettings(ctx, si)

	// The entry mongos itself is a node.
	c.addNode(ctx, c.entry, c.snap.EntryHost, "", false)

	if c.opts.EntryOnly {
		return
	}

	// Config server replica set, from the mongos startup options.
	var cfgConn string
	for _, n := range c.snap.Nodes {
		if n.Role == snapshot.RoleMongos {
			if raw, ok := n.Options["sharding.configDB"]; ok {
				cfgConn = trimJSONString(raw)
			}
		}
	}
	if cfgConn != "" {
		c.collectShardRS(ctx, cfgConn, "config", "config")
	} else {
		c.snap.AddError("sharding", "getCmdLineOpts", fmt.Errorf("could not determine the config server replica set from sharding.configDB"))
	}
	for _, s := range si.Shards {
		c.collectShardRS(ctx, s.Host, "shard", s.ID)
	}
	// Other routers that are alive (pinged in the last 10 minutes).
	for _, m := range recentMongos(c.snap.Topology.Mongos, time.Now(), 10*time.Minute) {
		if c.seen[m.Host] {
			continue
		}
		cl, err := connect(c.opts.URI, []string{m.Host}, "", true)
		if err != nil {
			c.snap.AddError("node:"+m.Host, "connect", err)
			continue
		}
		c.addNode(ctx, cl, m.Host, "", false)
		_ = cl.Disconnect(context.Background())
	}
	for _, rs := range c.snap.Topology.ReplSets {
		if rs.Role != "shard" {
			continue
		}
		cl, err := connectRS(c.opts.URI, rs)
		if err != nil {
			continue
		}
		if n, err := c.count(ctx, cl.Database("config").Collection("migrationCoordinators"), bson.D{}); err == nil {
			si.ActiveMigrations += int(n)
		} else {
			c.snap.AddError("shard:"+rs.Name, "config.migrationCoordinators", err)
		}
		_ = cl.Disconnect(context.Background())
	}
}

func (c *Collector) collectShardRS(ctx context.Context, conn, role, shard string) {
	setName, hosts := hostsFromShardString(conn)
	cl, err := connect(c.opts.URI, hosts, setName, false)
	if err != nil {
		c.snap.AddError("shard:"+shard, "connect", err)
		return
	}
	defer func() { _ = cl.Disconnect(context.Background()) }()
	rs := c.collectReplSet(ctx, cl, role, shard)
	c.collectMembers(ctx, rs, shard)
}

// collectMongosList reads config.mongos through mongos. Sharding metadata is
// read from the primary so it is current.
func (c *Collector) collectMongosList(ctx context.Context) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, c.entry.Database("config"), findCmd("mongos", nil, nil, nil, 0), readpref.Primary())
	if err != nil {
		c.snap.AddError("sharding", "config.mongos", err)
		return
	}
	defer func() { _ = cur.Close(cctx) }()
	for cur.Next(cctx) {
		c.snap.Topology.Mongos = append(c.snap.Topology.Mongos, snapshot.Mongos{
			Host:    str(cur.Current, "_id"),
			Version: str(cur.Current, "mongoVersion"),
			Ping:    timeVal(cur.Current, "ping"),
			Up:      num(cur.Current, "up"),
		})
	}
}

// collectBalancerSettings reads config.settings chunksize and autosplit
// (sharding metadata: primary).
func (c *Collector) collectBalancerSettings(ctx context.Context, si *snapshot.ShardingInfo) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, c.entry.Database("config"), findCmd("settings",
		bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: bson.A{"chunksize", "autosplit"}}}}}, nil, nil, 0), readpref.Primary())
	if err != nil {
		c.snap.AddError("sharding", "config.settings", err)
		return
	}
	defer func() { _ = cur.Close(cctx) }()
	for cur.Next(cctx) {
		switch str(cur.Current, "_id") {
		case "chunksize":
			si.ChunkSizeMB = num(cur.Current, "value")
		case "autosplit":
			if v, err := cur.Current.LookupErr("enabled"); err == nil {
				if b, ok := v.BooleanOK(); ok {
					si.AutoSplit = &b
				}
			}
		}
	}
	if err := cur.Err(); err != nil {
		c.snap.AddError("sharding", "config.settings", err)
	}
}

// collectShardKeys reads the shard keys from config.collections through
// mongos (clusterMonitor grants read on the config database). At most
// MaxNamespaces entries are kept. Sharding metadata: primary.
func (c *Collector) collectShardKeys(ctx context.Context, si *snapshot.ShardingInfo) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, c.entry.Database("config"), findCmd("collections",
		bson.D{{Key: "_id", Value: bson.D{{Key: "$ne", Value: "config.system.sessions"}}}},
		bson.D{{Key: "_id", Value: 1}, {Key: "key", Value: 1}, {Key: "unique", Value: 1},
			{Key: "unsplittable", Value: 1}, {Key: "timeseriesFields", Value: 1}},
		bson.D{{Key: "_id", Value: 1}}, 0), readpref.Primary())
	if err != nil {
		c.snap.AddError("sharding", "config.collections", err)
		return
	}
	defer func() { _ = cur.Close(cctx) }()
	for cur.Next(cctx) {
		if len(si.Collections) >= c.opts.MaxNamespaces {
			si.CollectionsTruncated = true
			break
		}
		si.Collections = append(si.Collections, shardedCollection(cur.Current))
	}
	if err := cur.Err(); err != nil {
		c.snap.AddError("sharding", "config.collections", err)
		return
	}
	si.CollectionsRead = true
}

// shardedCollection converts one config.collections document.
func shardedCollection(r bson.Raw) snapshot.ShardedCollection {
	sc := snapshot.ShardedCollection{
		NS:           str(r, "_id"),
		Unique:       boolean(r, "unique"),
		Unsplittable: boolean(r, "unsplittable"),
		TimeField:    str(r, "timeseriesFields", "timeField"),
		MetaField:    str(r, "timeseriesFields", "metaField"),
	}
	if key := doc(r, "key"); key != nil {
		if elems, err := key.Elements(); err == nil {
			for _, e := range elems {
				sc.Key = append(sc.Key, snapshot.IndexKey{Field: e.Key(), Value: relaxedJSON(e.Value())})
			}
		}
	}
	return sc
}

// collectRWConcern reads the cluster-wide default read/write concern.
func (c *Collector) collectRWConcern(ctx context.Context) {
	res, err := c.run(ctx, c.entry, "admin", bson.D{{Key: "getDefaultRWConcern", Value: 1}})
	if err != nil {
		c.snap.AddError("entry", "getDefaultRWConcern", err)
		return
	}
	rw := &snapshot.DefaultRWConcern{
		WriteConcernSource: str(res, "defaultWriteConcernSource"),
		ReadConcernSource:  str(res, "defaultReadConcernSource"),
	}
	if v, err := res.LookupErr("defaultWriteConcern"); err == nil {
		rw.WriteConcern = relaxedJSON(v)
	}
	if v, err := res.LookupErr("defaultReadConcern"); err == nil {
		rw.ReadConcern = relaxedJSON(v)
	}
	c.snap.DefaultRWConcern = rw
}

// collectActiveSetClusterParameter counts setClusterParameter operations in
// progress on the entry node ($currentOp describes one node: no secondary).
func (c *Collector) collectActiveSetClusterParameter(ctx context.Context) {
	pipeline := bson.A{
		bson.D{{Key: "$currentOp", Value: bson.D{{Key: "allUsers", Value: true}}}},
		bson.D{{Key: "$match", Value: bson.D{{Key: "command.setClusterParameter", Value: bson.D{{Key: "$exists", Value: true}}}}}},
		bson.D{{Key: "$count", Value: "n"}},
	}
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, c.entry.Database("admin"), aggregateCmd("", pipeline), nodeReadPref())
	if err != nil {
		c.snap.AddError("entry", "$currentOp setClusterParameter", err)
		return
	}
	defer func() { _ = cur.Close(cctx) }()
	if cur.Next(cctx) {
		c.snap.ActiveSetClusterParameter = int(num(cur.Current, "n"))
	}
}

// run executes one read-only command on the member cl points at, with the
// per-command timeout (the driver sends it as maxTimeMS).
func (c *Collector) run(ctx context.Context, cl *mongo.Client, db string, cmd bson.D) (bson.Raw, error) {
	return c.runWith(ctx, cl, db, cmd, nodeReadPref())
}

// runWith is run with an explicit read preference.
func (c *Collector) runWith(ctx context.Context, cl *mongo.Client, db string, cmd bson.D, rp *readpref.ReadPref) (bson.Raw, error) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	return cl.Database(db).RunCommand(cctx, cmd, options.RunCmd().SetReadPreference(rp)).Raw()
}

func (c *Collector) count(ctx context.Context, coll *mongo.Collection, filter bson.D) (int64, error) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	return coll.CountDocuments(cctx, filter)
}

// connect builds a client from the user's URI (keeping credentials and TLS)
// and optionally overrides hosts / replica set / direct connection.
func connect(uri string, hosts []string, setName string, direct bool) (*mongo.Client, error) {
	o := options.Client().ApplyURI(uri).SetAppName("ucfm").SetServerSelectionTimeout(15 * time.Second)
	if testMonitor != nil {
		o.SetMonitor(testMonitor)
	}
	if len(hosts) > 0 {
		o.SetHosts(hosts)
		o.ReplicaSet = nil
		o.Direct = nil
		o.LoadBalanced = nil
		if setName != "" {
			o.SetReplicaSet(setName)
		}
		if direct {
			o.SetDirect(true)
		}
	}
	return mongo.Connect(o)
}

// firstHost returns the first seed host of a connection string.
func firstHost(uri string) string {
	o := options.Client().ApplyURI(uri)
	if len(o.Hosts) > 0 {
		return o.Hosts[0]
	}
	return "entry"
}

func connectRS(uri string, rs snapshot.ReplSet) (*mongo.Client, error) {
	var hosts []string
	for _, m := range rs.Members {
		hosts = append(hosts, m.Host)
	}
	return connect(uri, hosts, rs.Name, false)
}

// shardedCollectionsFilter counts the sharded collections in
// config.collections. On 8.0+ the config server also tracks unsharded
// (unsplittable) collections there, which are not sharded.
var shardedCollectionsFilter = bson.D{
	{Key: "_id", Value: bson.D{{Key: "$ne", Value: "config.system.sessions"}}},
	{Key: "unsplittable", Value: bson.D{{Key: "$ne", Value: true}}},
}
