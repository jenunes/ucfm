package collect

import (
	"context"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// skippedDBs are internal databases whose namespaces are not user data.
var skippedDBs = map[string]bool{"local": true, "config": true}

// collectData lists databases, collections, views and indexes through the
// entry connection. A secondary returns the same catalog, so on a replica set
// these listings use dataReadPref.
func (c *Collector) collectData(ctx context.Context) {
	rp := c.dataReadPref()
	res, err := c.runWith(ctx, c.entry, "admin", bson.D{{Key: "listDatabases", Value: 1}}, rp)
	if err != nil {
		c.snap.AddError("data", "listDatabases", err)
		return
	}
	budget := c.opts.MaxNamespaces
	for _, d := range docArray(res, "databases") {
		name := str(d, "name")
		if skippedDBs[name] {
			continue
		}
		db := snapshot.Database{Name: name, SizeOnDisk: num(d, "sizeOnDisk")}
		if budget <= 0 {
			c.snap.Data.Truncated = true
			c.snap.Data.Databases = append(c.snap.Data.Databases, db)
			continue
		}
		c.opts.Log("listing namespaces in %s", name)
		listing, err := c.listCollections(ctx, name, rp)
		if err != nil {
			c.snap.AddError("data:"+name, "listCollections", err)
		}
		for _, entry := range listing {
			if budget <= 0 {
				c.snap.Data.Truncated = true
				break
			}
			coll := collectionFromListing(entry)
			if strings.HasPrefix(coll.Name, "system.buckets.") {
				db.BucketCollections = append(db.BucketCollections, coll.Name)
				continue
			}
			if strings.HasPrefix(coll.Name, "system.") {
				continue
			}
			budget--
			if coll.Type != "view" {
				coll.Indexes = c.listIndexes(ctx, name, coll.Name)
			}
			db.Collections = append(db.Collections, coll)
		}
		c.addHiddenViews(ctx, &db)
		sort.Slice(db.Collections, func(i, j int) bool { return db.Collections[i].Name < db.Collections[j].Name })
		sort.Strings(db.BucketCollections)
		c.snap.Data.Databases = append(c.snap.Data.Databases, db)
	}
}

// listCollections reads the whole listCollections result of one database
// under one deadline, before the per-collection index listings start, so a
// database with many collections does not run its listing past the timeout.
// It returns what it read so far together with any error.
func (c *Collector) listCollections(ctx context.Context, db string, rp *readpref.ReadPref) ([]bson.Raw, error) {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := c.entry.Database(db, options.Database().SetReadPreference(rp)).ListCollections(cctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(cctx) }()
	var out []bson.Raw
	for cur.Next(cctx) {
		out = append(out, append(bson.Raw(nil), cur.Current...))
	}
	return out, cur.Err()
}

func collectionFromListing(r bson.Raw) snapshot.Collection {
	opts := doc(r, "options")
	coll := snapshot.Collection{
		Name:    str(r, "name"),
		Type:    str(r, "type"),
		Options: docJSON(opts),
		ViewOn:  str(opts, "viewOn"),
		Capped:  boolean(opts, "capped"),
	}
	if v, err := opts.LookupErr("pipeline"); err == nil {
		coll.Pipeline = relaxedJSON(v)
	}
	if v := doc(opts, "validator"); v != nil {
		coll.Validator = docJSON(v)
	}
	if v := doc(opts, "encryptedFields"); v != nil {
		coll.EncryptedFields = docJSON(v)
	}
	if _, err := opts.LookupErr("clusteredIndex"); err == nil {
		coll.Clustered = true
	}
	return coll
}

func (c *Collector) listIndexes(ctx context.Context, db, coll string) []snapshot.Index {
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := c.entry.Database(db, options.Database().SetReadPreference(c.dataReadPref())).Collection(coll).Indexes().List(cctx)
	if err != nil {
		c.snap.AddError("data:"+db+"."+coll, "listIndexes", err)
		return nil
	}
	defer func() { _ = cur.Close(cctx) }()
	var out []snapshot.Index
	for cur.Next(cctx) {
		idx := snapshot.Index{Name: str(cur.Current, "name"), Spec: docJSON(cur.Current)}
		if key := doc(cur.Current, "key"); key != nil {
			if elems, err := key.Elements(); err == nil {
				for _, e := range elems {
					idx.Key = append(idx.Key, snapshot.IndexKey{Field: e.Key(), Value: relaxedJSON(e.Value())})
				}
			}
		}
		out = append(out, idx)
	}
	return out
}

// collectSecurity reads users (never credentials) and user-defined roles.
// The users and roles collections replicate, so a secondary answers the same
// (dataReadPref).
func (c *Collector) collectSecurity(ctx context.Context) {
	rp := c.dataReadPref()
	res, err := c.runWith(ctx, c.entry, "admin", bson.D{
		{Key: "usersInfo", Value: bson.D{{Key: "forAllDBs", Value: true}}},
		{Key: "showCredentials", Value: false},
	}, rp)
	if err != nil {
		c.snap.AddError("security", "usersInfo", err)
	} else {
		for _, u := range docArray(res, "users") {
			c.snap.Security.Users = append(c.snap.Security.Users, snapshot.User{
				User:       str(u, "user"),
				DB:         str(u, "db"),
				Mechanisms: strArray(u, "mechanisms"),
				Roles:      roleRefs(u, "roles"),
			})
		}
	}

	dbs := []string{"admin"}
	for _, d := range c.snap.Data.Databases {
		if d.Name != "admin" {
			dbs = append(dbs, d.Name)
		}
	}
	for _, db := range dbs {
		res, err := c.runWith(ctx, c.entry, db, bson.D{
			{Key: "rolesInfo", Value: 1},
			{Key: "showPrivileges", Value: true},
			{Key: "showBuiltinRoles", Value: false},
		}, rp)
		if err != nil {
			c.snap.AddError("security:"+db, "rolesInfo", err)
			continue
		}
		for _, r := range docArray(res, "roles") {
			role := snapshot.Role{Role: str(r, "role"), DB: str(r, "db"), Roles: roleRefs(r, "roles")}
			for _, p := range docArray(r, "privileges") {
				role.Privileges = append(role.Privileges, snapshot.Privilege{
					Resource: docJSON(doc(p, "resource")),
					Actions:  strArray(p, "actions"),
				})
			}
			c.snap.Security.Roles = append(c.snap.Security.Roles, role)
		}
	}
}

func roleRefs(r bson.Raw, key string) []snapshot.RoleRef {
	var out []snapshot.RoleRef
	for _, rr := range docArray(r, key) {
		out = append(out, snapshot.RoleRef{Role: str(rr, "role"), DB: str(rr, "db")})
	}
	return out
}

// collectClients aggregates connected drivers from $currentOp. On a replica
// set they come from every member inspected (collected per node); otherwise
// from the entry node (on a sharded cluster, the clients of that mongos).
func (c *Collector) collectClients(ctx context.Context) {
	if c.snap.Topology.Kind == snapshot.KindReplicaSet && !c.opts.EntryOnly {
		var per [][]snapshot.ClientDriver
		for _, n := range c.snap.Nodes {
			per = append(per, n.Clients)
		}
		c.snap.Clients = mergeClients(per...)
		return
	}
	cds, err := c.clientDrivers(ctx, c.entry, c.snap.EntryHost)
	if err != nil {
		c.snap.AddError("clients", "$currentOp", err)
		return
	}
	c.snap.Clients = cds
}

// mergeClients combines driver lists from several members: one entry per
// driver name and version, with connections summed and app names and hosts
// merged.
func mergeClients(lists ...[]snapshot.ClientDriver) []snapshot.ClientDriver {
	byKey := map[string]*snapshot.ClientDriver{}
	var keys []string
	for _, list := range lists {
		for _, d := range list {
			k := d.DriverName + "\x00" + d.DriverVersion
			m, ok := byKey[k]
			if !ok {
				m = &snapshot.ClientDriver{DriverName: d.DriverName, DriverVersion: d.DriverVersion}
				byKey[k] = m
				keys = append(keys, k)
			}
			m.Connections += d.Connections
			m.AppNames = unionSorted(m.AppNames, d.AppNames)
			m.SeenOn = unionSorted(m.SeenOn, d.SeenOn)
		}
	}
	sort.Strings(keys)
	var out []snapshot.ClientDriver
	for _, k := range keys {
		out = append(out, *byKey[k])
	}
	return out
}

func unionSorted(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// clientDrivers groups the application connections of the node behind cl by
// driver name and version. mongod/mongos internal connections and ucfm's own
// are excluded.
func (c *Collector) clientDrivers(ctx context.Context, cl *mongo.Client, host string) ([]snapshot.ClientDriver, error) {
	pipeline := bson.A{
		bson.D{{Key: "$currentOp", Value: bson.D{
			{Key: "allUsers", Value: true},
			{Key: "idleConnections", Value: true},
			{Key: "localOps", Value: true},
		}}},
		bson.D{{Key: "$match", Value: bson.D{
			// Skip mongod/mongos internal connections (replication, sharding).
			{Key: "clientMetadata.driver.name", Value: bson.D{
				{Key: "$exists", Value: true},
				{Key: "$not", Value: bson.Regex{Pattern: `^(NetworkInterfaceTL|MongoDB Internal Client)`}},
			}},
			{Key: "appName", Value: bson.D{{Key: "$ne", Value: "ucfm"}}},
		}}},
		bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{
				{Key: "n", Value: "$clientMetadata.driver.name"},
				{Key: "v", Value: "$clientMetadata.driver.version"},
			}},
			{Key: "apps", Value: bson.D{{Key: "$addToSet", Value: "$appName"}}},
			{Key: "c", Value: bson.D{{Key: "$sum", Value: 1}}},
		}}},
	}
	// $currentOp describes the node behind cl: read that node.
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, cl.Database("admin"), aggregateCmd("", pipeline), nodeReadPref())
	if err != nil {
		return nil, err
	}
	defer func() { _ = cur.Close(cctx) }()
	var out []snapshot.ClientDriver
	for cur.Next(cctx) {
		cd := snapshot.ClientDriver{
			DriverName:    str(cur.Current, "_id", "n"),
			DriverVersion: str(cur.Current, "_id", "v"),
			Connections:   int(num(cur.Current, "c")),
			SeenOn:        []string{host},
		}
		for _, a := range strArray(cur.Current, "apps") {
			if a != "" {
				cd.AppNames = append(cd.AppNames, a)
			}
		}
		sort.Strings(cd.AppNames)
		out = append(out, cd)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DriverName != out[j].DriverName {
			return out[i].DriverName < out[j].DriverName
		}
		return out[i].DriverVersion < out[j].DriverVersion
	})
	return out, cur.Err()
}

// recentMongos returns routers that pinged within the window.
func recentMongos(list []snapshot.Mongos, now time.Time, window time.Duration) []snapshot.Mongos {
	var out []snapshot.Mongos
	for _, m := range list {
		if now.Sub(m.Ping) <= window {
			out = append(out, m)
		}
	}
	return out
}

// addHiddenViews reads <db>.system.views and adds the views listCollections
// does not return. MongoDB accepts views on system.buckets.* namespaces but
// never lists them, so they are only visible here. Reading system.views
// needs an explicit find privilege on it (not included in root or
// readAnyDatabase); without it the gap is recorded.
func (c *Collector) addHiddenViews(ctx context.Context, db *snapshot.Database) {
	listed := map[string]bool{}
	for _, coll := range db.Collections {
		listed[coll.Name] = true
	}
	cctx, cancel := c.deadline(ctx)
	defer cancel()
	cur, err := cursorCmd(cctx, c.entry.Database(db.Name), findCmd("system.views", nil,
		bson.D{{Key: "_id", Value: 1}, {Key: "viewOn", Value: 1}, {Key: "pipeline", Value: 1}}, nil, 0), c.dataReadPref())
	if err != nil {
		c.snap.AddError("data:"+db.Name, "find system.views", err)
		return
	}
	defer func() { _ = cur.Close(cctx) }()
	for cur.Next(cctx) {
		_, name, ok := strings.Cut(str(cur.Current, "_id"), ".")
		if !ok || listed[name] {
			continue
		}
		coll := snapshot.Collection{Name: name, Type: "view", ViewOn: str(cur.Current, "viewOn"), Hidden: true}
		if v, err := cur.Current.LookupErr("pipeline"); err == nil {
			coll.Pipeline = relaxedJSON(v)
		}
		db.Collections = append(db.Collections, coll)
	}
	if err := cur.Err(); err != nil {
		c.snap.AddError("data:"+db.Name, "find system.views", err)
	}
}
