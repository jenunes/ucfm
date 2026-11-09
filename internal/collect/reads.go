package collect

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Server-side time limits.
//
// Every read runs under a context deadline of Options.CommandTimeout. For
// commands, listings and counts, the Go driver turns that deadline into a
// maxTimeMS field (the remaining time minus the measured round trip), so the
// server stops working just before the client gives up. Collection.Find and
// Collection.Aggregate are the exception: the driver omits maxTimeMS for
// cursors it hands to the caller (DRIVERS-2722). The collector therefore runs
// find and aggregate as commands through cursorCmd, which goes through
// RunCommandCursor and gets maxTimeMS like any other command. A command must
// never carry its own maxTimeMS field: the driver adds one, and the server
// rejects a duplicate.

// testMonitor lets tests observe every command the collector sends.
var testMonitor *event.CommandMonitor

// deadline returns a context bounded by the per-command timeout.
func (c *Collector) deadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.opts.CommandTimeout)
}

// cursorCmd runs a find or aggregate command (built with findCmd or
// aggregateCmd) and returns its cursor. ctx must carry a deadline (see
// deadline) and must stay valid while the cursor is read.
func cursorCmd(ctx context.Context, db *mongo.Database, cmd bson.D, rp *readpref.ReadPref) (*mongo.Cursor, error) {
	return db.RunCommandCursor(ctx, cmd, options.RunCmd().SetReadPreference(rp))
}

// findCmd builds a find command. Empty projection, sort or limit are left out.
func findCmd(coll string, filter, projection, sort bson.D, limit int64) bson.D {
	if filter == nil {
		filter = bson.D{}
	}
	cmd := bson.D{{Key: "find", Value: coll}, {Key: "filter", Value: filter}}
	if len(projection) > 0 {
		cmd = append(cmd, bson.E{Key: "projection", Value: projection})
	}
	if len(sort) > 0 {
		cmd = append(cmd, bson.E{Key: "sort", Value: sort})
	}
	if limit > 0 {
		cmd = append(cmd, bson.E{Key: "limit", Value: limit})
	}
	return cmd
}

// aggregateCmd builds an aggregate command on a collection, or on the
// database when coll is "" (as $currentOp requires: aggregate: 1).
func aggregateCmd(coll string, pipeline bson.A) bson.D {
	var target any = coll
	if coll == "" {
		target = 1
	}
	return bson.D{{Key: "aggregate", Value: target}, {Key: "pipeline", Value: pipeline}, {Key: "cursor", Value: bson.D{}}}
}

// Read preferences.
//
// Per-member reads use the member's own connection and read that member by
// design (nodeReadPref). Reads through the entry connection follow
// entryReadPref or dataReadPref, chosen per read in the calling code.

// nodeReadPref reads the member the client points at. On a direct connection
// the driver allows reading a secondary with it; on a replica set connection it
// reads the primary when there is one.
func nodeReadPref() *readpref.ReadPref { return readpref.PrimaryPreferred() }

// maxStaleness keeps lagging or delayed secondaries out of dataReadPref.
// 90 seconds is the smallest value the server accepts.
const maxStaleness = 90 * time.Second

// dataReadPref is for catalog and data reads through the entry connection
// that a secondary answers with the same result: database, collection and
// index listings, view definitions, users and roles, and --deep-check samples.
// On a replica set they go to a secondary when one is available, sparing the
// primary; maxStaleness excludes delayed members. Through mongos, on a
// standalone or with --entry-only the reads stay where they were.
func (c *Collector) dataReadPref() *readpref.ReadPref {
	return dataReadPrefFor(c.snap.Topology.Kind, c.opts.EntryOnly)
}

func dataReadPrefFor(kind string, entryOnly bool) *readpref.ReadPref {
	if kind == snapshot.KindReplicaSet && !entryOnly {
		return readpref.SecondaryPreferred(readpref.WithMaxStaleness(maxStaleness))
	}
	return readpref.PrimaryPreferred()
}
