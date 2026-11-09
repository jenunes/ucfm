package rules

import (
	"fmt"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// On a sharded cluster ucfm logs in to every shard member directly. Users
// created through mongos are stored on the config servers and are not
// accepted by shard members, so a user that exists only through mongos
// leaves most per-member checks of the shards undone.

var (
	ruleShardAccess = Rule{
		ID: "shard-access", Title: "Access to every shard",
		Category: "path", Scope: ScopeGlobal, Severity: Warning,
		DocURL: "https://www.mongodb.com/docs/manual/core/sharded-cluster-shards/",
	}
	ruleProdShardAccess = Rule{
		ID: "prod-shard-access", Title: "Access to every shard",
		Category: "path", Scope: ScopeProduction, Severity: Warning,
		DocURL: "https://www.mongodb.com/docs/manual/core/sharded-cluster-shards/",
	}
)

func init() {
	ruleShardAccess.Check = func(c *Context) []Finding { return checkShardAccess(c, ruleShardAccess) }
	ruleProdShardAccess.Check = func(c *Context) []Finding { return checkShardAccess(c, ruleProdShardAccess) }
	register(ruleShardAccess, ruleProdShardAccess)
}

// connUser returns the user name of the connection template, or "".
func connUser(s *snapshot.Snapshot) string {
	t, ok := strings.CutPrefix(s.Collection.ConnTemplate, "mongodb://")
	if !ok {
		return ""
	}
	at := strings.Index(t, "@")
	if at < 0 {
		return ""
	}
	user, _, _ := strings.Cut(t[:at], ":")
	return user
}

func checkShardAccess(c *Context, r Rule) []Finding {
	if c.Snap.Topology.Kind != snapshot.KindSharded {
		return c.NotApplicable(notSharded)
	}
	if c.Snap.Collection.EntryOnly {
		return c.NotApplicable("--entry-only inspects only the node in --uri")
	}
	issues := c.Snap.InaccessibleShards()
	if len(issues) == 0 {
		n := 0
		if c.Snap.Sharding != nil {
			n = len(c.Snap.Sharding.Shards)
		}
		if n == 1 {
			return c.Checked("ucfm logged in to every member of the only shard.")
		}
		return c.Checked("ucfm logged in to every member of all %d shards.", n)
	}
	var items []string
	auth := 0
	for _, is := range issues {
		why := "unreachable from this machine"
		if is.AuthFail {
			why = "login rejected: the user does not exist on this shard"
			auth++
		}
		items = append(items, fmt.Sprintf("%s (%s): %s", is.ID, is.Hosts, why))
	}
	user := connUser(c.Snap)
	if user == "" {
		user = "the ucfm user"
	}
	msg := fmt.Sprintf("ucfm could not collect %d of %d shards, so most upgrade checks for them (versions, FCV, options, parameters, health, counters, OS) were skipped.",
		len(issues), len(c.Snap.Sharding.Shards))
	action := "Make every shard member reachable from this machine, then re-run."
	if auth > 0 {
		msg += " On a sharded cluster the user must also be created on every shard: users created through mongos are stored on the config servers and shard members do not accept them."
		action = fmt.Sprintf("Create %s, with the same roles (and the ucfmViewSecurity role), on the primary of each listed shard, as described on the Requirements page, then re-run.", user)
	}
	return []Finding{r.finding(Warning, msg, items, action)}
}
