package snapshot

import "strings"

// ShardIssue is a shard ucfm could not collect.
type ShardIssue struct {
	ID       string // shard name (rs0)
	Hosts    string // connection string from config.shards
	AuthFail bool   // the members rejected the login
	Reason   string // first error message for the shard
}

// InaccessibleShards lists the shards of a sharded cluster for which no
// member was collected, with the reason taken from the collection errors.
// With --entry-only shards are not contacted on purpose, so it returns nil.
func (s *Snapshot) InaccessibleShards() []ShardIssue {
	if s.Topology.Kind != KindSharded || s.Sharding == nil || s.Collection.EntryOnly {
		return nil
	}
	collected := map[string]bool{}
	for _, n := range s.Nodes {
		if n.ShardName != "" {
			collected[n.ShardName] = true
		}
	}
	var out []ShardIssue
	for _, sh := range s.Sharding.Shards {
		if collected[sh.ID] {
			continue
		}
		is := ShardIssue{ID: sh.ID, Hosts: sh.Host, Reason: "no member could be reached"}
		for _, e := range s.Errors {
			if e.Scope == "replset:"+sh.ID || e.Scope == "shard:"+sh.ID {
				is.Reason = e.Message
				is.AuthFail = isAuthError(e.Message)
				break
			}
		}
		out = append(out, is)
	}
	return out
}

func isAuthError(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "authentication failed") || strings.Contains(m, "auth error") ||
		strings.Contains(m, "unauthorized") || strings.Contains(m, "requires authentication")
}
