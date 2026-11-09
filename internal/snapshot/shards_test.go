package snapshot

import "testing"

func shardedSnap() *Snapshot {
	return &Snapshot{
		Topology: Topology{Kind: KindSharded},
		Sharding: &ShardingInfo{Shards: []Shard{
			{ID: "rs0", Host: "rs0/a:27017,b:27017"},
			{ID: "rs1", Host: "rs1/c:27017"},
			{ID: "rs2", Host: "rs2/d:27017"},
		}},
		Nodes: []Node{{Host: "a:27017", ShardName: "rs0"}, {Host: "m:27017", Role: RoleMongos}},
		Errors: []CollectError{
			{Scope: "replset:rs1", Command: "replSetGetStatus", Message: "connection() error occurred during connection handshake: auth error: sasl conversation error: unable to authenticate using mechanism \"SCRAM-SHA-1\": (AuthenticationFailed) Authentication failed."},
			{Scope: "replset:rs2", Command: "replSetGetStatus", Message: "server selection error: context deadline exceeded"},
		},
	}
}

func TestInaccessibleShards(t *testing.T) {
	got := shardedSnap().InaccessibleShards()
	if len(got) != 2 || got[0].ID != "rs1" || !got[0].AuthFail || got[1].ID != "rs2" || got[1].AuthFail {
		t.Fatalf("got %+v", got)
	}
	s := shardedSnap()
	s.Collection.EntryOnly = true
	if got := s.InaccessibleShards(); got != nil {
		t.Errorf("entry-only must not report shards: %+v", got)
	}
	s = shardedSnap()
	s.Topology.Kind = KindReplicaSet
	if got := s.InaccessibleShards(); got != nil {
		t.Errorf("replica set: %+v", got)
	}
}
