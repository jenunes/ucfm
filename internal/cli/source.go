package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jenunes/ucfm/internal/collect"
	"github.com/jenunes/ucfm/internal/host"
	"github.com/jenunes/ucfm/internal/snapshot"
)

// snapshot returns the snapshot to analyze: loaded from --from-snapshot, or
// collected live (and saved when --save-snapshot is set).
func (s *sourceFlags) snapshot(ctx context.Context) (*snapshot.Snapshot, error) {
	if s.fromSnapshot != "" {
		return snapshot.Load(s.fromSnapshot)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	logf := func(string, ...any) {}
	if s.verbose {
		logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "ucfm: "+f+"\n", a...) }
	}
	snap, err := collect.Run(ctx, collect.Options{
		URI:           s.uri,
		EntryOnly:     s.entryOnly,
		SkipData:      s.skipData,
		SkipSecurity:  s.skipSecurity,
		MaxNamespaces: s.maxNamespaces,
		DeepCheck:     s.deepCheck,
		ToolVersion:   toolVersion(),
		Log:           logf,
	})
	if err != nil {
		return nil, err
	}
	warnShards(snap)
	if s.local {
		if err := attachHost(snap, s.configFile); err != nil {
			return nil, err
		}
	}
	if s.saveSnapshot != "" {
		if err := snap.Save(s.saveSnapshot); err != nil {
			return nil, fmt.Errorf("save snapshot: %w", err)
		}
	}
	return snap, nil
}

// attachHost collects local host facts into the snapshot.
func attachHost(snap *snapshot.Snapshot, configFile string) error {
	h, err := host.Collect(host.Options{ConfigFile: configFile})
	if err != nil {
		return err
	}
	h.Node = host.MatchNode(snap, h)
	if h.Node == "" {
		fmt.Fprintf(os.Stderr, "ucfm: warning: this machine (%s) is not a host of this deployment; its OS settings will not be used. Run ucfm with --local on each database host.\n", h.Hostname)
	}
	snap.Host = h
	snap.Collection.Local = true
	return nil
}

// warnShards tells the user right away when shards could not be collected,
// most often because the user exists only through mongos.
func warnShards(snap *snapshot.Snapshot) {
	issues := snap.InaccessibleShards()
	if len(issues) == 0 {
		return
	}
	var auth, other []string
	for _, is := range issues {
		if is.AuthFail {
			auth = append(auth, is.ID)
		} else {
			other = append(other, is.ID)
		}
	}
	if len(auth) > 0 {
		fmt.Fprintf(os.Stderr, "ucfm: warning: login rejected on %s. On a sharded cluster the user must also be created on every shard (users created through mongos are not accepted by shard members); checks for these shards will be incomplete.\n", shardList(auth))
	}
	if len(other) > 0 {
		fmt.Fprintf(os.Stderr, "ucfm: warning: could not reach %s from this machine; checks for these shards will be incomplete.\n", shardList(other))
	}
}

func toolVersion() string { v, _ := buildVersion(); return v }

// shardList writes "shard rs2" or "shards rs1, rs2".
func shardList(ids []string) string {
	if len(ids) == 1 {
		return "shard " + ids[0]
	}
	return "shards " + strings.Join(ids, ", ")
}
