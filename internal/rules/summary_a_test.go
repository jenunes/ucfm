package rules

import (
	"strings"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
)

func init() {
	passNotOnFixtures["backup-before-upgrade"] = "always reports"
	passNotOnFixtures["sharding-balancer"] = "unit test TestGroupASummaries"
	passNotOnFixtures["host-checks-coverage"] = "unit test TestGroupASummaries"
	passNotOnFixtures["prod-host-coverage"] = "unit test TestGroupASummaries"
}

func groupAAuditCheck(t *testing.T, a *AuditResult, id string) CheckResult {
	t.Helper()
	for _, c := range a.Checks {
		if c.RuleID == id {
			return c
		}
	}
	t.Fatalf("no audit check %s", id)
	return CheckResult{}
}

func groupAWant(t *testing.T, c CheckResult, want string) {
	t.Helper()
	if c.Status != StatusOK || c.Summary != want {
		t.Errorf("%s: status %s, summary %q, want %q", c.RuleID, c.Status, c.Summary, want)
	}
}

func TestGroupASummaries(t *testing.T) {
	// Healthy 3-member replica set.
	res := run(t, base(), "8.0")
	groupAWant(t, checkOf(t, res, "binary-versions-consistent"), "all 3 members run 7.0.29.")
	groupAWant(t, checkOf(t, res, "fcv-matches-binary"), "FCV is 7.0 on 3 members, the same as their binaries.")
	groupAWant(t, checkOf(t, res, "replset-has-primary"), "replica set rs0 has a primary.")
	groupAWant(t, checkOf(t, res, "replset-members-healthy"), "all 3 members of replica set rs0 are reachable, in a normal state and less than 60s behind the primary.")
	groupAWant(t, checkOf(t, res, "replset-arbiters"), "replica set rs0 has no arbiter.")
	groupAWant(t, checkOf(t, res, "startup-warnings"), "the startup logs of 3 members have no warnings.")
	groupAWant(t, checkOf(t, res, "collection-gaps"), "every fact was collected from 3 members.")
	groupAWant(t, checkOf(t, res, "driver-compatibility"), "no application driver was connected to any of the 3 replica set members when the snapshot was taken.")

	// Sharded, every shard reachable, balancer stopped.
	s := shardedWithMissingShards()
	s.Errors = nil
	s.Sharding.Shards = s.Sharding.Shards[:1]
	sh := run(t, s, "8.0")
	groupAWant(t, checkOf(t, sh, "sharding-balancer"), `the balancer is stopped (mode "off").`)
	groupAWant(t, checkOf(t, sh, "sharding-no-resharding"), "no resharding operation is in progress.")
	groupAWant(t, checkOf(t, sh, "sharding-no-migrations"), "no chunk migration is running and the only shard is not draining.")
	groupAWant(t, checkOf(t, sh, "shard-access"), "ucfm logged in to every member of the only shard.")

	// Single-member replica set checked with --local on its own host.
	one := base()
	one.Nodes = one.Nodes[:1]
	one.Topology.ReplSets[0].Members = one.Topology.ReplSets[0].Members[:1]
	one.Host = &snapshot.HostInfo{Hostname: "a", Node: "a:27017"}
	groupAWant(t, checkOf(t, run(t, one, "8.0"), "host-checks-coverage"), "host settings were checked on a:27017, the only data-bearing member.")
	groupAWant(t, groupAAuditCheck(t, audit(t, one), "prod-host-coverage"), "host settings were checked on a:27017, the only data-bearing member.")
}

func TestOSSupportSummary(t *testing.T) {
	s := base()
	for i := range s.Nodes {
		s.Nodes[i].HostInfo.OSName = "Ubuntu"
		s.Nodes[i].HostInfo.OSVersion = "22.04"
		s.Nodes[i].HostInfo.CPUArch = "x86_64"
	}
	c := checkOf(t, run(t, s, "8.0"), "platform-os-supported")
	if c.Status == StatusOK {
		groupAWant(t, c, "Ubuntu 22.04 on 3 hosts is supported by MongoDB Community 8.0.")
	} else {
		t.Logf("platform-os-supported: %s %s", c.Status, c.Reason)
	}
}

func TestDriversOnSecondariesAreListed(t *testing.T) {
	s := base()
	s.Clients = []snapshot.ClientDriver{{DriverName: "nodejs", DriverVersion: "6.9.0", Connections: 2, AppNames: []string{"reports"}, SeenOn: []string{"b:27017"}}}
	f := find(run(t, s, "8.0"), "driver-compatibility")
	if f == nil || !strings.Contains(f.Message, "connected to the 3 replica set members") || len(f.Items) != 1 ||
		f.Items[0] != "nodejs 6.9.0 (2 connections) apps: reports on b:27017" {
		t.Fatalf("got %+v", f)
	}
}
