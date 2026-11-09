package rules

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Group D (production.go): audit rules that never pass on the fixtures are
// covered by TestAuditPassingSummaries; prod-manual-checklist always reports.
func init() {
	for _, id := range []string{
		"prod-thp", "prod-swappiness", "prod-numa", "prod-filesystem", "prod-noatime", "prod-readahead",
		"prod-io-scheduler", "prod-ulimits", "prod-kernel-limits", "prod-clock-sync", "prod-tcp",
		"prod-disk-space", "prod-selinux-js", "prod-tcmalloc-per-cpu", "prod-tls",
	} {
		passNotOnFixtures[id] = "unit test TestAuditPassingSummaries"
	}
	passNotOnFixtures["prod-connections"] = "unit test TestAuditSummaryBranches"
	passNotOnFixtures["prod-oplog-window"] = "unit test TestOplogWindowSummary"
	passNotOnFixtures["prod-manual-checklist"] = "always reports: the items cannot be verified from the database or host"
}

// cleanProductionHost is an 8.0 replica set whose member a:27017 was audited
// with --local and follows every production recommendation.
func cleanProductionHost() *snapshot.Snapshot {
	s := base()
	synced := true
	for i := range s.Nodes {
		s.Nodes[i].Version, s.Nodes[i].FCV = "8.0.12", "8.0"
		s.Nodes[i].Options["net.tls.mode"] = json.RawMessage(`"requireTLS"`)
		s.Nodes[i].Options["security.authorization"] = json.RawMessage(`"enabled"`)
		s.Nodes[i].TCMalloc = &snapshot.TCMallocInfo{UsingPerCPUCaches: true, CPUFreeBytes: 1 << 20}
	}
	s.Host = &snapshot.HostInfo{
		Hostname: "db1", Node: "a:27017",
		THPEnabled: "[always] madvise never",
		NUMANodes:  1,
		Sysctls: map[string]string{
			"vm.swappiness": "1", "vm.max_map_count": "262144", "fs.file-max": "9223372036854775807",
			"kernel.pid_max": "4194304", "kernel.threads-max": "500000",
			"net.ipv4.tcp_keepalive_time": "120", "net.ipv4.tcp_retries2": "5",
		},
		DBPath: "/var/lib/mongo", DBPathFS: "xfs", DBPathMountOpts: []string{"rw", "noatime"},
		DBPathDevice: "sda", ReadaheadKB: "8", IOScheduler: "[none] mq-deadline",
		DBPathFreeMB: 90000, DBPathUsedMB: 10000,
		MongodProcesses: []snapshot.LocalProcess{{PID: 100, Name: "mongod",
			Limits: map[string]string{"Max open files": "64000 64000", "Max processes": "64000 64000"}}},
		ClockSynced: &synced,
		SELinux:     "permissive",
	}
	return s
}

func TestAuditPassingSummaries(t *testing.T) {
	res, err := Audit(cleanProductionHost())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"prod-thp":               "transparent_hugepage/enabled is always on db1 (a:27017), as MongoDB 8.0 recommends.",
		"prod-swappiness":        "vm.swappiness is 1 on db1 (a:27017) (recommended 1 or 0).",
		"prod-numa":              "db1 (a:27017) has at most one NUMA node, and no member reports NUMA hardware.",
		"prod-filesystem":        "dbPath /var/lib/mongo is on XFS on db1 (a:27017).",
		"prod-noatime":           "the filesystem holding dbPath /var/lib/mongo is mounted with noatime on db1 (a:27017).",
		"prod-readahead":         "readahead on sda (dbPath /var/lib/mongo) is 16 sectors on db1 (a:27017) (recommended 8–32).",
		"prod-io-scheduler":      "the I/O scheduler of sda is none on db1 (a:27017).",
		"prod-ulimits":           "open files and processes limits are at least 64000 (or unlimited) for 1 mongod/mongos process on db1 (a:27017).",
		"prod-kernel-limits":     "vm.max_map_count, fs.file-max, kernel.pid_max and kernel.threads-max are at or above the operations checklist's starting values on db1 (a:27017).",
		"prod-clock-sync":        "the kernel reports the clock of db1 (a:27017) as synchronized.",
		"prod-tcp":               "net.ipv4.tcp_keepalive_time is 120 (at most 300) and net.ipv4.tcp_retries2 is 5 (at most 5) on db1 (a:27017).",
		"prod-disk-space":        "the dbPath filesystem on db1 (a:27017) has 90000 MB free (90%; minimum 15% and 4096 MB).",
		"prod-selinux-js":        "SELinux is permissive on db1 (a:27017), so server-side JavaScript cannot trigger the SELinux crash.",
		"prod-tcmalloc-per-cpu":  "TCMalloc uses per-CPU caches on all 3 servers that report it.",
		"prod-tls":               "TLS is enabled on all 3 members (arbiters excluded).",
		"prod-authorization":     "access control is enabled on all 3 members (arbiters excluded).",
		"prod-replset-voting":    "rs0 has 3 voting members, 3 data-bearing (odd, and at least 3 data-bearing).",
		"prod-replset-hostnames": "all 3 members of 1 replica set use hostnames, not IP addresses.",
		"prod-journal":           "journaling is not disabled on any of the 3 data-bearing members.",
		"prod-wt-cache":          "no member sets cacheSizeGB, so all 3 data-bearing members use the default WiredTiger cache size.",
		"prod-collection-gaps":   "every fact was collected from 3 members and from the local host.",
	}
	got := map[string]CheckResult{}
	for _, c := range res.Checks {
		got[c.RuleID] = c
	}
	for id, summary := range want {
		c, ok := got[id]
		switch {
		case !ok:
			t.Errorf("%s: not run", id)
		case c.Status != StatusOK:
			t.Errorf("%s: status %s, findings %+v, reason %q", id, c.Status, c.Findings, c.Reason)
		case c.Summary != summary:
			t.Errorf("%s summary\n got  %q\n want %q", id, c.Summary, summary)
		}
	}
}

func TestAuditSummaryBranches(t *testing.T) {
	s := cleanProductionHost()
	interleaved := true
	s.Host.NUMANodes = 2
	s.Host.Sysctls["vm.zone_reclaim_mode"] = "0"
	s.Host.MongodProcesses[0].NUMAInterleave = &interleaved
	s.Host.SELinux = "enforcing"
	s.Nodes[0].Options["security.javascriptEnabled"] = json.RawMessage(`false`)
	s.Nodes[1].Options["storage.wiredTiger.engineConfig.cacheSizeGB"] = json.RawMessage(`1`)
	s.Nodes[1].HostInfo.MemSizeMB = 8192
	for i := range s.Nodes {
		s.Nodes[i].Connections = &snapshot.Connections{Current: int64(10 * (i + 1)), Available: 990}
	}
	res, err := Audit(s)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"prod-numa":        "db1 (a:27017) has 2 NUMA nodes; vm.zone_reclaim_mode is 0, 1 mongod process run with numactl --interleave=all and numad is not running.",
		"prod-selinux-js":  "SELinux is enforcing on db1 (a:27017), and server-side JavaScript is disabled (security.javascriptEnabled: false on a:27017).",
		"prod-wt-cache":    "cacheSizeGB is set on 1 member and stays within the default size and 80% of memory.",
		"prod-connections": "connection usage on 3 members is at most 3% of the limit (c:27017; warning at 80%).",
	}
	for _, c := range res.Checks {
		if w, ok := want[c.RuleID]; ok && c.Summary != w {
			t.Errorf("%s summary\n got  %q\n want %q", c.RuleID, c.Summary, w)
		}
	}
}

func TestOplogWindowSummary(t *testing.T) {
	s := cleanProductionHost()
	for i := range s.Nodes {
		s.Nodes[i].Oplog = &snapshot.OplogInfo{MaxSizeMB: 1000, UsedMB: 100, WindowHours: 10 + float64(i), First: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	}
	res, err := Audit(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Checks {
		if c.RuleID == "prod-oplog-window" {
			if want := "checked the oplog of 3 members; the shortest window is 100.0 hours on a:27017 (minimum 24; 72 when the oplog is full)."; c.Status != StatusOK || c.Summary != want {
				t.Errorf("got %s %q\nwant %q", c.Status, c.Summary, want)
			}
			return
		}
	}
	t.Fatal("prod-oplog-window did not run")
}
