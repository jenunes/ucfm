package rules

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jenunes/ucfm/internal/snapshot"
)

func audit(t *testing.T, s *snapshot.Snapshot) *AuditResult {
	t.Helper()
	res, err := Audit(s)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func auditFind(res *AuditResult, id string) *Finding {
	for _, f := range res.Findings() {
		if f.RuleID == id {
			return &f
		}
	}
	return nil
}

func boolp(b bool) *bool { return &b }

// healthyHost is a host that follows every production recommendation for a
// 7.0 deployment.
func healthyHost() *snapshot.HostInfo {
	return &snapshot.HostInfo{
		Hostname: "a", THPEnabled: "always madvise [never]", NUMANodes: 1,
		Sysctls: map[string]string{
			"vm.swappiness": "1", "vm.zone_reclaim_mode": "0", "vm.max_map_count": "262144",
			"fs.file-max": "9223372036854775807", "kernel.pid_max": "4194304", "kernel.threads-max": "500000",
			"net.ipv4.tcp_keepalive_time": "120", "net.ipv4.tcp_retries2": "5",
		},
		DBPath: "/data", DBPathFS: "xfs", DBPathDevice: "/dev/sdb1", DBPathMountOpts: []string{"rw", "noatime"},
		ReadaheadKB: "8", IOScheduler: "[none] mq-deadline", ClockSynced: boolp(true),
		DBPathFreeMB: 500000, DBPathUsedMB: 100000,
		MongodProcesses: []snapshot.LocalProcess{{PID: 1, Name: "mongod",
			Limits: map[string]string{"Max open files": "64000 64000", "Max processes": "64000 64000"}}},
	}
}

// healthyProd is base() with auth, TLS, host facts and a healthy oplog.
func healthyProd() *snapshot.Snapshot {
	s := base()
	for i := range s.Nodes {
		s.Nodes[i].Options["security.authorization"] = json.RawMessage(`"enabled"`)
		s.Nodes[i].Options["net.tls.mode"] = json.RawMessage(`"requireTLS"`)
		s.Nodes[i].HostInfo = snapshot.HostInfoCmd{NumCores: 8, MemSizeMB: 32000, KernelVersion: "5.14.0-427.el9.x86_64"}
		s.Nodes[i].Oplog = &snapshot.OplogInfo{MaxSizeMB: 10000, UsedMB: 9500, WindowHours: 100,
			First: time.Now().Add(-100 * time.Hour), Last: time.Now()}
		s.Nodes[i].Connections = &snapshot.Connections{Current: 100, Available: 50000}
	}
	s.Host = healthyHost()
	return s
}

func TestAuditHealthyOnlyManualNotice(t *testing.T) {
	res := audit(t, healthyProd())
	// Only host "a" ran --local, so the coverage notice for b and c is expected.
	for _, f := range res.Findings() {
		if f.RuleID != "prod-manual-checklist" && f.RuleID != "prod-host-coverage" {
			t.Errorf("unexpected %s %s %v", f.Severity, f.RuleID, f.Items)
		}
	}
	if res.Max() != Notice {
		t.Errorf("max = %v", res.Max())
	}
}

func TestRunNeverReturnsProductionFindings(t *testing.T) {
	s := healthyProd()
	s.Host.Sysctls["vm.swappiness"] = "60"
	s.Host.DBPathFS = "overlay"
	for _, fixture := range []*snapshot.Snapshot{s, loadFixture(t, "psmdb60-local.json")} {
		res, err := Run(fixture, "8.0", Options{SeeTheFuture: true})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range res.AllFindings() {
			if r := rule(f.RuleID); r.Scope == ScopeProduction {
				t.Errorf("upgrade check returned production finding %s", f.RuleID)
			}
		}
	}
}

func TestAuditRules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*snapshot.Snapshot)
		rule   string
		sev    Severity
	}{
		{"thp on for 7.0", func(s *snapshot.Snapshot) { s.Host.THPEnabled = "[always] madvise never" }, "prod-thp", Warning},
		{"swappiness", func(s *snapshot.Snapshot) { s.Host.Sysctls["vm.swappiness"] = "60" }, "prod-swappiness", Warning},
		{"numa", func(s *snapshot.Snapshot) {
			s.Host.NUMANodes = 2
			s.Host.MongodProcesses[0].NUMAInterleave = boolp(false)
		}, "prod-numa", Warning},
		{"ext4", func(s *snapshot.Snapshot) { s.Host.DBPathFS = "ext4" }, "prod-filesystem", Notice},
		{"nfs", func(s *snapshot.Snapshot) { s.Host.DBPathFS = "nfs4" }, "prod-filesystem", Warning},
		{"atime", func(s *snapshot.Snapshot) { s.Host.DBPathMountOpts = []string{"rw", "relatime"} }, "prod-noatime", Notice},
		{"readahead", func(s *snapshot.Snapshot) { s.Host.ReadaheadKB = "4096" }, "prod-readahead", Warning},
		{"scheduler", func(s *snapshot.Snapshot) { s.Host.IOScheduler = "noop [cfq]" }, "prod-io-scheduler", Notice},
		{"ulimit", func(s *snapshot.Snapshot) { s.Host.MongodProcesses[0].Limits["Max open files"] = "1024 4096" }, "prod-ulimits", Warning},
		{"max_map_count", func(s *snapshot.Snapshot) { s.Host.Sysctls["vm.max_map_count"] = "65530" }, "prod-kernel-limits", Notice},
		{"clock", func(s *snapshot.Snapshot) { s.Host.ClockSynced = boolp(false) }, "prod-clock-sync", Warning},
		{"keepalive", func(s *snapshot.Snapshot) { s.Host.Sysctls["net.ipv4.tcp_keepalive_time"] = "7200" }, "prod-tcp", Notice},
		{"disk", func(s *snapshot.Snapshot) { s.Host.DBPathFreeMB = 1000 }, "prod-disk-space", Warning},
		{"selinux js", func(s *snapshot.Snapshot) { s.Host.SELinux = "enforcing" }, "prod-selinux-js", Notice},
		{"uek", func(s *snapshot.Snapshot) { s.Nodes[0].HostInfo.KernelVersion = "5.15.0-300.163.18.el8uek.x86_64" }, "prod-kernel-uek", Warning},
		{"one core", func(s *snapshot.Snapshot) { s.Nodes[1].HostInfo.NumCores = 1 }, "prod-cpu-cores", Warning},
		{"no auth", func(s *snapshot.Snapshot) { delete(s.Nodes[0].Options, "security.authorization") }, "prod-authorization", Warning},
		{"no tls", func(s *snapshot.Snapshot) { delete(s.Nodes[2].Options, "net.tls.mode") }, "prod-tls", Notice},
		{"even voters", func(s *snapshot.Snapshot) {
			s.Topology.ReplSets[0].Members = append(s.Topology.ReplSets[0].Members,
				snapshot.Member{Host: "d:27017", State: snapshot.RoleSecondary, Health: 1, Votes: 1})
		}, "prod-replset-voting", Warning},
		{"ip members", func(s *snapshot.Snapshot) { s.Topology.ReplSets[0].Members[0].Host = "10.0.0.5:27017" }, "prod-replset-hostnames", Notice},
		{"unequal ram", func(s *snapshot.Snapshot) { s.Nodes[2].HostInfo.MemSizeMB = 8000 }, "prod-members-identical", Notice},
		{"journal off", func(s *snapshot.Snapshot) { s.Nodes[0].Options["storage.journal.enabled"] = json.RawMessage(`false`) }, "prod-journal", Warning},
		{"big cache", func(s *snapshot.Snapshot) {
			s.Nodes[0].Options["storage.wiredTiger.engineConfig.cacheSizeGB"] = json.RawMessage(`30`)
		}, "prod-wt-cache", Warning},
		{"short oplog", func(s *snapshot.Snapshot) { s.Nodes[0].Oplog.WindowHours = 6 }, "prod-oplog-window", Warning},
		{"connections", func(s *snapshot.Snapshot) {
			s.Nodes[0].Connections = &snapshot.Connections{Current: 900, Available: 100}
		}, "prod-connections", Warning},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := healthyProd()
			c.mutate(s)
			f := auditFind(audit(t, s), c.rule)
			if f == nil || f.Severity != c.sev {
				t.Fatalf("%s: got %+v", c.rule, f)
			}
		})
	}
}

func TestAuditTHPFlipsAt80(t *testing.T) {
	s := healthyProd()
	for i := range s.Nodes {
		s.Nodes[i].Version, s.Nodes[i].FCV = "8.0.19", "8.0"
	}
	// THP disabled is wrong for 8.0 ...
	if f := auditFind(audit(t, s), "prod-thp"); f == nil {
		t.Error("expected THP warning for 8.0 with THP disabled")
	}
	// ... and enabled is right.
	s.Host.THPEnabled = "[always] madvise never"
	if f := auditFind(audit(t, s), "prod-thp"); f != nil {
		t.Errorf("unexpected %+v", f)
	}
}

func TestAuditOplogNotFullProjection(t *testing.T) {
	s := healthyProd()
	// 10% used over 2h -> projected 20h window: warn.
	s.Nodes[0].Oplog = &snapshot.OplogInfo{MaxSizeMB: 1000, UsedMB: 100, WindowHours: 2, First: time.Now().Add(-2 * time.Hour), Last: time.Now()}
	if f := auditFind(audit(t, s), "prod-oplog-window"); f == nil || f.Severity != Warning {
		t.Fatalf("got %+v", f)
	}
	// Barely used (0 MB): no judgement.
	s.Nodes[0].Oplog.UsedMB = 0
	if f := auditFind(audit(t, s), "prod-oplog-window"); f != nil {
		t.Errorf("unexpected %+v", f)
	}
}

func TestAuditRealContainerFixture(t *testing.T) {
	// anydbver PSMDB 6.0 container: overlay dbPath, THP never (correct for 6.0).
	res := audit(t, memberLocalFixture(t))
	if f := auditFind(res, "prod-filesystem"); f == nil || f.Severity != Warning {
		t.Errorf("overlay dbPath: %+v", f)
	}
	if f := auditFind(res, "prod-thp"); f != nil {
		t.Errorf("THP never is right for 6.0: %+v", f)
	}
	if res.Max() > Warning {
		t.Errorf("audit must not produce errors, got %v", res.Max())
	}
}

func TestHostCoverageCommands(t *testing.T) {
	s := healthyProd()
	s.Collection.ConnTemplate = "mongodb://ucfm:****@{host}/?authSource=admin"
	s.Nodes[0].HostInfo.Hostname = "a"
	f := auditFind(audit(t, s), "prod-host-coverage")
	if f == nil || len(f.Items) != 2 {
		t.Fatalf("got %+v", f)
	}
	want := `ucfm audit --uri "mongodb://ucfm@b:27017/?authSource=admin&directConnection=true" --local --entry-only`
	if f.Items[0] != "b:27017" || len(f.Commands) != 2 || f.Commands[0] != want {
		t.Errorf("items %q commands %q\nwant command %q", f.Items, f.Commands, want)
	}
	if !strings.Contains(f.Message, "checked on a:27017 only") {
		t.Errorf("message = %q", f.Message)
	}
	// Without --local at all, every data-bearing host is listed.
	s.Host = nil
	if f := auditFind(audit(t, s), "prod-host-coverage"); f == nil || len(f.Items) != 3 {
		t.Errorf("no --local: %+v", f)
	}
}

func TestStartupWarningLinksHostCheck(t *testing.T) {
	s := healthyProd()
	s.Host = nil
	s.Nodes[0].StartupWarnings = []string{`{"msg":"Soft rlimits for open file descriptors too low","attr":{}}`}
	res, err := Run(s, "8.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	f := find(res, "startup-warnings")
	if f == nil || !strings.Contains(f.Items[0], "(host check: Process limits)") || !strings.Contains(f.Message, "Host checks coverage") {
		t.Fatalf("got %+v", f)
	}
	if find(res, "host-checks-coverage") == nil {
		t.Error("check must also list the host re-run commands")
	}
}

// A snapshot collected with --local on a workstation that is not a member
// (Node empty, LocalAddrs recorded): its settings must never be judged.
func nonMemberHost(s *snapshot.Snapshot) {
	s.Host.Hostname = "laptop"
	s.Host.Node = ""
	s.Host.LocalAddrs = []string{"192.168.1.20"}
	s.Host.THPEnabled = "[always] madvise never" // wrong for 7.0 if it were used
	s.Host.Sysctls["vm.swappiness"] = "60"
	s.Host.ConfigFile = "/etc/mongod.conf"
	s.Host.ConfigOptions = map[string]json.RawMessage{"net.transportLayer": json.RawMessage(`"asio"`)} // removed in 8.0
}

func checkStatus(cs []CheckResult, id string) (CheckResult, bool) {
	for _, c := range cs {
		if c.RuleID == id {
			return c, true
		}
	}
	return CheckResult{}, false
}

func TestNonMemberHostFactsAreNotUsed(t *testing.T) {
	s := healthyProd()
	nonMemberHost(s)
	a := audit(t, s)
	for _, id := range []string{"prod-thp", "prod-swappiness", "prod-filesystem"} {
		c, ok := checkStatus(a.Checks, id)
		if !ok || c.Status != StatusNotChecked || !strings.Contains(c.Reason, "ucfm ran with --local on laptop, which is not a host of this deployment") {
			t.Errorf("%s = %+v", id, c)
		}
	}
	if f := auditFind(a, "prod-host-coverage"); f == nil || len(f.Items) != 3 || !strings.Contains(f.Message, "laptop") {
		t.Errorf("coverage = %+v", f)
	}

	res, err := Run(s, "8.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(res, "config-option-removed"); f != nil {
		t.Errorf("the workstation's mongod.conf must not be judged: %+v", f)
	}
	for _, h := range res.Hops {
		if c, ok := checkStatus(h.Checks, "thp-enabled-for-8.0"); ok && c.Status == StatusIssues {
			t.Errorf("THP of the workstation judged: %+v", c)
		}
	}
}

func TestMemberHostFactsAreAttributed(t *testing.T) {
	s := healthyProd()
	s.Host.Node = "a:27017"
	s.Host.LocalAddrs = []string{"10.0.0.1"}
	s.Host.Sysctls["vm.swappiness"] = "60"
	s.Host.ConfigFile = "/etc/mongod.conf"
	s.Host.ConfigOptions = map[string]json.RawMessage{"net.transportLayer": json.RawMessage(`"asio"`)}
	a := audit(t, s)
	if f := auditFind(a, "prod-swappiness"); f == nil || !strings.Contains(f.Message, "is 60 on a:27017") {
		t.Errorf("swappiness = %+v", f)
	}
	res, err := Run(s, "8.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	if f := find(res, "config-option-removed"); f == nil || !strings.Contains(f.Items[0], "/etc/mongod.conf on a:27017") {
		t.Errorf("config option = %+v", f)
	}
}

func shardedWithMissingShards() *snapshot.Snapshot {
	s := base()
	s.Topology.Kind = snapshot.KindSharded
	s.Collection.ConnTemplate = "mongodb://ucfm:****@{host}/?authSource=admin"
	s.Sharding = &snapshot.ShardingInfo{Shards: []snapshot.Shard{
		{ID: "rs0", Host: "rs0/a:27017,b:27017,c:27017"},
		{ID: "rs1", Host: "rs1/d:27017"},
		{ID: "rs2", Host: "rs2/e:27017"},
	}, BalancerMode: "off"}
	for i := range s.Nodes {
		s.Nodes[i].ShardName = "rs0"
	}
	s.Errors = []snapshot.CollectError{
		{Scope: "replset:rs1", Command: "replSetGetStatus", Message: "auth error: (AuthenticationFailed) Authentication failed."},
		{Scope: "replset:rs2", Command: "replSetGetStatus", Message: "server selection error: context deadline exceeded"},
	}
	return s
}

func TestShardAccessWarning(t *testing.T) {
	res, err := Run(shardedWithMissingShards(), "8.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	f := find(res, "shard-access")
	if f == nil || f.Severity != Warning || len(f.Items) != 2 {
		t.Fatalf("got %+v", f)
	}
	if !strings.Contains(f.Items[0], "rs1 (rs1/d:27017): login rejected: the user does not exist on this shard") ||
		!strings.Contains(f.Items[1], "rs2 (rs2/e:27017): unreachable") {
		t.Errorf("items %v", f.Items)
	}
	if !strings.Contains(f.Message, "must also be created on every shard") || !strings.Contains(f.Action, "Create ucfm, with the same roles") {
		t.Errorf("message/action: %q / %q", f.Message, f.Action)
	}
	if f := auditFind(audit(t, shardedWithMissingShards()), "prod-shard-access"); f == nil {
		t.Error("audit must warn too")
	}
}

func TestShardAccessStatuses(t *testing.T) {
	res, err := Run(base(), "8.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := checkStatus(res.Checks, "shard-access"); c.Status != StatusNotApplicable {
		t.Errorf("replica set: %+v", c)
	}
	s := shardedWithMissingShards()
	s.Errors = nil
	s.Sharding.Shards = s.Sharding.Shards[:1]
	res, err = Run(s, "8.0", Options{SeeTheFuture: true})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := checkStatus(res.Checks, "shard-access"); c.Status != StatusOK {
		t.Errorf("all shards collected: %+v", c)
	}
}

func TestAuditPerCPUCaches(t *testing.T) {
	s := healthyProd()
	status := func() CheckStatus {
		for _, c := range audit(t, s).Checks {
			if c.RuleID == "prod-tcmalloc-per-cpu" {
				return c.Status
			}
		}
		t.Fatal("prod-tcmalloc-per-cpu not run")
		return ""
	}
	if st := status(); st != StatusNotApplicable {
		t.Errorf("7.0: %s", st)
	}
	for i := range s.Nodes {
		s.Nodes[i].Version, s.Nodes[i].FCV = "8.0.19", "8.0"
		s.Host.THPEnabled = "[always] madvise never"
	}
	if st := status(); st != StatusNotChecked {
		t.Errorf("8.0 without the tcmalloc fields: %s", st)
	}
	for i := range s.Nodes {
		s.Nodes[i].TCMalloc = &snapshot.TCMallocInfo{UsingPerCPUCaches: true, CPUFreeBytes: 4096}
	}
	if st := status(); st != StatusOK {
		t.Errorf("caches on: %s", st)
	}
	s.Nodes[0].TCMalloc.UsingPerCPUCaches = false
	f := auditFind(audit(t, s), "prod-tcmalloc-per-cpu")
	if f == nil || f.Severity != Warning || len(f.Items) != 1 || !strings.Contains(f.Action, "glibc.pthread.rseq=0") {
		t.Fatalf("got %+v", f)
	}
	for i := range s.Nodes {
		s.Nodes[i].HostInfo.CPUArch = "s390x"
	}
	if st := status(); st != StatusNotApplicable {
		t.Errorf("s390x: %s", st)
	}
}
