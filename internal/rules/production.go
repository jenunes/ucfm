package rules

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Production-readiness rules (`ucfm audit`). They judge the deployment against
// the MongoDB Production Notes and Operations Checklist for the release it
// runs now. They use ScopeProduction, which rules.Run (the upgrade check)
// never executes, so they cannot change upgrade findings or exit codes.
// Severities are WARNING or NOTICE only.

const (
	docOpsChecklist  = "https://www.mongodb.com/docs/manual/administration/production-checklist-operations/"
	docUlimit        = "https://www.mongodb.com/docs/manual/reference/ulimit/"
	docSecurityCheck = "https://www.mongodb.com/docs/manual/administration/security-checklist/"
	docOplogSize     = "https://www.mongodb.com/docs/manual/core/replica-set-oplog/"
	docProdLinux     = docProdNotes + "#mongodb-on-linux"
)

// AuditResult is the outcome of a production-readiness audit.
type AuditResult struct {
	Version    string                  `json:"version"`
	Flavor     string                  `json:"flavor"`
	Topology   string                  `json:"topology"`
	EntryHost  string                  `json:"entryHost"`
	Deployment string                  `json:"deployment"`
	Versions   string                  `json:"versions"`
	Host       string                  `json:"host,omitempty"` // host audited with --local
	Checks     []CheckResult           `json:"checks"`
	NotChecked []snapshot.CollectError `json:"collectionErrors,omitempty"`
}

// Findings returns the findings of all audit checks.
func (r *AuditResult) Findings() []Finding { return findingsOf(r.Checks) }

// Counts returns how many findings there are per severity.
func (r *AuditResult) Counts() map[Severity]int { return countFindings(r.Findings()) }

// Max returns the highest severity found (0 when there are none).
func (r *AuditResult) Max() Severity { return maxSeverity(r.Findings()) }

// Audit runs only the production-readiness rules.
func Audit(snap *snapshot.Snapshot) (*AuditResult, error) {
	v := snap.SourceVersion()
	if v == "" {
		return nil, fmt.Errorf("could not determine the running version from the snapshot (no node answered buildInfo)")
	}
	guarded, skipped := guardHost(snap)
	ctx := &Context{Snap: guarded, Source: v, Target: v, Flavor: catalogFlavor(snap.Flavor()), hostSkipped: skipped}
	res := &AuditResult{Version: v, Flavor: snap.Flavor(), Topology: snap.Topology.Kind, EntryHost: snap.EntryHost,
		Deployment: DescribeDeployment(snap), Versions: DescribeVersions(snap),
		Checks: []CheckResult{}, NotChecked: snap.Errors}
	if snap.Host != nil {
		res.Host = snap.Host.Hostname
		res.NotChecked = append(res.NotChecked, snap.Host.Errors...)
	}
	for _, r := range All() {
		if r.Scope != ScopeProduction || !r.AppliesToFlavor(ctx.Flavor) {
			continue
		}
		res.Checks = append(res.Checks, runCheck(r, ctx, ""))
	}
	return res, nil
}

func prodRule(id, title, category string, sev Severity, doc string, check func(*Context) []Finding) Rule {
	return Rule{ID: id, Title: title, Category: category, Scope: ScopeProduction, Severity: sev, DocURL: doc, Check: check}
}

func init() {
	register(
		// ---- host (--local) ----
		prodRule("prod-thp", "Transparent Huge Pages", "host", Warning, docProdLinux, checkProdTHP),
		prodRule("prod-swappiness", "Swappiness", "host", Warning, docProdNotes, checkSwappiness),
		prodRule("prod-numa", "NUMA configuration", "host", Warning, docProdNotes, checkNUMA),
		prodRule("prod-filesystem", "dbPath filesystem type", "host", Warning, docOpsChecklist, checkFilesystem),
		prodRule("prod-noatime", "dbPath mount options", "host", Notice, docProdNotes, checkNoatime),
		prodRule("prod-readahead", "Readahead of the dbPath device", "host", Warning, docOpsChecklist, checkReadahead),
		prodRule("prod-io-scheduler", "I/O scheduler", "host", Notice, docProdNotes, checkScheduler),
		prodRule("prod-ulimits", "Process limits (open files, processes)", "host", Warning, docUlimit, checkUlimits),
		prodRule("prod-kernel-limits", "Kernel limits", "host", Notice, docOpsChecklist, checkKernelLimits),
		prodRule("prod-clock-sync", "Clock synchronization", "host", Warning, docProdNotes, checkClock),
		prodRule("prod-tcp", "TCP keepalive and retries", "host", Notice, docProdNotes, checkTCP),
		prodRule("prod-disk-space", "Free space on the dbPath filesystem", "host", Warning, docOpsChecklist, checkDiskSpace),
		prodRule("prod-selinux-js", "SELinux and server-side JavaScript", "host", Notice, docProdNotes, checkSELinuxJS),
		// ---- platform (hostInfo, remote) ----
		prodRule("prod-kernel-uek", "Oracle Linux kernel (UEK or RHCK)", "platform", Warning, docProdNotes, checkUEK),
		prodRule("prod-cpu-cores", "CPU cores", "platform", Warning, docProdNotes, checkCores),
		// tcmalloc-performance: "To verify that TCMalloc is running with
		// per-CPU caches, ensure that: tcmalloc.usingPerCPUCaches is true."
		// "If per-CPU caches aren't enabled, ensure that: You disable glibc
		// rseq. You're using Linux kernel version 4.18 or later."
		prodRule("prod-tcmalloc-per-cpu", "TCMalloc per-CPU caches", "platform", Warning, docTCMalloc, checkPerCPUCaches),
		// ---- deployment (remote) ----
		prodRule("prod-authorization", "Access control", "security", Warning, docSecurityCheck, checkAuthorization),
		prodRule("prod-tls", "Network encryption (TLS)", "security", Notice, docSecurityCheck, checkTLS),
		prodRule("prod-replset-voting", "Replica set voting members", "topology", Warning, docOpsChecklist, checkVoting),
		prodRule("prod-replset-hostnames", "Replica set member host names", "topology", Notice, docOpsChecklist, checkHostnames),
		prodRule("prod-members-identical", "Member hardware consistency", "topology", Notice, docOpsChecklist, checkIdentical),
		prodRule("prod-journal", "Journaling", "config", Warning, docOpsChecklist, checkJournal),
		prodRule("prod-wt-cache", "WiredTiger cache size", "config", Warning, docProdNotes, checkWTCache),
		prodRule("prod-oplog-window", "Oplog window", "topology", Warning, docOplogSize, checkOplogWindow),
		prodRule("prod-connections", "Connection usage", "config", Warning, docProdNotes, checkConnections),
		prodRule("prod-collection-gaps", "Facts that could not be collected", "path", Warning, "", func(c *Context) []Finding {
			if fs := gapFindings(c, rule("prod-collection-gaps")); len(fs) > 0 {
				return fs
			}
			return c.Checked("%s", gapSummary(c))
		}),
		prodRule("prod-manual-checklist", "Items that need a manual review", "path", Notice, docOpsChecklist, checkManual),
	)
}

// ---------------------------------------------------------------- helpers

func runningAtLeast(c *Context, v string) bool { return snapshot.CompareVersions(c.Source, v) >= 0 }

func optStr(n snapshot.Node, key string) (string, bool) {
	raw, ok := n.Options[key]
	if !ok {
		return "", false
	}
	return jsonScalar(raw), true
}

func hostLabel(h *snapshot.HostInfo) string {
	switch {
	case h.Node != "" && h.Hostname != "" && snapshot.HostPart(h.Node) != h.Hostname:
		return fmt.Sprintf("%s (%s)", h.Hostname, h.Node)
	case h.Node != "":
		return h.Node
	case h.Hostname != "":
		return h.Hostname
	}
	return "local host"
}

func sysctlInt(h *snapshot.HostInfo, name string) (int64, bool) {
	v, ok := h.Sysctls[name]
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.Fields(v)[0], 10, 64)
	return n, err == nil
}

// prod builds a finding for a production rule by ID.
func prod(id string, sev Severity, msg string, items []string, action string) []Finding {
	return []Finding{rule(id).finding(sev, msg, items, action)}
}

// ---------------------------------------------------------------- host

func checkProdTHP(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if h.THPEnabled == "" {
		return c.NotChecked("Transparent Huge Pages settings could not be read on this host.")
	}
	enabled := selected(h.THPEnabled)
	if runningAtLeast(c, "8.0") {
		if legacyTCMallocArch(c.Snap) {
			return c.Checked("%s runs on ppc64le or s390x, whose legacy TCMalloc has no Transparent Huge Pages requirement.", hostLabel(h))
		}
		if enabled == "always" {
			return c.Checked("transparent_hugepage/enabled is always on %s, as MongoDB %s recommends.", hostLabel(h), c.Source)
		}
		return prod("prod-thp", Warning,
			fmt.Sprintf("MongoDB %s should run with Transparent Huge Pages enabled, but %s has transparent_hugepage/enabled = %s.", c.Source, hostLabel(h), enabled),
			nil, "Enable THP (enabled=always, defrag=defer+madvise, khugepaged/max_ptes_none=0) with a boot-time service, then restart mongod.")
	}
	if enabled == "never" {
		return c.Checked("transparent_hugepage/enabled is never on %s, as MongoDB %s and earlier recommend.", hostLabel(h), c.Source)
	}
	return prod("prod-thp", Warning,
		fmt.Sprintf("MongoDB %s and earlier should run with Transparent Huge Pages disabled, but %s has transparent_hugepage/enabled = %s. (This flips when you upgrade to 8.0: see `ucfm check`.)", c.Source, hostLabel(h), enabled),
		nil, "Disable THP (enabled=never, defrag=never) with a boot-time service, then restart mongod.")
}

func checkPerCPUCaches(c *Context) []Finding {
	if legacyTCMallocArch(c.Snap) {
		return c.NotApplicable("ppc64le/s390x use the legacy TCMalloc")
	}
	if !runningAtLeast(c, "8.0") {
		return c.NotApplicable("per-CPU caches come with the TCMalloc of MongoDB 8.0; `ucfm check` covers their prerequisites before upgrading")
	}
	off, reported, _ := perCPUCaches(c.Snap)
	if reported == 0 {
		return c.NotChecked("To run this check, collect the snapshot with this version of ucfm from the live deployment (no server reported serverStatus tcmalloc.usingPerCPUCaches).")
	}
	if len(off) == 0 {
		return c.Checked("TCMalloc uses per-CPU caches on all %s that report it.", count(reported, "server", "servers"))
	}
	return prod("prod-tcmalloc-per-cpu", Warning,
		"TCMalloc is not using per-CPU caches on these servers, so it falls back to per-thread caches: more memory fragmentation and less resilience under load.",
		off, perCPUAction)
}

func checkSwappiness(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if v, ok := sysctlInt(h, "vm.swappiness"); ok && v > 1 {
		return prod("prod-swappiness", Warning,
			fmt.Sprintf("vm.swappiness is %d on %s; the production notes recommend 1 (or 0) so the kernel does not swap mongod memory out.", v, hostLabel(h)),
			nil, "Set vm.swappiness=1 in /etc/sysctl.conf (and in the tuned profile on RHEL).")
	} else if ok {
		return c.Checked("vm.swappiness is %d on %s (recommended 1 or 0).", v, hostLabel(h))
	}
	return c.NotChecked(fmt.Sprintf("vm.swappiness was not reported on %s, so it could not be compared with the recommended 1.", hostLabel(h)))
}

func checkNUMA(c *Context) []Finding {
	h := c.Snap.Host
	numa := false
	for _, n := range c.Snap.Nodes {
		numa = numa || n.HostInfo.NUMAEnabled
	}
	if h == nil {
		if numa {
			return prod("prod-numa", Notice, "At least one member reports NUMA hardware. Interleaving and zone_reclaim_mode could not be verified without --local.",
				nil, "Run `ucfm audit --local` on the NUMA hosts.")
		}
		return c.NotChecked(c.localReason())
	}
	if h.NUMANodes <= 1 && !numa {
		return c.Checked("%s has at most one NUMA node, and no member reports NUMA hardware.", hostLabel(h))
	}
	var items []string
	if v, ok := sysctlInt(h, "vm.zone_reclaim_mode"); ok && v != 0 {
		items = append(items, fmt.Sprintf("vm.zone_reclaim_mode = %d (want 0)", v))
	}
	for _, p := range h.MongodProcesses {
		if p.NUMAInterleave != nil && !*p.NUMAInterleave {
			items = append(items, fmt.Sprintf("%s pid %d is not started with numactl --interleave=all", p.Name, p.PID))
		}
	}
	if h.NumadRunning {
		items = append(items, "numad is running")
	}
	if len(items) == 0 {
		return c.Checked("%s has %s; %s.", hostLabel(h), count(h.NUMANodes, "NUMA node", "NUMA nodes"), numaSetup(h))
	}
	return prod("prod-numa", Warning,
		fmt.Sprintf("%s has %d NUMA nodes. Without interleaving, mongod can show slow performance and periods of high system load.", hostLabel(h), h.NUMANodes),
		items, "Disable NUMA in the BIOS, or set vm.zone_reclaim_mode=0, start mongod with `numactl --interleave=all`, and disable numad.")
}

func checkFilesystem(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if h.DBPathFS == "" {
		return c.NotChecked("The dbPath could not be determined; pass the mongod configuration file with --config.")
	}
	fs := strings.ToLower(h.DBPathFS)
	switch {
	case fs == "xfs":
		return c.Checked("dbPath %s is on XFS on %s.", h.DBPath, hostLabel(h))
	case fs == "ext4":
		return prod("prod-filesystem", Notice,
			fmt.Sprintf("dbPath %s is on ext4. It is supported, but XFS is strongly recommended with WiredTiger.", h.DBPath), nil,
			"Use XFS for new data volumes.")
	case strings.HasPrefix(fs, "nfs"):
		return prod("prod-filesystem", Warning,
			fmt.Sprintf("dbPath %s is on NFS. The operations checklist says to avoid NFS for dbPath: performance is degraded and unstable.", h.DBPath), nil,
			"Move the data to local XFS storage; if NFS is unavoidable use the documented mount options (bg, hard, nolock, noatime, nointr).")
	default:
		return prod("prod-filesystem", Warning,
			fmt.Sprintf("dbPath %s is on %s, not XFS or EXT4 (container overlay storage, shared folders and other filesystems are not recommended).", h.DBPath, h.DBPathFS), nil,
			"Put dbPath on a dedicated XFS volume (for containers, a bind mount or volume on XFS).")
	}
}

func checkNoatime(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if len(h.DBPathMountOpts) == 0 {
		return c.NotChecked("The dbPath mount could not be determined; pass the mongod configuration file with --config.")
	}
	if strings.HasPrefix(h.DBPathFS, "overlay") {
		return c.NotApplicable("dbPath is on container overlay storage")
	}
	for _, o := range h.DBPathMountOpts {
		if o == "noatime" {
			return c.Checked("the filesystem holding dbPath %s is mounted with noatime on %s.", h.DBPath, hostLabel(h))
		}
	}
	return prod("prod-noatime", Notice,
		fmt.Sprintf("The filesystem holding dbPath %s is mounted without noatime (%s).", h.DBPath, strings.Join(h.DBPathMountOpts, ",")), nil,
		"Add noatime to the dbPath mount options in /etc/fstab and remount.")
}

func checkReadahead(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if h.ReadaheadKB == "" {
		return c.NotApplicable("dbPath is not on a local block device")
	}
	kb, err := strconv.Atoi(h.ReadaheadKB)
	if err != nil {
		return c.Checked("the readahead of %s on %s was reported as %q and could not be compared with 8–32 sectors.", h.DBPathDevice, hostLabel(h), h.ReadaheadKB)
	}
	sectors := kb * 2 // 512-byte sectors
	if sectors >= 8 && sectors <= 32 {
		return c.Checked("readahead on %s (dbPath %s) is %d sectors on %s (recommended 8–32).", h.DBPathDevice, h.DBPath, sectors, hostLabel(h))
	}
	return prod("prod-readahead", Warning,
		fmt.Sprintf("Readahead on %s (dbPath %s) is %d sectors (%d KB); the recommendation for WiredTiger is 8–32 sectors.", h.DBPathDevice, h.DBPath, sectors, kb), nil,
		"Set it with `blockdev --setra 32 <device>` (or 16) and persist it with a udev rule or tuned profile.")
}

func checkScheduler(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if h.IOScheduler == "" {
		return c.NotApplicable("dbPath is not on a local block device")
	}
	s := selected(h.IOScheduler)
	switch s {
	case "none", "mq-deadline", "kyber", "noop":
		return c.Checked("the I/O scheduler of %s is %s on %s.", h.DBPathDevice, s, hostLabel(h))
	}
	return prod("prod-io-scheduler", Notice,
		fmt.Sprintf("The I/O scheduler of %s is %s.", h.DBPathDevice, s), nil,
		"Use none for SSD/NVMe and virtual disks, mq-deadline for spinning disks (kyber for mixed workloads in one VM).")
}

func checkUlimits(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	var items []string
	for _, p := range h.MongodProcesses {
		for _, lim := range []string{"Max open files", "Max processes"} {
			v := strings.Fields(p.Limits[lim])
			if len(v) == 0 || v[0] == "unlimited" {
				continue
			}
			if n, err := strconv.Atoi(v[0]); err == nil && n < 64000 {
				items = append(items, fmt.Sprintf("%s pid %d: %s soft limit %d", p.Name, p.PID, lim, n))
			}
		}
	}
	if len(items) == 0 {
		if len(h.MongodProcesses) == 0 {
			return c.Checked("no running mongod or mongos process was found on %s, so there were no process limits to read.", hostLabel(h))
		}
		return c.Checked("open files and processes limits are at least 64000 (or unlimited) for %s on %s.",
			count(len(h.MongodProcesses), "mongod/mongos process", "mongod/mongos processes"), hostLabel(h))
	}
	return prod("prod-ulimits", Warning,
		"Low per-process limits cause failed connections and loss of service under load.", items,
		"Set LimitNOFILE=64000 and LimitNPROC=64000 (systemd) or the equivalent ulimit settings, then restart mongod.")
}

func checkKernelLimits(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	want := []struct {
		name string
		min  int64
	}{{"vm.max_map_count", 131060}, {"fs.file-max", 98000}, {"kernel.pid_max", 64000}, {"kernel.threads-max", 64000}}
	var items, read []string
	for _, w := range want {
		v, ok := sysctlInt(h, w.name)
		if ok {
			read = append(read, w.name)
		}
		if ok && v < w.min {
			items = append(items, fmt.Sprintf("%s = %d (starting value %d)", w.name, v, w.min))
		}
	}
	if len(items) == 0 {
		if len(read) == 0 {
			return c.Checked("none of vm.max_map_count, fs.file-max, kernel.pid_max or kernel.threads-max was reported on %s.", hostLabel(h))
		}
		verb := "are"
		if len(read) == 1 {
			verb = "is"
		}
		return c.Checked("%s %s at or above the operations checklist's starting values on %s.", prodJoinAnd(read), verb, hostLabel(h))
	}
	return prod("prod-kernel-limits", Notice,
		"These kernel limits are below the operations checklist's starting values for large systems.", items,
		"Raise them in /etc/sysctl.conf if the deployment has many connections, collections or indexes.")
}

func checkClock(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if h.ClockSynced == nil {
		return c.NotChecked("The clock synchronization state could not be read on this host.")
	}
	if *h.ClockSynced {
		return c.Checked("the kernel reports the clock of %s as synchronized.", hostLabel(h))
	}
	return prod("prod-clock-sync", Warning,
		fmt.Sprintf("The kernel reports the clock of %s as not synchronized. Clock drift between members (critical for sharded clusters) makes communication unreliable.", hostLabel(h)), nil,
		"Run an NTP-compatible daemon (chrony, ntpd or systemd-timesyncd) on every host.")
}

func checkTCP(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	var items, read []string
	if v, ok := sysctlInt(h, "net.ipv4.tcp_keepalive_time"); ok {
		read = append(read, fmt.Sprintf("net.ipv4.tcp_keepalive_time is %d (at most 300)", v))
		if v > 300 {
			items = append(items, fmt.Sprintf("net.ipv4.tcp_keepalive_time = %d (120 recommended; mongod/mongos cap their own sockets at 300)", v))
		}
	}
	if v, ok := sysctlInt(h, "net.ipv4.tcp_retries2"); ok {
		read = append(read, fmt.Sprintf("net.ipv4.tcp_retries2 is %d (at most 5)", v))
		if v > 5 {
			items = append(items, fmt.Sprintf("net.ipv4.tcp_retries2 = %d (5 or lower avoids long stalls before timeouts)", v))
		}
	}
	if len(items) == 0 {
		if len(read) == 0 {
			return c.NotChecked(fmt.Sprintf("net.ipv4.tcp_keepalive_time and net.ipv4.tcp_retries2 were not reported on %s.", hostLabel(h)))
		}
		return c.Checked("%s on %s.", prodJoinAnd(read), hostLabel(h))
	}
	return prod("prod-tcp", Notice, "TCP settings differ from the production notes.", items,
		"Set them in /etc/sysctl.conf; keepalive matters most behind load balancers and firewalls with idle timeouts.")
}

func checkDiskSpace(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if h.DBPathFreeMB == 0 && h.DBPathUsedMB == 0 {
		return c.NotChecked("The dbPath could not be determined; pass the mongod configuration file with --config.")
	}
	total := h.DBPathFreeMB + h.DBPathUsedMB
	pct := float64(h.DBPathFreeMB) * 100 / float64(max(total, 1))
	if pct >= 15 && h.DBPathFreeMB >= 4096 {
		return c.Checked("the dbPath filesystem on %s has %d MB free (%.0f%%; minimum 15%% and 4096 MB).", hostLabel(h), h.DBPathFreeMB, pct)
	}
	return prod("prod-disk-space", Warning,
		fmt.Sprintf("The dbPath filesystem has %d MB free (%.0f%%). Upgrades, initial syncs and compaction need headroom.", h.DBPathFreeMB, pct), nil,
		"Add space or clean up before upgrading; monitor disk usage with alerts.")
}

func checkSELinuxJS(c *Context) []Finding {
	if c.Snap.Host == nil {
		return c.NotChecked(c.localReason())
	}
	h := c.Snap.Host
	if h.SELinux != "enforcing" {
		mode := h.SELinux
		if mode == "" {
			mode = "not reported (no SELinux)"
		}
		return c.Checked("SELinux is %s on %s, so server-side JavaScript cannot trigger the SELinux crash.", mode, hostLabel(h))
	}
	for _, n := range c.Snap.DataNodes() {
		if v, ok := optStr(n, "security.javascriptEnabled"); ok && v == "false" {
			return c.Checked("SELinux is enforcing on %s, and server-side JavaScript is disabled (security.javascriptEnabled: false on %s).", hostLabel(h), n.Host)
		}
	}
	return prod("prod-selinux-js", Notice,
		"SELinux is enforcing and server-side JavaScript is enabled; the production notes warn this combination can make mongod segfault.", nil,
		"Set security.javascriptEnabled: false unless you need $where, $function, $accumulator or mapReduce.")
}

// ---------------------------------------------------------------- platform

func checkUEK(c *Context) []Finding {
	var items []string
	for k, hosts := range kernelVersions(c.Snap) {
		if strings.Contains(strings.ToLower(k), "uek") {
			items = append(items, fmt.Sprintf("%s [%s]", k, summarizeHosts(hosts)))
		}
	}
	if len(items) == 0 {
		hosts := 0
		for _, hs := range kernelVersions(c.Snap) {
			hosts += len(hs)
		}
		if hosts == 0 {
			return c.NotChecked("no member reported its kernel version, so none is known to run the Oracle UEK kernel.")
		}
		return c.Checked("none of the %s that reported a kernel runs the Oracle UEK kernel.", members(hosts))
	}
	sort.Strings(items)
	return prod("prod-kernel-uek", Warning,
		"These hosts run the Oracle Unbreakable Enterprise Kernel, which MongoDB does not support; use the Red Hat Compatible Kernel (RHCK).", items,
		"Boot the RHCK kernel on Oracle Linux hosts.")
}

func checkCores(c *Context) []Finding {
	var items []string
	for _, n := range c.Snap.Nodes {
		if n.HostInfo.NumCores > 0 && n.HostInfo.NumCores < 2 {
			items = append(items, fmt.Sprintf("%s: %d core", n.Host, n.HostInfo.NumCores))
		}
	}
	if len(items) == 0 {
		lowest, host, reported := 0, "", 0
		for _, n := range c.Snap.Nodes {
			if k := n.HostInfo.NumCores; k > 0 {
				reported++
				if lowest == 0 || k < lowest {
					lowest, host = k, n.Host
				}
			}
		}
		if reported == 0 {
			return c.NotChecked("no member reported its CPU core count.")
		}
		return c.Checked("all %s that reported it have at least 2 CPU cores (fewest: %d on %s).", members(reported), lowest, host)
	}
	return prod("prod-cpu-cores", Warning, "The production notes require at least two real cores per mongod or mongos.", items, "Give these hosts more cores.")
}

// ---------------------------------------------------------------- deployment

func authEnabled(n snapshot.Node) bool {
	if v, ok := optStr(n, "security.authorization"); ok && v == "enabled" {
		return true
	}
	if _, ok := optStr(n, "security.keyFile"); ok {
		return true
	}
	if v, ok := optStr(n, "security.clusterAuthMode"); ok && v != "" && v != "keyFile" {
		return true
	}
	return false
}

func checkAuthorization(c *Context) []Finding {
	var open, exposed []string
	checked := 0
	for _, n := range c.Snap.Nodes {
		if n.Role == snapshot.RoleArbiter || n.Options == nil {
			continue
		}
		checked++
		if authEnabled(n) {
			continue
		}
		open = append(open, n.Host)
		bind, _ := optStr(n, "net.bindIp")
		all, _ := optStr(n, "net.bindIpAll")
		if all == "true" || strings.Contains(bind, "0.0.0.0") || strings.Contains(bind, "::") {
			exposed = append(exposed, n.Host)
		}
	}
	if len(open) == 0 {
		if checked == 0 {
			return c.NotChecked("no member reported its startup options, so access control could not be read.")
		}
		return c.Checked("access control is enabled on all %s (arbiters excluded).", members(checked))
	}
	msg := "Access control is not enabled: anyone who can reach these members can read and change all data."
	if len(exposed) > 0 {
		msg += fmt.Sprintf(" %d of them listen on all interfaces.", len(exposed))
	}
	return prod("prod-authorization", Warning, msg, open,
		"Enable security.authorization (and keyFile or x.509 internal authentication), following the security checklist.")
}

func checkTLS(c *Context) []Finding {
	var plain []string
	checked := 0
	for _, n := range c.Snap.Nodes {
		if n.Role == snapshot.RoleArbiter || n.Options == nil {
			continue
		}
		checked++
		mode, ok := optStr(n, "net.tls.mode")
		if !ok {
			mode, ok = optStr(n, "net.ssl.mode")
		}
		if !ok || mode == "disabled" {
			plain = append(plain, n.Host)
		}
	}
	if len(plain) == 0 {
		if checked == 0 {
			return c.NotChecked("no member reported its startup options, so the TLS mode could not be read.")
		}
		return c.Checked("TLS is enabled on all %s (arbiters excluded).", members(checked))
	}
	return prod("prod-tls", Notice, "These members accept unencrypted connections.", plain,
		"Configure TLS (net.tls.mode requireTLS) for client and intra-cluster traffic if the network is not fully trusted.")
}

func checkVoting(c *Context) []Finding {
	if len(c.Snap.Topology.ReplSets) == 0 {
		return c.NotApplicable("not a replica set")
	}
	var items, sets []string
	for _, rs := range c.Snap.Topology.ReplSets {
		voters, dataVoters := 0, 0
		for _, m := range rs.Members {
			if m.Votes > 0 {
				voters++
				if !m.ArbiterOnly {
					dataVoters++
				}
			}
		}
		if voters%2 == 0 && voters > 0 {
			items = append(items, fmt.Sprintf("%s: %d voting members (even)", rs.Name, voters))
		}
		if dataVoters < 3 {
			items = append(items, fmt.Sprintf("%s: %s", rs.Name, count(dataVoters, "data-bearing voting member", "data-bearing voting members")))
		}
		sets = append(sets, fmt.Sprintf("%s has %d voting members, %d data-bearing", rs.Name, voters, dataVoters))
	}
	if len(items) == 0 {
		if len(sets) == 1 {
			return c.Checked("%s (odd, and at least 3 data-bearing).", sets[0])
		}
		return c.Checked("each of the %d replica sets has an odd number of voting members, at least 3 of them data-bearing.", len(sets))
	}
	return prod("prod-replset-voting", Warning,
		"Replica sets need an odd number of voters and at least three data-bearing voting members to keep a majority (and majority writes) through a member failure or restart.", items,
		"Add data-bearing members (or adjust votes) so each set has an odd number of voters, at least three of them data-bearing.")
}

func checkHostnames(c *Context) []Finding {
	if len(c.Snap.Topology.ReplSets) == 0 {
		return c.NotApplicable("not a replica set")
	}
	var items []string
	total := 0
	for _, rs := range c.Snap.Topology.ReplSets {
		for _, m := range rs.Members {
			total++
			host := m.Host
			if h, _, err := net.SplitHostPort(m.Host); err == nil {
				host = h
			}
			if net.ParseIP(host) != nil {
				items = append(items, rs.Name+"/"+m.Host)
			}
		}
	}
	if len(items) == 0 {
		return c.Checked("all %s of %s use hostnames, not IP addresses.", members(total), count(len(c.Snap.Topology.ReplSets), "replica set", "replica sets"))
	}
	return prod("prod-replset-hostnames", Notice,
		"These replica set members are configured with IP addresses. Hostnames survive IP changes and are required for TLS hostname validation.", items,
		"Reconfigure the members with resolvable hostnames (every host must also resolve itself).")
}

func checkIdentical(c *Context) []Finding {
	if len(c.Snap.Topology.ReplSets) == 0 {
		return c.NotApplicable("not a replica set")
	}
	hidden := map[string]bool{}
	for _, rs := range c.Snap.Topology.ReplSets {
		for _, m := range rs.Members {
			if m.Hidden || m.ArbiterOnly {
				hidden[m.Host] = true
			}
		}
	}
	bySet := map[string][]snapshot.Node{}
	for _, n := range c.Snap.DataNodes() {
		if n.ReplSet != "" && !hidden[n.Host] && n.HostInfo.MemSizeMB > 0 {
			bySet[n.ReplSet] = append(bySet[n.ReplSet], n)
		}
	}
	var items []string
	for _, set := range sortedKeys(bySet) {
		nodes := bySet[set]
		lo, hi := nodes[0], nodes[0]
		cores := map[int]bool{}
		for _, n := range nodes {
			if n.HostInfo.MemSizeMB < lo.HostInfo.MemSizeMB {
				lo = n
			}
			if n.HostInfo.MemSizeMB > hi.HostInfo.MemSizeMB {
				hi = n
			}
			cores[n.HostInfo.NumCores] = true
		}
		if float64(hi.HostInfo.MemSizeMB) > float64(lo.HostInfo.MemSizeMB)*1.1 {
			items = append(items, fmt.Sprintf("%s: RAM from %d MB (%s) to %d MB (%s)", set, lo.HostInfo.MemSizeMB, lo.Host, hi.HostInfo.MemSizeMB, hi.Host))
		}
		if len(cores) > 1 {
			items = append(items, fmt.Sprintf("%s: members have different core counts", set))
		}
	}
	if len(items) == 0 {
		if len(bySet) == 0 {
			return c.Checked("no non-hidden member reported its memory size, so there was nothing to compare.")
		}
		return c.Checked("in each of %s, the non-hidden members have the same core count and RAM within 10%%.", count(len(bySet), "replica set", "replica sets"))
	}
	return prod("prod-members-identical", Notice,
		"Non-hidden members should be identical in RAM, CPU, disk and network: any of them can become primary.", items,
		"Size the smaller members like the largest one.")
}

func checkJournal(c *Context) []Finding {
	var off []string
	for _, n := range c.Snap.DataNodes() {
		if v, ok := optStr(n, "storage.journal.enabled"); ok && v == "false" {
			off = append(off, n.Host)
		}
	}
	if len(off) == 0 {
		return c.Checked("journaling is not disabled on any of the %s.", count(len(c.Snap.DataNodes()), "data-bearing member", "data-bearing members"))
	}
	return prod("prod-journal", Warning, "Journaling is disabled on these members; a crash can lose acknowledged writes.", off,
		"Enable journaling (remove storage.journal.enabled: false / --nojournal).")
}

func checkWTCache(c *Context) []Finding {
	var items []string
	set := 0
	for _, n := range c.Snap.DataNodes() {
		raw, ok := n.Options["storage.wiredTiger.engineConfig.cacheSizeGB"]
		if !ok {
			continue
		}
		set++
		gb, err := strconv.ParseFloat(jsonScalar(raw), 64)
		if err != nil {
			continue
		}
		cacheMB := int64(gb * 1024)
		mem := n.HostInfo.MemLimitMB
		if mem == 0 {
			mem = n.HostInfo.MemSizeMB
		}
		if mem == 0 {
			continue
		}
		def := max((mem-1024)/2, 256)
		switch {
		case float64(cacheMB) > float64(mem)*0.8:
			items = append(items, fmt.Sprintf("%s: cacheSizeGB %.2f is more than 80%% of the %d MB available", n.Host, gb, mem))
		case cacheMB > def:
			items = append(items, fmt.Sprintf("%s: cacheSizeGB %.2f is above the default (%d MB for %d MB of memory)", n.Host, gb, def, mem))
		}
	}
	if len(items) == 0 {
		if set == 0 {
			return c.Checked("no member sets cacheSizeGB, so all %s use the default WiredTiger cache size.", count(len(c.Snap.DataNodes()), "data-bearing member", "data-bearing members"))
		}
		return c.Checked("cacheSizeGB is set on %s and stays within the default size and 80%% of memory.", members(set))
	}
	return prod("prod-wt-cache", Warning,
		"The WiredTiger cache is set larger than the production notes recommend; the OS filesystem cache and mongod's other memory need room (and containers must stay below their memory limit).", items,
		"Remove cacheSizeGB to use the default, or lower it below the container or host memory limit.")
}

func checkOplogWindow(c *Context) []Finding {
	var warn, notice []string
	checked, shortest, shortestHost := 0, -1.0, ""
	for _, n := range c.Snap.DataNodes() {
		o := n.Oplog
		if o == nil || o.MaxSizeMB == 0 || o.First.IsZero() {
			continue
		}
		checked++
		full := float64(o.UsedMB) >= float64(o.MaxSizeMB)*0.9
		window := o.WindowHours
		if !full && o.UsedMB > 0 {
			window = o.WindowHours * float64(o.MaxSizeMB) / float64(o.UsedMB)
		}
		if full || o.UsedMB > 0 {
			if shortest < 0 || window < shortest {
				shortest, shortestHost = window, n.Host
			}
		}
		switch {
		case full && o.WindowHours < 24:
			warn = append(warn, fmt.Sprintf("%s: %.1f h window (oplog %d MB, full)", n.Host, o.WindowHours, o.MaxSizeMB))
		case full && o.WindowHours < 72:
			notice = append(notice, fmt.Sprintf("%s: %.1f h window (oplog %d MB, full)", n.Host, o.WindowHours, o.MaxSizeMB))
		case !full && o.UsedMB > 0:
			proj := o.WindowHours * float64(o.MaxSizeMB) / float64(o.UsedMB)
			if proj < 24 {
				warn = append(warn, fmt.Sprintf("%s: oplog %d/%d MB used; projected window ≈ %.1f h at the current write rate", n.Host, o.UsedMB, o.MaxSizeMB, proj))
			}
		}
	}
	if len(warn) == 0 && len(notice) == 0 {
		switch {
		case checked == 0:
			return c.NotChecked("no member reported its oplog size and window.")
		case shortest < 0:
			return c.NotChecked(fmt.Sprintf("the oplog of %s has no writes yet, so its window cannot be measured.", members(checked)))
		}
		return c.Checked("checked the oplog of %s; the shortest window is %.1f hours on %s (minimum 24; 72 when the oplog is full).", members(checked), shortest, shortestHost)
	}
	var out []Finding
	if len(warn) > 0 {
		out = append(out, rule("prod-oplog-window").finding(Warning,
			"The oplog window is shorter than a day. A member that is down longer than the window (for example during a slow upgrade or restore) needs a full initial sync.",
			warn, "Grow the oplog with replSetResizeOplog (or storage.oplogMinRetentionHours) to cover maintenance windows and restore time."))
	}
	if len(notice) > 0 {
		out = append(out, rule("prod-oplog-window").finding(Notice,
			"The oplog window is under three days.", notice,
			"Check it covers your longest planned maintenance and the time to restore from backup."))
	}
	return out
}

func checkConnections(c *Context) []Finding {
	var items []string
	checked, highest, highestHost := 0, 0.0, ""
	for _, n := range c.Snap.Nodes {
		cn := n.Connections
		if cn == nil || cn.Current+cn.Available == 0 {
			continue
		}
		pct := float64(cn.Current) * 100 / float64(cn.Current+cn.Available)
		checked++
		if pct >= highest {
			highest, highestHost = pct, n.Host
		}
		if pct >= 80 {
			items = append(items, fmt.Sprintf("%s: %d of %d connections in use (%.0f%%)", n.Host, cn.Current, cn.Current+cn.Available, pct))
		}
	}
	if len(items) == 0 {
		if checked == 0 {
			return c.NotChecked("no member reported its connection counts.")
		}
		return c.Checked("connection usage on %s is at most %.0f%% of the limit (%s; warning at 80%%).", members(checked), highest, highestHost)
	}
	return prod("prod-connections", Warning, "These members are close to their connection limit.", items,
		"Review driver pool sizes (maxPoolSize), net.maxIncomingConnections and the open-files limit.")
}

func checkManual(c *Context) []Finding {
	items := []string{
		"RAID-10 on SSDs; no RAID-5/6; partitions aligned with the RAID geometry",
		"Provisioned IOPS or dedicated drives on SANs/VMs; no memory ballooning; replica set members not on the same SAN",
		"Monitoring with alerts on replication lag, oplog window, assertions, queues, page faults and disk space",
		"Regular, tested backups and restores",
		"Antivirus/EDR excludes dbPath and the log path",
		"No load balancer between cluster components; client affinity (sticky sessions) on load balancers in front of mongos",
		"Members spread across at least three data centers for high availability",
		"Security checklist reviewed (authentication, authorization, TLS, network exposure, auditing)",
	}
	return prod("prod-manual-checklist", Notice,
		"These Production Notes / Operations Checklist items cannot be verified from the database or host and need a manual review.", items, "")
}

// numaSetup describes a NUMA host that passed: zone reclaim, interleaving
// of the local mongod processes and numad.
func numaSetup(h *snapshot.HostInfo) string {
	var parts []string
	if v, ok := sysctlInt(h, "vm.zone_reclaim_mode"); ok {
		parts = append(parts, fmt.Sprintf("vm.zone_reclaim_mode is %d", v))
	}
	interleaved := 0
	for _, p := range h.MongodProcesses {
		if p.NUMAInterleave != nil && *p.NUMAInterleave {
			interleaved++
		}
	}
	if interleaved > 0 {
		parts = append(parts, fmt.Sprintf("%s run with numactl --interleave=all", count(interleaved, "mongod process", "mongod processes")))
	}
	parts = append(parts, "numad is not running")
	return prodJoinAnd(parts)
}

// prodJoinAnd writes "a", "a and b" or "a, b and c".
func prodJoinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}
