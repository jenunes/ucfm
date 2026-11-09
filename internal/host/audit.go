package host

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// sysctls read for the production-notes audit (path under /proc/sys).
var auditSysctls = []string{
	"vm.swappiness",
	"vm.zone_reclaim_mode",
	"vm.max_map_count",
	"fs.file-max",
	"kernel.pid_max",
	"kernel.threads-max",
	"net.ipv4.tcp_keepalive_time",
	"net.ipv4.tcp_retries2",
}

// collectAudit fills the HostInfo fields used by `ucfm audit`.
func collectAudit(h *snapshot.HostInfo) {
	h.Sysctls = map[string]string{}
	for _, name := range auditSysctls {
		path := p(filepath.Join("/proc/sys", strings.ReplaceAll(name, ".", "/")))
		if v := readTrim(path); v != "" {
			h.Sysctls[name] = strings.Join(strings.Fields(v), " ")
		}
	}

	if h.DBPath != "" {
		if m, ok := mountFor(p("/proc/mounts"), h.DBPath); ok {
			h.DBPathDevice = m.device
			h.DBPathMountOpts = strings.Split(m.options, ",")
			if q := queueDir(m.device); q != "" {
				h.ReadaheadKB = readTrim(filepath.Join(q, "read_ahead_kb"))
				h.IOScheduler = readTrim(filepath.Join(q, "scheduler"))
			}
		}
	}

	h.NumadRunning = processRunning(p("/proc"), "numad")
	for i := range h.MongodProcesses {
		lp := &h.MongodProcesses[i]
		if b, err := os.ReadFile(p(filepath.Join("/proc", strconv.Itoa(lp.PID), "numa_maps"))); err == nil {
			v := strings.Contains(string(b), "interleave")
			lp.NUMAInterleave = &v
		}
	}

	h.ClockSynced = clockSynced()

	if _, err := os.Stat(p("/sys/fs/selinux")); err == nil {
		switch readTrim(p("/sys/fs/selinux/enforce")) {
		case "1":
			h.SELinux = "enforcing"
		case "0":
			h.SELinux = "permissive"
		default:
			h.SELinux = "disabled"
		}
	}

	if v := readTrim(p("/sys/fs/cgroup/memory.max")); v != "" && v != "max" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			h.CgroupMemoryMaxMB = n / (1 << 20)
		}
	}
}

type mount struct{ point, device, fsType, options string }

// mountFor returns the /proc/mounts entry holding path (longest prefix).
func mountFor(mounts, path string) (mount, bool) {
	b, err := os.ReadFile(mounts)
	if err != nil {
		return mount{}, false
	}
	var best mount
	found := false
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		mp := f[1]
		if (path == mp || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/") || mp == "/") && len(mp) >= len(best.point) {
			best, found = mount{point: mp, device: f[0], fsType: f[2], options: f[3]}, true
		}
	}
	return best, found
}

// queueDir returns the sysfs queue directory of the whole disk behind a
// block device ("/dev/sdb1" -> ".../sdb/queue"), or "" for non-block mounts
// (overlay, tmpfs, NFS...).
func queueDir(device string) string {
	if !strings.HasPrefix(device, "/dev/") {
		return ""
	}
	name := filepath.Base(device)
	if real, err := filepath.EvalSymlinks(p(device)); err == nil {
		name = filepath.Base(real) // /dev/mapper/x -> dm-0
	}
	dir, err := filepath.EvalSymlinks(p(filepath.Join("/sys/class/block", name)))
	if err != nil {
		return ""
	}
	for _, d := range []string{dir, filepath.Dir(dir)} { // partition -> parent disk
		q := filepath.Join(d, "queue")
		if st, err := os.Stat(q); err == nil && st.IsDir() {
			return q
		}
	}
	return ""
}

func processRunning(procDir, comm string) bool {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if readTrim(filepath.Join(procDir, e.Name(), "comm")) == comm {
			return true
		}
	}
	return false
}

// fakeClock reads /clock-synced ("1"/"0") under a test Root.
func fakeClock() *bool {
	switch readTrim(p("/clock-synced")) {
	case "1":
		v := true
		return &v
	case "0":
		v := false
		return &v
	}
	return nil
}
