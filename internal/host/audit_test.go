package host

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCollectAuditFakeRoot(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/proc/sys/vm/swappiness", "60\n")
	write(t, root, "/proc/sys/vm/zone_reclaim_mode", "1\n")
	write(t, root, "/proc/sys/net/ipv4/tcp_keepalive_time", "7200\n")
	write(t, root, "/proc/mounts", "rootfs / ext4 rw 0 0\n/dev/sdb1 /data xfs rw,relatime,attr2 0 0\n")
	// /sys/class/block/sdb1 -> ../../devices/x/sdb/sdb1; the queue lives on the disk.
	write(t, root, "/sys/devices/x/sdb/queue/read_ahead_kb", "4096\n")
	write(t, root, "/sys/devices/x/sdb/queue/scheduler", "none [mq-deadline] kyber\n")
	if err := os.MkdirAll(filepath.Join(root, "/sys/devices/x/sdb/sdb1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "/sys/class/block"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../devices/x/sdb/sdb1", filepath.Join(root, "/sys/class/block/sdb1")); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/proc/77/comm", "numad\n")
	write(t, root, "/proc/4242/comm", "mongod\n")
	write(t, root, "/proc/4242/numa_maps", "55d0 default file=/usr/bin/mongod\n7f00 interleave:0-1 anon=10\n")
	write(t, root, "/clock-synced", "0\n")
	write(t, root, "/sys/fs/selinux/enforce", "1\n")
	write(t, root, "/sys/fs/cgroup/memory.max", "2147483648\n")
	write(t, root, "/etc/mongod.conf", "storage:\n  dbPath: /data/db\n")
	if err := os.MkdirAll(filepath.Join(root, "/data/db"), 0o755); err != nil {
		t.Fatal(err)
	}

	old := Root
	Root = root
	defer func() { Root = old }()
	h, err := Collect(Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"vm.swappiness": "60", "vm.zone_reclaim_mode": "1", "net.ipv4.tcp_keepalive_time": "7200"}
	if !reflect.DeepEqual(h.Sysctls, want) {
		t.Errorf("sysctls %v", h.Sysctls)
	}
	if h.DBPathFS != "xfs" || h.DBPathDevice != "/dev/sdb1" || !reflect.DeepEqual(h.DBPathMountOpts, []string{"rw", "relatime", "attr2"}) {
		t.Errorf("mount %q %q %v", h.DBPathFS, h.DBPathDevice, h.DBPathMountOpts)
	}
	if h.ReadaheadKB != "4096" || h.IOScheduler != "none [mq-deadline] kyber" {
		t.Errorf("queue %q %q", h.ReadaheadKB, h.IOScheduler)
	}
	if !h.NumadRunning || h.SELinux != "enforcing" || h.CgroupMemoryMaxMB != 2048 {
		t.Errorf("numad %v selinux %q cgroup %d", h.NumadRunning, h.SELinux, h.CgroupMemoryMaxMB)
	}
	if h.ClockSynced == nil || *h.ClockSynced {
		t.Errorf("clock %v", h.ClockSynced)
	}
	if len(h.MongodProcesses) != 1 || h.MongodProcesses[0].NUMAInterleave == nil || !*h.MongodProcesses[0].NUMAInterleave {
		t.Errorf("numa interleave %+v", h.MongodProcesses)
	}
}

func TestQueueDirNonBlock(t *testing.T) {
	if q := queueDir("overlay"); q != "" {
		t.Errorf("overlay should have no queue, got %q", q)
	}
}
