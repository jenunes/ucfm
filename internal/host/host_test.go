package host

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func write(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectFakeRoot(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/os-release", "NAME=\"Oracle Linux Server\"\nVERSION_ID=\"8.10\"\nID=\"ol\"\n")
	write(t, root, "/proc/sys/kernel/osrelease", "5.15.0-300.el8uek.x86_64\n")
	write(t, root, "/sys/kernel/mm/transparent_hugepage/enabled", "always madvise [never]\n")
	write(t, root, "/sys/kernel/mm/transparent_hugepage/defrag", "always defer [defer+madvise] madvise never\n")
	write(t, root, "/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none", "511\n")
	write(t, root, "/glibc-version", "2.28\n")
	write(t, root, "/proc/cpuinfo", "processor\t: 0\nflags\t\t: fpu sse avx avx2\n\nprocessor\t: 1\nflags\t\t: fpu sse avx avx2\n")
	write(t, root, "/sys/devices/system/node/node0/x", "")
	write(t, root, "/sys/devices/system/node/node1/x", "")
	write(t, root, "/proc/4242/comm", "mongod\n")
	write(t, root, "/proc/4242/cmdline", "/usr/bin/mongod\x00--config\x00/etc/mongod-rs0.conf\x00")
	write(t, root, "/proc/4242/environ", "PATH=/usr/bin\x00GLIBC_TUNABLES=glibc.pthread.rseq=0\x00")
	write(t, root, "/proc/4242/limits", "Limit                     Soft Limit           Hard Limit           Units\nMax open files            64000                64000                files\nMax processes             64000                64000                processes\n")
	write(t, root, "/proc/1/comm", "systemd\n")
	write(t, root, "/etc/mongod-rs0.conf", `
storage:
  dbPath: /
  journal:
    enabled: true
net:
  bindIp: 0.0.0.0
  port: 27017
setParameter:
  enableLocalhostAuthBypass: false
`)
	write(t, root, "/proc/mounts", "rootfs / xfs rw 0 0\n/dev/sdb1 /data ext4 rw 0 0\n")

	old := Root
	Root = root
	defer func() { Root = old }()

	h, err := Collect(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if h.OSRelease["ID"] != "ol" || h.OSRelease["VERSION_ID"] != "8.10" {
		t.Errorf("os-release %v", h.OSRelease)
	}
	if h.THPEnabled != "always madvise [never]" || h.THPMaxPtesNone != "511" || h.GlibcVersion != "2.28" {
		t.Errorf("thp/glibc %q %q %q", h.THPEnabled, h.THPMaxPtesNone, h.GlibcVersion)
	}
	if !reflect.DeepEqual(h.CPUFlags, []string{"avx", "avx2", "fpu", "sse"}) || h.NUMANodes != 2 {
		t.Errorf("cpu %v numa %d", h.CPUFlags, h.NUMANodes)
	}
	if len(h.MongodProcesses) != 1 {
		t.Fatalf("processes %+v", h.MongodProcesses)
	}
	lp := h.MongodProcesses[0]
	if lp.PID != 4242 || lp.GlibcTunables != "glibc.pthread.rseq=0" || !lp.EnvReadable || lp.Limits["Max open files"] != "64000 64000" {
		t.Errorf("process %+v", lp)
	}
	if h.ConfigFile != "/etc/mongod-rs0.conf" {
		t.Errorf("config file %q", h.ConfigFile)
	}
	for k, want := range map[string]string{
		"storage.journal.enabled":                `true`,
		"net.port":                               `27017`,
		"setParameter.enableLocalhostAuthBypass": `false`,
	} {
		if string(h.ConfigOptions[k]) != want {
			t.Errorf("%s = %s, want %s", k, h.ConfigOptions[k], want)
		}
	}
	if h.DBPath != "/" || h.DBPathFS != "xfs" {
		t.Errorf("dbPath %q fs %q", h.DBPath, h.DBPathFS)
	}
}

func TestFsTypeLongestPrefix(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "mounts")
	if err := os.WriteFile(m, []byte("r / ext4 rw 0 0\n/dev/x /var/lib/mongo xfs rw 0 0\n/dev/y /var/lib/mongodb2 ext4 rw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"/var/lib/mongo":      "xfs",
		"/var/lib/mongo/data": "xfs",
		"/var/lib/mongodb2":   "ext4",
		"/srv":                "ext4",
	}
	for path, want := range cases {
		if got := fsType(m, path); got != want {
			t.Errorf("fsType(%s) = %s, want %s", path, got, want)
		}
	}
}
