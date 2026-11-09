// Package host collects facts from the local machine (ucfm --local): the
// mongod configuration file, kernel THP settings, glibc, CPU flags, NUMA,
// limits and environment of running mongod processes, and dbPath filesystem.
// Everything is read-only and Linux-specific; on other systems it returns an
// error.
package host

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Root is prepended to every absolute path read; tests point it at a fake
// filesystem tree.
var Root = "/"

func p(path string) string { return filepath.Join(Root, path) }

// Options for host collection.
type Options struct {
	ConfigFile string // explicit mongod.conf; empty = auto-detect
	DBPath     string // explicit dbPath; empty = from the config file
}

// Collect gathers host facts. Individual failures are recorded in
// HostInfo.Errors; only an unsupported OS is fatal.
func Collect(o Options) (*snapshot.HostInfo, error) {
	if runtime.GOOS != "linux" && Root == "/" {
		return nil, fmt.Errorf("--local host checks are only supported on Linux (running on %s)", runtime.GOOS)
	}
	h := &snapshot.HostInfo{}
	addErr := func(what string, err error) {
		h.Errors = append(h.Errors, snapshot.CollectError{Scope: "host", Command: what, Message: err.Error()})
	}

	h.Hostname, _ = os.Hostname()
	if osr, err := readOSRelease(p("/etc/os-release")); err != nil {
		addErr("os-release", err)
	} else {
		h.OSRelease = osr
	}
	h.KernelVersion = readTrim(p("/proc/sys/kernel/osrelease"))
	h.THPEnabled = readTrim(p("/sys/kernel/mm/transparent_hugepage/enabled"))
	h.THPDefrag = readTrim(p("/sys/kernel/mm/transparent_hugepage/defrag"))
	h.THPMaxPtesNone = readTrim(p("/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none"))
	if h.THPEnabled == "" {
		addErr("transparent_hugepage", errors.New("cannot read /sys/kernel/mm/transparent_hugepage/enabled (container or non-Linux kernel?)"))
	}
	h.GlibcVersion = glibcVersion()
	h.CPUFlags = cpuFlags(p("/proc/cpuinfo"))
	h.NUMANodes = numaNodes(p("/sys/devices/system/node"))
	h.MongodProcesses = mongodProcesses(p("/proc"))

	// Configuration file: explicit, else the one a local mongod was started
	// with, else the package default.
	cfg := o.ConfigFile
	if cfg == "" {
		cfg = configFromProcesses(h.MongodProcesses)
	}
	if cfg == "" {
		if _, err := os.Stat(p("/etc/mongod.conf")); err == nil {
			cfg = "/etc/mongod.conf"
		}
	}
	if cfg != "" {
		h.ConfigFile = cfg
		opts, err := ParseConfigFile(p(cfg))
		if err != nil {
			addErr("config-file", err)
		} else {
			h.ConfigOptions = opts
		}
	}

	dbPath := o.DBPath
	if dbPath == "" && h.ConfigOptions != nil {
		if raw, ok := h.ConfigOptions["storage.dbPath"]; ok {
			_ = json.Unmarshal(raw, &dbPath)
		}
	}
	if dbPath != "" {
		h.DBPath = dbPath
		h.DBPathFS = fsType(p("/proc/mounts"), dbPath)
		var st syscall.Statfs_t
		if err := syscall.Statfs(p(dbPath), &st); err != nil {
			addErr("statfs", err)
		} else {
			bs := int64(st.Bsize)
			h.DBPathFreeMB = int64(st.Bavail) * bs / (1 << 20)
			h.DBPathUsedMB = (int64(st.Blocks) - int64(st.Bfree)) * bs / (1 << 20)
		}
	}
	collectAudit(h)
	return h, nil
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out, sc.Err()
}

// glibcVersion asks getconf, which is part of glibc itself.
func glibcVersion() string {
	if Root != "/" {
		return readTrim(p("/glibc-version")) // test hook
	}
	out, err := exec.Command("getconf", "GNU_LIBC_VERSION").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out)) // "glibc 2.35"
	if len(f) == 2 {
		return f[1]
	}
	return ""
}

func cpuFlags(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		k = strings.TrimSpace(k)
		if ok && (k == "flags" || k == "Features") { // x86 / arm64
			flags := strings.Fields(v)
			sort.Strings(flags)
			return flags
		}
	}
	return nil
}

func numaNodes(dir string) int {
	m, _ := filepath.Glob(filepath.Join(dir, "node[0-9]*"))
	return len(m)
}

// mongodProcesses scans /proc for mongod and mongos.
func mongodProcesses(procDir string) []snapshot.LocalProcess {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil
	}
	var out []snapshot.LocalProcess
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(procDir, e.Name())
		name := readTrim(filepath.Join(dir, "comm"))
		if name != "mongod" && name != "mongos" {
			continue
		}
		lp := snapshot.LocalProcess{PID: pid, Name: name}
		if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
			for _, a := range bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0}) {
				lp.Cmdline = append(lp.Cmdline, string(a))
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, "environ")); err == nil {
			lp.EnvReadable = true
			for _, kv := range bytes.Split(b, []byte{0}) {
				if v, ok := bytes.CutPrefix(kv, []byte("GLIBC_TUNABLES=")); ok {
					lp.GlibcTunables = string(v)
				}
			}
		}
		lp.Limits = readLimits(filepath.Join(dir, "limits"))
		out = append(out, lp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// readLimits parses /proc/<pid>/limits ("Max open files  64000  64000  files").
func readLimits(path string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	want := []string{"Max open files", "Max processes", "Max locked memory", "Max address space", "Max file size", "Max cpu time", "Max resident set"}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		for _, w := range want {
			if rest, ok := strings.CutPrefix(line, w); ok {
				f := strings.Fields(rest)
				if len(f) >= 2 {
					out[w] = f[0] + " " + f[1]
				}
			}
		}
	}
	return out
}

// configFromProcesses finds "--config X" / "-f X" in a mongod command line.
func configFromProcesses(ps []snapshot.LocalProcess) string {
	for _, lp := range ps {
		for i, a := range lp.Cmdline {
			switch {
			case (a == "--config" || a == "-f") && i+1 < len(lp.Cmdline):
				return lp.Cmdline[i+1]
			case strings.HasPrefix(a, "--config="):
				return strings.TrimPrefix(a, "--config=")
			}
		}
	}
	return ""
}

// ParseConfigFile flattens a mongod YAML configuration into dotted keys.
// setParameter children become "setParameter.<name>".
func ParseConfigFile(path string) (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := map[string]json.RawMessage{}
	flattenYAML("", root, out)
	return out, nil
}

func flattenYAML(prefix string, v any, out map[string]json.RawMessage) {
	if m, ok := v.(map[string]any); ok && len(m) > 0 {
		for k, child := range m {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenYAML(key, child, out)
		}
		return
	}
	if prefix == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(strconv.Quote(fmt.Sprint(v)))
	}
	out[prefix] = b
}

// fsType returns the filesystem type of the mount holding path.
func fsType(mounts, path string) string {
	m, _ := mountFor(mounts, path)
	return m.fsType
}
