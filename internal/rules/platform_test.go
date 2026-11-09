package rules

import (
	"strings"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// withPlatforms swaps in a small support table for the test.
func withPlatforms(t *testing.T, flavor, release string, list []PlatformEntry) {
	t.Helper()
	oldOS, oldSrc := supportedOS, supportedOSSources
	supportedOS = map[string]map[string][]PlatformEntry{flavor: {release: list}}
	supportedOSSources = map[string]map[string]string{flavor: {release: "https://example.test/" + release}}
	t.Cleanup(func() { supportedOS, supportedOSSources = oldOS, oldSrc })
}

func osSnap(name, version, arch string) *snapshot.Snapshot {
	s := base() // 7.0 community replica set a, b, c
	for i := range s.Nodes {
		s.Nodes[i].HostInfo.OSName, s.Nodes[i].HostInfo.OSVersion, s.Nodes[i].HostInfo.CPUArch = name, version, arch
	}
	return s
}

func osCheck(t *testing.T, s *snapshot.Snapshot) CheckResult {
	t.Helper()
	res := run(t, s, "8.0")
	for _, h := range res.Hops {
		if c, ok := checkStatus(h.Checks, "platform-os-supported"); ok {
			return c
		}
	}
	t.Fatal("platform-os-supported did not run")
	return CheckResult{}
}

var table80 = []PlatformEntry{
	{Family: "rhel", Version: "8", Arches: []string{"x86_64", "arm64"}},
	{Family: "rhel", Version: "9", Arches: []string{"x86_64", "arm64"}},
	{Family: "debian", Version: "12", Arches: []string{"x86_64"}},
	{Family: "ubuntu", Version: "22.04", Arches: []string{"x86_64", "arm64"}},
}

func TestPlatformSupported(t *testing.T) {
	withPlatforms(t, "community", "8.0", table80)
	cases := []struct {
		name, osName, osVersion, arch string
		status                        CheckStatus
		want                          string
	}{
		{"rocky 8 counts as RHEL 8", "Rocky Linux release 8.9 (Green Obsidian)", "Kernel 6.1", "x86_64", StatusOK, ""},
		{"ubuntu 22.04 arm64", "Ubuntu", "22.04", "aarch64", StatusOK, ""},
		{"rhel 7 not supported", "Red Hat Enterprise Linux Server release 7.9 (Maipo)", "", "x86_64", StatusIssues, "RHEL 7 is not supported by MongoDB Community 8.0"},
		{"debian 12 arm64 not listed", "Debian GNU/Linux 12 (bookworm)", "", "aarch64", StatusIssues, "Debian 12 on arm64 is not supported"},
		{"suse is not a supported family", "SUSE Linux Enterprise Server 15 SP5", "", "x86_64", StatusIssues, "is not a supported operating system (only Red Hat, Debian and Ubuntu)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := osCheck(t, osSnap(c.osName, c.osVersion, c.arch))
			if got.Status != c.status {
				t.Fatalf("status %s, want %s (%+v)", got.Status, c.status, got)
			}
			if c.want != "" {
				f := got.Findings[0]
				if f.Severity != Warning || !strings.Contains(strings.Join(f.Items, "\n"), c.want) || f.DocURL != "https://example.test/8.0" {
					t.Errorf("finding %+v", f)
				}
				if !strings.Contains(f.Message, "RHEL (and Rocky, Alma, Oracle Linux) 8, 9; Debian 12; Ubuntu 22.04") {
					t.Errorf("message %q", f.Message)
				}
			}
		})
	}
}

func TestPlatformNotChecked(t *testing.T) {
	withPlatforms(t, "community", "8.0", table80)
	if c := osCheck(t, osSnap("", "", "")); c.Status != StatusNotChecked {
		t.Errorf("no OS info: %+v", c)
	}
	withPlatforms(t, "community", "7.3", table80) // no list for 8.0
	if c := osCheck(t, osSnap("Ubuntu", "22.04", "x86_64")); c.Status != StatusNotChecked || !strings.Contains(c.Reason, "No official supported-OS list") {
		t.Errorf("no list: %+v", c)
	}
}

func TestProdPlatformUsesRunningRelease(t *testing.T) {
	withPlatforms(t, "community", "7.0", []PlatformEntry{{Family: "ubuntu", Version: "20.04", Arches: []string{"x86_64"}}})
	s := osSnap("Ubuntu", "22.04", "x86_64")
	s.Host = nil
	a := audit(t, s)
	f := auditFind(a, "prod-os-supported")
	if f == nil || !strings.Contains(f.Items[0], "Ubuntu 22.04 is not supported by MongoDB Community 7.0") {
		t.Errorf("audit = %+v", f)
	}
}
