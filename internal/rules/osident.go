package rules

import (
	"regexp"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// OSIdent identifies a host's operating system for the supported-platform
// checks. Family is "rhel" (RHEL and its rebuilds: Rocky, Alma, Oracle
// Linux, CentOS), "debian", "ubuntu", or "" when unknown or another OS.
type OSIdent struct {
	Family  string // rhel | debian | ubuntu | ""
	Distro  string // rhel, rocky, almalinux, ol, centos, debian, ubuntu, or the raw name
	Version string // RHEL/Debian major ("8"); Ubuntu "22.04"
	Arch    string // x86_64 | arm64 | raw cpuArch
	Raw     string // the text it was derived from, for messages
}

// Label is a readable name: "Rocky Linux 8 (RHEL 8 family)", "Ubuntu 22.04".
func (o OSIdent) Label() string {
	switch o.Family {
	case "rhel":
		if o.Distro == "rhel" {
			return "RHEL " + o.Version
		}
		return distroNames[o.Distro] + " " + o.Version + " (RHEL " + o.Version + " family)"
	case "debian":
		return "Debian " + o.Version
	case "ubuntu":
		return "Ubuntu " + o.Version
	}
	if o.Raw != "" {
		return o.Raw
	}
	return "unknown"
}

var distroNames = map[string]string{
	"rhel": "RHEL", "rocky": "Rocky Linux", "almalinux": "AlmaLinux", "ol": "Oracle Linux", "centos": "CentOS",
}

var (
	reRelease = regexp.MustCompile(`(?i)release\s+(\d+)(?:\.(\d+))?`)
	reMajor   = regexp.MustCompile(`\b(\d+)(?:\.\d+)*\b`)
	reUbuntu  = regexp.MustCompile(`\b(\d{2}\.\d{2})\b`)
)

// normArch maps cpuArch / uname -m to the names used in support tables.
func normArch(a string) string {
	switch strings.ToLower(a) {
	case "x86_64", "amd64":
		return "x86_64"
	case "aarch64", "arm64":
		return "arm64"
	}
	return a
}

// identifyName parses hostInfo os.name / os.version text.
func identifyName(name, version string) OSIdent {
	raw := strings.TrimSpace(strings.Trim(strings.TrimPrefix(strings.TrimPrefix(name, "PRETTY_NAME="), "NAME="), `"`))
	l := strings.ToLower(raw)
	o := OSIdent{Raw: raw}
	rhelMajor := func() string {
		if m := reRelease.FindStringSubmatch(raw); m != nil {
			return m[1]
		}
		if m := reMajor.FindStringSubmatch(raw); m != nil {
			return m[1]
		}
		return ""
	}
	switch {
	case strings.Contains(l, "red hat enterprise linux"):
		o.Family, o.Distro, o.Version = "rhel", "rhel", rhelMajor()
	case strings.Contains(l, "rocky"):
		o.Family, o.Distro, o.Version = "rhel", "rocky", rhelMajor()
	case strings.Contains(l, "almalinux"):
		o.Family, o.Distro, o.Version = "rhel", "almalinux", rhelMajor()
	case strings.Contains(l, "oracle linux"):
		o.Family, o.Distro, o.Version = "rhel", "ol", rhelMajor()
	case strings.Contains(l, "centos"):
		o.Family, o.Distro, o.Version = "rhel", "centos", rhelMajor()
	case strings.Contains(l, "ubuntu"):
		o.Family, o.Distro = "ubuntu", "ubuntu"
		if m := reUbuntu.FindStringSubmatch(raw + " " + version); m != nil {
			o.Version = m[1]
		}
	case strings.Contains(l, "debian"):
		o.Family, o.Distro = "debian", "debian"
		if m := reMajor.FindStringSubmatch(raw); m != nil {
			o.Version = m[1]
		} else if m := reMajor.FindStringSubmatch(version); m != nil && !strings.HasPrefix(strings.ToLower(version), "kernel") {
			o.Version = m[1]
		}
	}
	if o.Family != "" && o.Version == "" {
		o.Family = "" // a family without a version cannot be checked
	}
	return o
}

// identifyOSRelease parses /etc/os-release fields (--local).
func identifyOSRelease(r map[string]string) OSIdent {
	id := strings.ToLower(r["ID"])
	like := strings.ToLower(r["ID_LIKE"])
	ver := r["VERSION_ID"]
	o := OSIdent{Raw: strings.TrimSpace(r["PRETTY_NAME"])}
	if o.Raw == "" {
		o.Raw = strings.TrimSpace(r["NAME"] + " " + ver)
	}
	major, _, _ := strings.Cut(ver, ".")
	switch {
	case id == "ubuntu":
		o.Family, o.Distro, o.Version = "ubuntu", "ubuntu", ver
	case id == "debian":
		o.Family, o.Distro, o.Version = "debian", "debian", major
	case id == "rhel" || id == "rocky" || id == "almalinux" || id == "ol" || id == "centos" || strings.Contains(" "+like+" ", " rhel "):
		o.Family, o.Distro, o.Version = "rhel", id, major
	}
	if o.Family != "" && o.Version == "" {
		o.Family = ""
	}
	return o
}

// nodeOS identifies the OS of every node (from hostInfo), using the local
// os-release when it belongs to that node.
func nodeOS(s *snapshot.Snapshot) map[string]OSIdent {
	out := map[string]OSIdent{}
	for _, n := range s.Nodes {
		if n.Role == snapshot.RoleArbiter {
			continue
		}
		o := identifyName(n.HostInfo.OSName, n.HostInfo.OSVersion)
		if s.Host != nil && len(s.Host.OSRelease) > 0 && localHostCovers(s.Host, n) {
			if lo := identifyOSRelease(s.Host.OSRelease); lo.Family != "" || o.Family == "" {
				o = lo
			}
		}
		o.Arch = normArch(n.HostInfo.CPUArch)
		out[n.Host] = o
	}
	return out
}
