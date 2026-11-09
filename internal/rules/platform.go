package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// Supported operating systems: only the Red Hat family (RHEL and its
// rebuilds, judged by RHEL major version), Debian and Ubuntu, on the
// versions each release officially supports (platforms.go). An unsupported
// OS is always a WARNING (user decision).

var (
	rulePlatformOS = Rule{
		ID: "platform-os-supported", Title: "Supported operating system for the target release",
		Category: "platform", Scope: ScopeHop, Severity: Warning,
	}
	ruleProdPlatformOS = Rule{
		ID: "prod-os-supported", Title: "Supported operating system for the running release",
		Category: "platform", Scope: ScopeProduction, Severity: Warning,
	}
)

func init() {
	rulePlatformOS.Check = func(c *Context) []Finding { return checkOSSupport(c, rulePlatformOS, c.Hop.To) }
	ruleProdPlatformOS.Check = func(c *Context) []Finding { return checkOSSupport(c, ruleProdPlatformOS, c.Source) }
	register(rulePlatformOS, ruleProdPlatformOS)
}

// platformList returns the supported OS list and its source for a release.
func platformList(flavor, release string) ([]PlatformEntry, string) {
	if l, ok := supportedOS[flavor][release]; ok {
		return l, supportedOSSources[flavor][release]
	}
	return nil, ""
}

// describePlatforms renders "RHEL 8, 9; Debian 12; Ubuntu 22.04, 24.04".
func describePlatforms(list []PlatformEntry) string {
	byFamily := map[string][]string{}
	for _, e := range list {
		byFamily[e.Family] = append(byFamily[e.Family], e.Version)
	}
	var parts []string
	for _, f := range []string{"rhel", "debian", "ubuntu"} {
		vs := byFamily[f]
		if len(vs) == 0 {
			continue
		}
		sort.Slice(vs, func(i, j int) bool { return snapshot.CompareVersions(vs[i], vs[j]) < 0 })
		name := map[string]string{"rhel": "RHEL (and Rocky, Alma, Oracle Linux)", "debian": "Debian", "ubuntu": "Ubuntu"}[f]
		parts = append(parts, name+" "+strings.Join(vs, ", "))
	}
	return strings.Join(parts, "; ")
}

func supports(list []PlatformEntry, o OSIdent) (familyVersion, arch bool) {
	for _, e := range list {
		if e.Family == o.Family && e.Version == o.Version {
			familyVersion = true
			for _, a := range e.Arches {
				if a == o.Arch || o.Arch == "" {
					return true, true
				}
			}
		}
	}
	return familyVersion, false
}

func checkOSSupport(c *Context, r Rule, release string) []Finding {
	product := ProductName(c.Snap.Flavor())
	list, source := platformList(c.Flavor, release)
	if list == nil {
		return c.NotChecked(fmt.Sprintf("No official supported-OS list is recorded for %s %s.", product, release))
	}
	oses := nodeOS(c.Snap)
	if len(oses) == 0 {
		return c.NotChecked("No host reported its operating system.")
	}
	var items []string
	unknown := 0
	labels := map[string]bool{}
	for _, host := range sortedKeys(oses) {
		o := oses[host]
		if o.Family != "" {
			labels[o.Label()] = true
		}
		switch {
		case o.Raw == "" && o.Family == "":
			unknown++
		case o.Family == "":
			items = append(items, fmt.Sprintf("%s: %s is not a supported operating system (only Red Hat, Debian and Ubuntu)", host, o.Label()))
		default:
			fv, arch := supports(list, o)
			switch {
			case !fv:
				items = append(items, fmt.Sprintf("%s: %s is not supported by %s %s", host, o.Label(), product, release))
			case !arch:
				items = append(items, fmt.Sprintf("%s: %s on %s is not supported by %s %s", host, o.Label(), o.Arch, product, release))
			}
		}
	}
	if len(items) == 0 {
		if unknown == len(oses) {
			return c.NotChecked("No host reported a recognizable operating system.")
		}
		hosts := count(len(oses)-unknown, "host", "hosts")
		sum := fmt.Sprintf("%s on %s is supported by %s %s", strings.Join(sortedKeys(labels), ", "), hosts, product, release)
		if unknown > 0 {
			sum += fmt.Sprintf(" (%s did not report its operating system)", count(unknown, "host", "hosts"))
		}
		return c.Checked("%s.", sum)
	}
	f := r.finding(Warning,
		fmt.Sprintf("%s %s is officially supported on: %s.", product, release, describePlatforms(list)),
		items, fmt.Sprintf("Move these hosts to a supported operating system version before running %s %s.", product, release))
	f.DocURL = source
	return []Finding{f}
}
