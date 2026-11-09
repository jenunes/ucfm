package rules

import "testing"

func TestIdentifyName(t *testing.T) {
	cases := []struct {
		name, version, family, distro, ver string
	}{
		{"Rocky Linux release 8.9 (Green Obsidian)", "Kernel 6.12.115", "rhel", "rocky", "8"},
		{"Red Hat Enterprise Linux release 9.2 (Plow)", "Kernel 5.14.0", "rhel", "rhel", "9"},
		{"AlmaLinux release 9.3 (Shamrock Pampas Cat)", "", "rhel", "almalinux", "9"},
		{"Oracle Linux Server release 8.10", "", "rhel", "ol", "8"},
		{"CentOS Linux release 7.9.2009 (Core)", "", "rhel", "centos", "7"},
		{"Ubuntu", "22.04", "ubuntu", "ubuntu", "22.04"},
		{`PRETTY_NAME="Ubuntu 24.04.1 LTS"`, "Kernel 6.8.0", "ubuntu", "ubuntu", "24.04"},
		{`PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"`, "Kernel 6.1.0", "debian", "debian", "12"},
		{"Debian", "11", "debian", "debian", "11"},
		{`NAME="Freedesktop SDK"`, "Kernel 6.12", "", "", ""},
		{"SUSE Linux Enterprise Server 15 SP5", "", "", "", ""},
		{"Debian", "Kernel 6.1.0", "", "debian", ""},
	}
	for _, c := range cases {
		o := identifyName(c.name, c.version)
		if o.Family != c.family || o.Distro != c.distro || o.Version != c.ver {
			t.Errorf("identifyName(%q,%q) = %+v, want %s/%s/%s", c.name, c.version, o, c.family, c.distro, c.ver)
		}
	}
}

func TestIdentifyOSRelease(t *testing.T) {
	cases := []struct {
		r                   map[string]string
		family, distro, ver string
	}{
		{map[string]string{"ID": "rocky", "VERSION_ID": "8.9", "ID_LIKE": "rhel centos fedora"}, "rhel", "rocky", "8"},
		{map[string]string{"ID": "ubuntu", "VERSION_ID": "22.04"}, "ubuntu", "ubuntu", "22.04"},
		{map[string]string{"ID": "debian", "VERSION_ID": "12"}, "debian", "debian", "12"},
		{map[string]string{"ID": "navy", "VERSION_ID": "9.1", "ID_LIKE": "rhel fedora"}, "rhel", "navy", "9"},
		{map[string]string{"ID": "sles", "VERSION_ID": "15.5", "ID_LIKE": "suse"}, "", "", ""},
		{map[string]string{"ID": "amzn", "VERSION_ID": "2023", "ID_LIKE": "fedora"}, "", "", ""},
	}
	for _, c := range cases {
		o := identifyOSRelease(c.r)
		if o.Family != c.family || o.Distro != c.distro || o.Version != c.ver {
			t.Errorf("identifyOSRelease(%v) = %+v, want %s/%s/%s", c.r, o, c.family, c.distro, c.ver)
		}
	}
}

func TestOSLabel(t *testing.T) {
	if l := (OSIdent{Family: "rhel", Distro: "rocky", Version: "8"}).Label(); l != "Rocky Linux 8 (RHEL 8 family)" {
		t.Errorf("label %q", l)
	}
	if l := (OSIdent{Family: "ubuntu", Distro: "ubuntu", Version: "22.04"}).Label(); l != "Ubuntu 22.04" {
		t.Errorf("label %q", l)
	}
}
