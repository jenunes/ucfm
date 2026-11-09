package host

import (
	"net"
	"os"
	"strings"

	"github.com/jenunes/ucfm/internal/snapshot"
)

// lookupHost resolves a host name; a variable so tests can stub it.
var lookupHost = net.LookupHost

// localAddrs returns the IP addresses of this machine's interfaces; a
// variable so tests can stub it.
var localAddrs = func() []string {
	var out []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// localHostnames returns the short and full host names of this machine.
var localHostnames = func() []string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return nil
	}
	out := []string{h}
	if short, _, ok := strings.Cut(h, "."); ok {
		out = append(out, short)
	}
	return out
}

func isLoopback(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func sameName(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	sa, _, _ := strings.Cut(a, ".")
	sb, _, _ := strings.Cut(b, ".")
	return sa == sb
}

// MatchNode returns the "host:port" of the deployment member running on
// this machine, or "" when this machine is not a member. A node matches
// when its hostInfo host name equals this machine's name, when its address
// resolves to one of this machine's interface addresses, or when it was
// reached through a loopback address (the entry node of a localhost URI).
// It also records the local addresses in h.LocalAddrs.
func MatchNode(snap *snapshot.Snapshot, h *snapshot.HostInfo) string {
	addrs := localAddrs()
	h.LocalAddrs = addrs
	local := map[string]bool{}
	for _, a := range addrs {
		local[a] = true
	}
	names := localHostnames()
	if h.Hostname != "" {
		names = append(names, h.Hostname)
	}
	for _, n := range snap.Nodes {
		if n.Role == snapshot.RoleArbiter {
			continue
		}
		hp := snapshot.HostPart(n.Host)
		if isLoopback(hp) || local[hp] {
			return n.Host
		}
		for _, name := range names {
			if sameName(snapshot.HostPart(n.HostInfo.Hostname), name) || sameName(hp, name) {
				return n.Host
			}
		}
		if ips, err := lookupHost(hp); err == nil {
			for _, ip := range ips {
				if local[ip] {
					return n.Host
				}
			}
		}
	}
	return ""
}
