package host

import (
	"errors"
	"testing"

	"github.com/jenunes/ucfm/internal/snapshot"
)

func stubIdentity(t *testing.T, names, addrs []string, dns map[string][]string) {
	t.Helper()
	oldN, oldA, oldL := localHostnames, localAddrs, lookupHost
	localHostnames = func() []string { return names }
	localAddrs = func() []string { return addrs }
	lookupHost = func(h string) ([]string, error) {
		if ips, ok := dns[h]; ok {
			return ips, nil
		}
		return nil, errors.New("no such host")
	}
	t.Cleanup(func() { localHostnames, localAddrs, lookupHost = oldN, oldA, oldL })
}

func cluster() *snapshot.Snapshot {
	return &snapshot.Snapshot{Nodes: []snapshot.Node{
		{Host: "db1.example.net:27017", Role: snapshot.RolePrimary, HostInfo: snapshot.HostInfoCmd{Hostname: "db1.example.net"}},
		{Host: "10.0.0.2:27017", Role: snapshot.RoleSecondary, HostInfo: snapshot.HostInfoCmd{Hostname: "db2:27017"}},
		{Host: "10.0.0.3:27017", Role: snapshot.RoleArbiter},
	}}
}

func TestMatchNode(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		addrs []string
		dns   map[string][]string
		snap  *snapshot.Snapshot
		want  string
	}{
		{"hostname (short vs FQDN)", []string{"db1"}, []string{"192.168.1.9"}, nil, cluster(), "db1.example.net:27017"},
		{"hostInfo hostname with port", []string{"db2"}, nil, nil, cluster(), "10.0.0.2:27017"},
		{"interface address", []string{"other"}, []string{"10.0.0.2"}, nil, cluster(), "10.0.0.2:27017"},
		{"DNS resolves to a local address", []string{"other"}, []string{"10.9.9.9"}, map[string][]string{"db1.example.net": {"10.9.9.9"}}, cluster(), "db1.example.net:27017"},
		{"arbiters never match", []string{"other"}, []string{"10.0.0.3"}, nil, cluster(), ""},
		{"workstation is not a member", []string{"laptop"}, []string{"192.168.1.9"}, nil, cluster(), ""},
		{"loopback entry node", []string{"laptop"}, nil, nil, &snapshot.Snapshot{Nodes: []snapshot.Node{{Host: "127.0.0.1:27017", Role: snapshot.RolePrimary}}}, "127.0.0.1:27017"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubIdentity(t, c.names, c.addrs, c.dns)
			h := &snapshot.HostInfo{}
			if got := MatchNode(c.snap, h); got != c.want {
				t.Errorf("MatchNode = %q, want %q", got, c.want)
			}
		})
	}
}
