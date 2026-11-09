package main

import (
	"reflect"
	"testing"

	"github.com/jenunes/ucfm/internal/catalog"
)

func parseFixture(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, st, err := Parse("testdata/r8.0.12", catalog.FlavorCommunity, "8.0", "r8.0.12")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.IDLFailures) > 0 {
		t.Fatalf("IDL failures: %v", st.IDLFailures)
	}
	return c
}

func TestDeprecatedOptionName(t *testing.T) {
	c := parseFixture(t)
	o, ok := c.StartupOptions["security.clusterIpSourceAllowlist"]
	if !ok {
		t.Fatal("security.clusterIpSourceAllowlist missing")
	}
	if o.Short != "clusterIpSourceAllowlist" {
		t.Errorf("short = %q", o.Short)
	}
	want := []string{"clusterIpSourceWhitelist", "security.clusterIpSourceWhitelist"}
	if !reflect.DeepEqual(o.DeprecatedNames, want) {
		t.Errorf("deprecated names = %v, want %v", o.DeprecatedNames, want)
	}
	canon, dep, ok := c.ResolveOption("security.clusterIpSourceWhitelist")
	if !ok || !dep || canon != "security.clusterIpSourceAllowlist" {
		t.Errorf("ResolveOption = %q %v %v", canon, dep, ok)
	}
}

func TestTestIDLExcluded(t *testing.T) {
	c := parseFixture(t)
	for name := range c.StartupOptions {
		if len(name) >= 5 && name[:5] == "test." {
			t.Errorf("test IDL option leaked: %s", name)
		}
	}
}

func TestServerParameterList(t *testing.T) {
	c := parseFixture(t)
	p, ok := c.ServerParameters["storageEngineConcurrentWriteTransactions"]
	if !ok {
		t.Fatal("parameter missing")
	}
	if !reflect.DeepEqual(p.SetAt, []string{"runtime", "startup"}) {
		t.Errorf("setAt = %v", p.SetAt)
	}
	if !reflect.DeepEqual(p.DeprecatedNames, []string{"wiredTigerConcurrentWriteTransactions"}) {
		t.Errorf("deprecated = %v", p.DeprecatedNames)
	}
	if _, ok := c.ServerParameters["clusterIpSourceAllowlist"]; !ok {
		t.Error("clusterIpSourceAllowlist parameter missing")
	}
}

func TestActionTypesAndFCV(t *testing.T) {
	c := parseFixture(t)
	if !c.HasActionType("addShard") || !c.HasActionType("compact") {
		t.Errorf("action types = %v", c.ActionTypes)
	}
	want := catalog.FCVInfo{Latest: "8.0", LastContinuous: "7.3", LastLTS: "7.0"}
	if c.FCV != want {
		t.Errorf("FCV = %+v, want %+v", c.FCV, want)
	}
}

func TestCppFixture(t *testing.T) {
	c := parseFixture(t)
	if !reflect.DeepEqual(c.AggStages, []string{"$match"}) {
		t.Errorf("stages = %v", c.AggStages)
	}
	if !reflect.DeepEqual(c.AggExpressions, []string{"$dayOfMonth", "$derivative", "$sum"}) {
		t.Errorf("exprs = %v", c.AggExpressions)
	}
	for _, n := range []string{"hello", "isMaster", "ismaster", "cleanupOrphaned", "balancerStatus", "findandmodify"} {
		if _, ok := c.ResolveCommand(n); !ok {
			t.Errorf("command %q not found", n)
		}
	}
	if canon, _ := c.ResolveCommand("ismaster"); canon != "isMaster" {
		t.Errorf("ismaster resolves to %q", canon)
	}
	if cmd := c.Commands["balancerStatus"]; len(cmd.Aliases) != 0 {
		t.Errorf("balancerStatus must not get aliases: %v", cmd.Aliases)
	}
	for _, n := range []string{"notRegistered", "alsoNotRegistered", "key"} {
		if _, ok := c.ResolveCommand(n); ok {
			t.Errorf("false positive command %q", n)
		}
	}
}

func TestParseReleases(t *testing.T) {
	y := []byte("featureCompatibilityVersions: [\"7.0\", \"8.0\", \"8.1\", \"8.2\", \"8.3\", \"9.0\", \"100.0\"]\nlongTermSupportReleases: [\"7.0\", \"8.0\"]\n")
	got, err := ParseReleases(y, "9.0")
	if err != nil {
		t.Fatal(err)
	}
	if want := (catalog.FCVInfo{Latest: "9.0", LastContinuous: "8.3", LastLTS: "8.0"}); got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestPickTag(t *testing.T) {
	tags := []string{"r8.0.9", "r8.0.19", "r8.0.20-rc0", "r9.1.0-rc1", "r9.1.0-rc2", "r9.1.0-alpha0"}
	if tag, prov := pickTag(catalog.FlavorCommunity, "8.0", tags); tag != "r8.0.19" || prov {
		t.Errorf("8.0 -> %s %v", tag, prov)
	}
	if tag, prov := pickTag(catalog.FlavorCommunity, "9.1", tags); tag != "r9.1.0-rc2" || !prov {
		t.Errorf("9.1 -> %s %v", tag, prov)
	}
	ptags := []string{"psmdb-8.0.12-4", "psmdb-8.0.34-15", "psmdb-8.0.4-2", "psmdb-8.3.13-4"}
	if tag, prov := pickTag(catalog.FlavorPSMDB, "8.0", ptags); tag != "psmdb-8.0.34-15" || prov {
		t.Errorf("psmdb 8.0 -> %s %v", tag, prov)
	}
	if tag, _ := pickTag(catalog.FlavorPSMDB, "9.0", ptags); tag != "" {
		t.Errorf("psmdb 9.0 -> %s", tag)
	}
}
