package catalog

import (
	"reflect"
	"testing"
)

func mk(version string, opts map[string]Option, params map[string]Parameter, cmds map[string]Command, actions []string) *Catalog {
	return &Catalog{Flavor: FlavorCommunity, Version: version, StartupOptions: opts, ServerParameters: params, Commands: cmds, ActionTypes: actions}
}

func TestResolveAndCompare(t *testing.T) {
	from := mk("7.0",
		map[string]Option{
			"net.bindIp":              {Name: "net.bindIp"},
			"storage.journal.enabled": {Name: "storage.journal.enabled"},
			"security.oldName":        {Name: "security.oldName"},
			"net.tls.mode":            {Name: "net.tls.mode", DeprecatedNames: []string{"net.ssl.mode"}},
		},
		map[string]Parameter{
			"keep":       {Name: "keep"},
			"gone":       {Name: "gone"},
			"testKnob":   {Name: "testKnob", TestOnly: true},
			"renamedOld": {Name: "renamedOld"},
		},
		map[string]Command{"find": {Name: "find"}, "getLastError": {Name: "getLastError", Aliases: []string{"getlasterror"}}},
		[]string{"a", "b"})
	to := mk("8.0",
		map[string]Option{
			"net.bindIp":       {Name: "net.bindIp"},
			"security.newName": {Name: "security.newName", DeprecatedNames: []string{"security.oldName"}},
			"net.tls.mode":     {Name: "net.tls.mode"},
		},
		map[string]Parameter{
			"keep":       {Name: "keep"},
			"renamedNew": {Name: "renamedNew", DeprecatedNames: []string{"renamedOld"}},
		},
		map[string]Command{"find": {Name: "find"}},
		[]string{"a"})

	if c, dep, ok := to.ResolveOption("security.oldName"); !ok || !dep || c != "security.newName" {
		t.Errorf("ResolveOption(oldName) = %q %v %v", c, dep, ok)
	}
	if _, _, ok := to.ResolveOption("nope"); ok {
		t.Error("unknown option resolved")
	}
	if c, dep, ok := to.ResolveParameter("renamedOld"); !ok || !dep || c != "renamedNew" {
		t.Errorf("ResolveParameter = %q %v %v", c, dep, ok)
	}

	d := Compare(from, to)
	if want := []string{"net.ssl.mode", "storage.journal.enabled"}; !reflect.DeepEqual(d.RemovedOptions, want) {
		t.Errorf("RemovedOptions = %v want %v", d.RemovedOptions, want)
	}
	if want := map[string]string{"security.oldName": "security.newName"}; !reflect.DeepEqual(d.NewlyDeprecatedOptions, want) {
		t.Errorf("NewlyDeprecatedOptions = %v", d.NewlyDeprecatedOptions)
	}
	if want := []string{"gone"}; !reflect.DeepEqual(d.RemovedParameters, want) {
		t.Errorf("RemovedParameters = %v", d.RemovedParameters)
	}
	if want := map[string]string{"renamedOld": "renamedNew"}; !reflect.DeepEqual(d.NewlyDeprecatedParameters, want) {
		t.Errorf("NewlyDeprecatedParameters = %v", d.NewlyDeprecatedParameters)
	}
	if want := []string{"getLastError", "getlasterror"}; !reflect.DeepEqual(d.RemovedCommands, want) {
		t.Errorf("RemovedCommands = %v", d.RemovedCommands)
	}
	if want := []string{"b"}; !reflect.DeepEqual(d.RemovedActionTypes, want) {
		t.Errorf("RemovedActionTypes = %v", d.RemovedActionTypes)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"8.0", "8.3", -1}, {"9.0", "8.3", 1}, {"7.0", "7.0", 0}, {"10.0", "9.0", 1}}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%s,%s)=%d", c.a, c.b, got)
		}
	}
}

func TestEmbeddedCatalogs(t *testing.T) {
	av := Available()
	if len(av) == 0 {
		t.Fatal("no embedded catalogs")
	}
	for _, v := range []string{"6.0", "7.0", "8.0", "8.3", "9.0"} {
		c, err := Load(FlavorCommunity, v)
		if err != nil {
			t.Fatal(err)
		}
		if c.Version != v || c.FCV.Latest != v {
			t.Errorf("%s: version %s fcv %+v", v, c.Version, c.FCV)
		}
		if _, _, ok := c.ResolveOption("net.bindIp"); !ok {
			t.Errorf("%s: net.bindIp missing", v)
		}
		if _, ok := c.ResolveCommand("serverStatus"); !ok {
			t.Errorf("%s: serverStatus missing", v)
		}
		if !c.HasAggStage("$match") || !c.HasAggExpression("$sum") || !c.HasActionType("find") {
			t.Errorf("%s: core agg/action facts missing", v)
		}
	}
	c90, _ := Load(FlavorCommunity, "9.0")
	if c90.FCV.LastLTS != "8.0" || c90.FCV.LastContinuous != "8.3" {
		t.Errorf("9.0 FCV = %+v", c90.FCV)
	}
	// storage.journal.enabled was removed in 6.1.
	c60, _ := Load(FlavorCommunity, "6.0")
	c70, _ := Load(FlavorCommunity, "7.0")
	d := Compare(c60, c70)
	found := false
	for _, o := range d.RemovedOptions {
		found = found || o == "storage.journal.enabled"
	}
	if !found {
		t.Errorf("6.0->7.0 should remove storage.journal.enabled: %v", d.RemovedOptions)
	}
	if _, err := Load(FlavorPSMDB, "8.0"); err != nil {
		t.Error(err)
	}
	if _, err := Load("nope", "1.0"); err == nil {
		t.Error("expected error for unknown catalog")
	}
}
