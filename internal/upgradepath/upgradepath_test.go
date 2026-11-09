package upgradepath

import (
	"reflect"
	"strings"
	"testing"
)

// These tests use the real embedded catalogs, so they also guard the FCV
// facts extracted from releases.yml.
func TestPlan(t *testing.T) {
	cases := []struct {
		from, to string
		want     []Hop
	}{
		{"6.0", "7.0", []Hop{{"6.0", "7.0"}}},
		{"7.0", "8.0", []Hop{{"7.0", "8.0"}}},
		{"8.0", "8.3", []Hop{{"8.0", "8.3"}}},
		{"8.0", "9.0", []Hop{{"8.0", "9.0"}}},
		{"8.3", "9.0", []Hop{{"8.3", "9.0"}}},
		{"6.0", "8.0", []Hop{{"6.0", "7.0"}, {"7.0", "8.0"}}},
		{"6.0", "9.0", []Hop{{"6.0", "7.0"}, {"7.0", "8.0"}, {"8.0", "9.0"}}},
		{"7.0", "8.3", []Hop{{"7.0", "8.0"}, {"8.0", "8.3"}}},
		{"8.0", "8.0", nil},
	}
	for _, c := range cases {
		got, err := Plan(c.from, c.to)
		if err != nil {
			t.Errorf("Plan(%s,%s) error: %v", c.from, c.to, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Plan(%s,%s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestPlanErrors(t *testing.T) {
	cases := []struct{ from, to, want string }{
		{"8.0", "7.0", "downgrade"},
		{"5.0", "8.0", "source 5.0 is not supported"},
		{"8.0", "8.2", "target 8.2 is not supported"},
	}
	for _, c := range cases {
		_, err := Plan(c.from, c.to)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Plan(%s,%s) err = %v, want containing %q", c.from, c.to, err, c.want)
		}
	}
}

func TestDirectlyUpgradable(t *testing.T) {
	for _, c := range []struct {
		from, to string
		ok       bool
	}{
		{"6.0", "8.0", false}, // must go through 7.0
		{"7.0", "8.3", false}, // 8.3 accepts 8.0/8.2 only
		{"8.0", "9.0", true},  // LTS to LTS
		{"8.3", "9.0", true},  // last continuous
	} {
		got, err := DirectlyUpgradable(c.from, c.to)
		if err != nil || got != c.ok {
			t.Errorf("DirectlyUpgradable(%s,%s) = %v,%v want %v", c.from, c.to, got, err, c.ok)
		}
	}
}
