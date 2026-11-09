// Package upgradepath works out the sequence of binary upgrades ("hops") from a
// source release series to a target one. A hop A→B is valid when the B binary
// can start on data files whose featureCompatibilityVersion is A, i.e. A is
// B's lastLTS or lastContinuous FCV (from releases.yml at B's source tag).
package upgradepath

import (
	"fmt"
	"sort"

	"github.com/jenunes/ucfm/internal/catalog"
)

// Supported are the release series ucfm knows how to check.
var Supported = []string{"6.0", "7.0", "8.0", "8.3", "9.0"}

// Hop is one binary upgrade step.
type Hop struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (h Hop) String() string { return h.From + " → " + h.To }

// FCVSource returns the FCV info of a release series. It is a variable so
// tests can stub it.
var FCVSource = func(version string) (catalog.FCVInfo, error) {
	c, err := catalog.Load(catalog.FlavorCommunity, version)
	if err != nil {
		return catalog.FCVInfo{}, err
	}
	return c.FCV, nil
}

// IsSupported reports whether v is one of the supported series.
func IsSupported(v string) bool {
	for _, s := range Supported {
		if s == v {
			return true
		}
	}
	return false
}

// DirectlyUpgradable reports whether the "to" binary accepts FCV "from".
func DirectlyUpgradable(from, to string) (bool, error) {
	fcv, err := FCVSource(to)
	if err != nil {
		return false, err
	}
	return from == fcv.LastLTS || from == fcv.LastContinuous, nil
}

// Plan returns the shortest sequence of hops from source to target through
// supported series. Ties prefer going through LTS releases (x.0).
func Plan(source, target string) ([]Hop, error) {
	switch {
	case !IsSupported(target):
		return nil, fmt.Errorf("target %s is not supported (supported: %v)", target, Supported)
	case !IsSupported(source):
		return nil, fmt.Errorf("source %s is not supported (supported: %v); upgrade to a supported series first", source, Supported)
	case catalog.CompareVersions(source, target) == 0:
		return nil, nil
	case catalog.CompareVersions(source, target) > 0:
		return nil, fmt.Errorf("target %s is older than the running version %s; downgrades are out of scope", target, source)
	}

	// Candidates: supported series between source and target, inclusive.
	var nodes []string
	for _, v := range Supported {
		if catalog.CompareVersions(v, source) >= 0 && catalog.CompareVersions(v, target) <= 0 {
			nodes = append(nodes, v)
		}
	}
	// Prefer LTS neighbours first so BFS ties resolve through them.
	sort.SliceStable(nodes, func(i, j int) bool {
		return isLTS(nodes[i]) && !isLTS(nodes[j])
	})

	prev := map[string]string{source: ""}
	queue := []string{source}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == target {
			break
		}
		for _, next := range nodes {
			if _, seen := prev[next]; seen || catalog.CompareVersions(next, cur) <= 0 {
				continue
			}
			ok, err := DirectlyUpgradable(cur, next)
			if err != nil {
				return nil, err
			}
			if ok {
				prev[next] = cur
				queue = append(queue, next)
			}
		}
	}
	if _, ok := prev[target]; !ok {
		return nil, fmt.Errorf("no supported upgrade path from %s to %s", source, target)
	}
	var hops []Hop
	for v := target; v != source; v = prev[v] {
		hops = append([]Hop{{From: prev[v], To: v}}, hops...)
	}
	return hops, nil
}

func isLTS(v string) bool {
	return len(v) > 2 && v[len(v)-2:] == ".0"
}
