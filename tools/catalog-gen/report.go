package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jenunes/ucfm/internal/catalog"
)

func loadDir(dir string) (map[string]*catalog.Catalog, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]*catalog.Catalog{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		c, err := catalog.Decode(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out[c.Flavor+"-"+c.Version] = c
	}
	return out, nil
}

// printReport prints catalog stats, per-hop diffs and community-vs-PSMDB extras.
func printReport(dir string) error {
	cats, err := loadDir(dir)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(cats))
	for k := range cats {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := cats[keys[i]], cats[keys[j]]
		if a.Flavor != b.Flavor {
			return a.Flavor < b.Flavor
		}
		return catalog.CompareVersions(a.Version, b.Version) < 0
	})
	fmt.Println("| flavor | series | tag | prov | options | params | commands | actions | stages | exprs | FCV latest/lastCont/lastLTS |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|---|---|")
	for _, k := range keys {
		c := cats[k]
		fmt.Printf("| %s | %s | %s | %v | %d | %d | %d | %d | %d | %d | %s/%s/%s |\n", c.Flavor, c.Version, c.SourceTag, c.Provisional,
			len(c.StartupOptions), len(c.ServerParameters), len(c.Commands), len(c.ActionTypes), len(c.AggStages), len(c.AggExpressions),
			c.FCV.Latest, c.FCV.LastContinuous, c.FCV.LastLTS)
	}
	hops := [][2]string{{"6.0", "7.0"}, {"7.0", "8.0"}, {"8.0", "8.3"}, {"8.0", "9.0"}, {"8.3", "9.0"}}
	for _, flavor := range []string{catalog.FlavorCommunity, catalog.FlavorPSMDB} {
		for _, h := range hops {
			from, to := cats[flavor+"-"+h[0]], cats[flavor+"-"+h[1]]
			if from == nil || to == nil {
				continue
			}
			d := catalog.Compare(from, to)
			fmt.Printf("\n## %s %s -> %s\n", flavor, h[0], h[1])
			printList("removed options", d.RemovedOptions)
			printMap("newly deprecated options", d.NewlyDeprecatedOptions)
			printList("removed parameters", d.RemovedParameters)
			printMap("newly deprecated parameters", d.NewlyDeprecatedParameters)
			printList("removed commands", d.RemovedCommands)
			printList("removed action types", d.RemovedActionTypes)
			printList("removed agg stages", d.RemovedAggStages)
			printList("removed agg expressions", d.RemovedAggExpressions)
		}
	}
	fmt.Println("\n## PSMDB-only startup options (vs community, same series)")
	for _, v := range []string{"6.0", "7.0", "8.0", "8.3", "9.0"} {
		p, c := cats["psmdb-"+v], cats["community-"+v]
		if p == nil || c == nil {
			continue
		}
		var extra []string
		for name := range p.StartupOptions {
			if _, _, ok := c.ResolveOption(name); !ok {
				extra = append(extra, name)
			}
		}
		sort.Strings(extra)
		printList(v, extra)
	}
	return nil
}

func printList(label string, l []string) {
	if len(l) == 0 {
		fmt.Printf("- %s: none\n", label)
		return
	}
	fmt.Printf("- %s (%d): %s\n", label, len(l), strings.Join(l, ", "))
}

func printMap(label string, m map[string]string) {
	var l []string
	for k, v := range m {
		l = append(l, k+"→"+v)
	}
	sort.Strings(l)
	printList(label, l)
}
