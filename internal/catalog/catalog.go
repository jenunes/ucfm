// Package catalog exposes per-version facts about MongoDB / PSMDB server
// binaries (startup options, server parameters, commands, auth action types,
// aggregation stages and expressions, FCV compatibility) generated from the
// upstream source tags by tools/catalog-gen and embedded into the binary.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Flavors.
const (
	FlavorCommunity = "community"
	FlavorPSMDB     = "psmdb"
)

// Option is a startup (config file / command line) option.
type Option struct {
	// Name is the dotted YAML path, e.g. "net.bindIp".
	Name string `json:"name"`
	// DeprecatedNames are older names (dotted or short) still accepted but deprecated.
	DeprecatedNames []string `json:"deprecatedNames,omitempty"`
	// Short is the command-line name when it differs from Name.
	Short  string `json:"short,omitempty"`
	Source string `json:"source"`
}

// Parameter is a server parameter (setParameter / getParameter).
type Parameter struct {
	Name            string   `json:"name"`
	SetAt           []string `json:"setAt"` // startup, runtime, cluster, readonly
	DeprecatedNames []string `json:"deprecatedNames,omitempty"`
	TestOnly        bool     `json:"testOnly,omitempty"`
	Source          string   `json:"source"`
}

// Command is a database command known to the server.
type Command struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	Source  string   `json:"source"`
}

// FCVInfo describes which featureCompatibilityVersion values a binary accepts.
type FCVInfo struct {
	Latest         string `json:"latest"`
	LastContinuous string `json:"lastContinuous"`
	LastLTS        string `json:"lastLTS"`
}

// Catalog holds the facts for one flavor + release series.
type Catalog struct {
	Flavor      string  `json:"flavor"`  // "community" | "psmdb"
	Version     string  `json:"version"` // "8.0"
	SourceTag   string  `json:"sourceTag"`
	Provisional bool    `json:"provisional"`
	FCV         FCVInfo `json:"fcv"`

	StartupOptions   map[string]Option    `json:"startupOptions"`
	ServerParameters map[string]Parameter `json:"serverParameters"`
	Commands         map[string]Command   `json:"commands"`

	ActionTypes    []string `json:"actionTypes"`
	AggStages      []string `json:"aggStages"`
	AggExpressions []string `json:"aggExpressions"`

	once       sync.Once
	optIndex   map[string]nameRef
	paramIndex map[string]nameRef
	cmdIndex   map[string]string
}

type nameRef struct {
	canonical  string
	deprecated bool
}

//go:embed data
var dataFS embed.FS

var (
	cacheMu sync.Mutex
	cache   = map[string]*Catalog{}
)

// FileName returns the data file name for a flavor/version pair.
func FileName(flavor, version string) string {
	return fmt.Sprintf("%s-%s.json", flavor, version)
}

// Load returns the embedded catalog for flavor ("community" or "psmdb") and
// release series (e.g. "8.0"). Catalogs are cached and must not be mutated.
func Load(flavor, version string) (*Catalog, error) {
	key := FileName(flavor, version)
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c, ok := cache[key]; ok {
		return c, nil
	}
	b, err := dataFS.ReadFile(path.Join("data", key))
	if err != nil {
		return nil, fmt.Errorf("no catalog for %s %s", flavor, version)
	}
	c, err := Decode(b)
	if err != nil {
		return nil, fmt.Errorf("catalog %s: %w", key, err)
	}
	cache[key] = c
	return c, nil
}

// Decode parses a catalog JSON document.
func Decode(b []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Entry identifies one available catalog.
type Entry struct {
	Flavor  string
	Version string
}

// Available lists the embedded catalogs sorted by flavor then version.
func Available() []Entry {
	var out []Entry
	files, _ := fs.Glob(dataFS, "data/*.json")
	for _, f := range files {
		base := strings.TrimSuffix(path.Base(f), ".json")
		i := strings.Index(base, "-")
		if i < 0 {
			continue
		}
		out = append(out, Entry{Flavor: base[:i], Version: base[i+1:]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Flavor != out[j].Flavor {
			return out[i].Flavor < out[j].Flavor
		}
		return CompareVersions(out[i].Version, out[j].Version) < 0
	})
	return out
}

// CompareVersions compares dotted numeric versions ("8.0" < "8.3" < "9.0").
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (c *Catalog) buildIndex() {
	c.once.Do(func() {
		c.optIndex = map[string]nameRef{}
		c.paramIndex = map[string]nameRef{}
		c.cmdIndex = map[string]string{}
		// Canonical names win over deprecated/short aliases.
		for name, o := range c.StartupOptions {
			for _, d := range o.DeprecatedNames {
				if _, ok := c.optIndex[d]; !ok {
					c.optIndex[d] = nameRef{name, true}
				}
			}
		}
		for name, o := range c.StartupOptions {
			if o.Short != "" {
				if r, ok := c.optIndex[o.Short]; !ok || r.deprecated {
					c.optIndex[o.Short] = nameRef{name, false}
				}
			}
		}
		for name := range c.StartupOptions {
			c.optIndex[name] = nameRef{name, false}
		}
		for name, p := range c.ServerParameters {
			for _, d := range p.DeprecatedNames {
				if _, ok := c.paramIndex[d]; !ok {
					c.paramIndex[d] = nameRef{name, true}
				}
			}
		}
		for name := range c.ServerParameters {
			c.paramIndex[name] = nameRef{name, false}
		}
		for name, cmd := range c.Commands {
			for _, a := range cmd.Aliases {
				if _, ok := c.cmdIndex[a]; !ok {
					c.cmdIndex[a] = name
				}
			}
		}
		for name := range c.Commands {
			c.cmdIndex[name] = name
		}
	})
}

// ResolveOption maps an option name (canonical dotted name, deprecated name or
// command-line short name) to its canonical dotted name.
func (c *Catalog) ResolveOption(name string) (canonical string, deprecated, ok bool) {
	c.buildIndex()
	r, ok := c.optIndex[name]
	return r.canonical, r.deprecated, ok
}

// ResolveParameter maps a server parameter name (canonical or deprecated) to
// its canonical name.
func (c *Catalog) ResolveParameter(name string) (canonical string, deprecated, ok bool) {
	c.buildIndex()
	r, ok := c.paramIndex[name]
	return r.canonical, r.deprecated, ok
}

// ResolveCommand maps a command name or alias to its canonical name.
func (c *Catalog) ResolveCommand(name string) (canonical string, ok bool) {
	c.buildIndex()
	canonical, ok = c.cmdIndex[name]
	return canonical, ok
}

// HasActionType reports whether the action type exists in this version.
func (c *Catalog) HasActionType(a string) bool { return containsSorted(c.ActionTypes, a) }

// HasAggStage reports whether the stage (with leading "$") exists.
func (c *Catalog) HasAggStage(s string) bool { return containsSorted(c.AggStages, s) }

// HasAggExpression reports whether the expression/accumulator/window function
// (with leading "$") exists.
func (c *Catalog) HasAggExpression(e string) bool { return containsSorted(c.AggExpressions, e) }

func containsSorted(list []string, s string) bool {
	i := sort.SearchStrings(list, s)
	return i < len(list) && list[i] == s
}

// Diff lists what changes between two catalogs, from the point of view of a
// deployment configured for the "from" version.
type Diff struct {
	// Names (canonical or deprecated) accepted by "from" and not accepted at all by "to".
	RemovedOptions        []string
	RemovedParameters     []string // test-only parameters are ignored
	RemovedCommands       []string // names and aliases
	RemovedActionTypes    []string
	RemovedAggStages      []string
	RemovedAggExpressions []string
	// Names that are canonical in "from" but only a deprecated alias in "to":
	// deprecated name -> canonical name in "to".
	NewlyDeprecatedOptions    map[string]string
	NewlyDeprecatedParameters map[string]string
}

// Compare computes the Diff from one catalog to another.
func Compare(from, to *Catalog) Diff {
	d := Diff{
		NewlyDeprecatedOptions:    map[string]string{},
		NewlyDeprecatedParameters: map[string]string{},
	}
	seen := map[string]bool{}
	for name, o := range from.StartupOptions {
		names := append([]string{name}, o.DeprecatedNames...)
		for i, n := range names {
			if seen[n] {
				continue
			}
			seen[n] = true
			canon, dep, ok := to.ResolveOption(n)
			switch {
			case !ok:
				d.RemovedOptions = append(d.RemovedOptions, n)
			case i == 0 && dep:
				d.NewlyDeprecatedOptions[n] = canon
			}
		}
	}
	seen = map[string]bool{}
	for name, p := range from.ServerParameters {
		if p.TestOnly {
			continue
		}
		names := append([]string{name}, p.DeprecatedNames...)
		for i, n := range names {
			if seen[n] {
				continue
			}
			seen[n] = true
			canon, dep, ok := to.ResolveParameter(n)
			switch {
			case !ok:
				d.RemovedParameters = append(d.RemovedParameters, n)
			case i == 0 && dep:
				d.NewlyDeprecatedParameters[n] = canon
			}
		}
	}
	seen = map[string]bool{}
	for name, cmd := range from.Commands {
		for _, n := range append([]string{name}, cmd.Aliases...) {
			if seen[n] {
				continue
			}
			seen[n] = true
			if _, ok := to.ResolveCommand(n); !ok {
				d.RemovedCommands = append(d.RemovedCommands, n)
			}
		}
	}
	d.RemovedActionTypes = setMinus(from.ActionTypes, to.ActionTypes)
	d.RemovedAggStages = setMinus(from.AggStages, to.AggStages)
	d.RemovedAggExpressions = setMinus(from.AggExpressions, to.AggExpressions)
	sort.Strings(d.RemovedOptions)
	sort.Strings(d.RemovedParameters)
	sort.Strings(d.RemovedCommands)
	return d
}

func setMinus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !containsSorted(b, x) {
			out = append(out, x)
		}
	}
	return out
}
