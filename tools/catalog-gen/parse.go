package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jenunes/ucfm/internal/catalog"
)

// ParseStats records parsing problems so gaps are visible in the output.
type ParseStats struct {
	IDLFiles     int
	IDLFailures  []string
	CppFiles     int
	ReleasesYAML bool
}

// excludedPath reports whether a source file belongs to tests, client tools,
// the shell or vendored code and must not contribute server facts.
func excludedPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := path_base(rel)
	switch {
	case strings.HasPrefix(rel, "src/third_party/"),
		strings.Contains(rel, "/dbtests/"),
		strings.Contains(rel, "/unittest/"),
		strings.Contains(rel, "/shell/"),
		strings.Contains(rel, "/mongo/tools/"),
		strings.Contains(rel, "/embedded/"),
		strings.Contains(rel, "/mongotmock/"),
		strings.Contains(rel, "/sdam/json_test_runner"),
		strings.Contains(rel, "/integration_tests/"),
		strings.Contains(rel, "/test_support/"),
		strings.Contains(base, "_test."),
		strings.Contains(base, "_test_"),
		strings.HasPrefix(base, "unittest"),
		strings.HasSuffix(base, "_bm.cpp"),
		strings.Contains(base, "_mock."),
		strings.Contains(base, "mock_"):
		return true
	}
	// IDL test fixtures live directly under src/mongo/idl.
	if strings.HasPrefix(rel, "src/mongo/idl/") && strings.Contains(base, "test") {
		return true
	}
	return false
}

// clientOnlyOption reports IDL files whose configs belong to client programs
// (mongo shell, tools), not mongod/mongos.
func clientOnlyOption(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := path_base(rel)
	return strings.Contains(base, "_options_client") ||
		strings.HasPrefix(rel, "src/mongo/client/") ||
		strings.Contains(rel, "/mongobridge") ||
		strings.Contains(rel, "/mongo_main") ||
		strings.Contains(base, "mongocryptd") ||
		strings.Contains(rel, "/cryptd/")
}

func path_base(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

// Parse walks a source checkout and builds the catalog.
func Parse(root, flavor, version, tag string) (*catalog.Catalog, *ParseStats, error) {
	c := &catalog.Catalog{
		Flavor:           flavor,
		Version:          version,
		SourceTag:        tag,
		StartupOptions:   map[string]catalog.Option{},
		ServerParameters: map[string]catalog.Parameter{},
		Commands:         map[string]catalog.Command{},
	}
	st := &ParseStats{}
	actions := map[string]bool{}
	stages := map[string]bool{}
	exprs := map[string]bool{}

	err := filepath.WalkDir(filepath.Join(root, "src"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "src/third_party" {
				return filepath.SkipDir
			}
			return nil
		}
		if excludedPath(rel) {
			return nil
		}
		switch {
		case strings.HasSuffix(rel, ".idl"):
			st.IDLFiles++
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := parseIDL(c, rel, b, actions); err != nil {
				st.IDLFailures = append(st.IDLFailures, fmt.Sprintf("%s: %v", rel, err))
			}
		case strings.HasSuffix(rel, ".cpp") || strings.HasSuffix(rel, ".h"):
			st.CppFiles++
			if err := parseCpp(c, rel, p, stages, exprs); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	rel, err := os.ReadFile(filepath.Join(root, "src/mongo/util/version/releases.yml"))
	if err == nil {
		st.ReleasesYAML = true
		fcv, err := ParseReleases(rel, version)
		if err != nil {
			return nil, nil, fmt.Errorf("releases.yml: %w", err)
		}
		c.FCV = fcv
	}
	c.ActionTypes = sortedKeys(actions)
	c.AggStages = sortedKeys(stages)
	c.AggExpressions = sortedKeys(exprs)
	return c, st, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stringOrList decodes YAML values that may be a scalar or a sequence.
type stringOrList []string

func (s *stringOrList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		v := strings.TrimSpace(n.Value)
		if v != "" {
			*s = []string{v}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if v := strings.TrimSpace(c.Value); v != "" {
				*s = append(*s, v)
			}
		}
	}
	return nil
}

type idlConfig struct {
	ShortName           string       `yaml:"short_name"`
	DeprecatedName      stringOrList `yaml:"deprecated_name"`
	DeprecatedShortName stringOrList `yaml:"deprecated_short_name"`
}

type idlParam struct {
	SetAt          stringOrList `yaml:"set_at"`
	DeprecatedName stringOrList `yaml:"deprecated_name"`
	TestOnly       bool         `yaml:"test_only"`
}

type idlCommand struct {
	CommandName  string       `yaml:"command_name"`
	CommandAlias stringOrList `yaml:"command_alias"`
}

type idlEnum struct {
	Values map[string]string `yaml:"values"`
}

// parseIDL extracts configs, server parameters, commands and (from
// action_type.idl) auth action types.
func parseIDL(c *catalog.Catalog, rel string, b []byte, actions map[string]bool) error {
	// Some IDL files reuse keys or hold non-map shapes in sections we do not
	// care about; decode leniently section by section.
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	top := root.Content[0]
	var errs []string
	for i := 0; i+1 < len(top.Content); i += 2 {
		key, val := top.Content[i].Value, top.Content[i+1]
		switch key {
		case "configs":
			if clientOnlyOption(rel) {
				continue
			}
			var m map[string]idlConfig
			if err := val.Decode(&m); err != nil {
				errs = append(errs, "configs: "+err.Error())
				continue
			}
			for name, cfg := range m {
				o := catalog.Option{Name: name, Source: rel}
				if cfg.ShortName != "" && cfg.ShortName != name {
					o.Short = cfg.ShortName
				}
				o.DeprecatedNames = append(o.DeprecatedNames, cfg.DeprecatedName...)
				o.DeprecatedNames = append(o.DeprecatedNames, cfg.DeprecatedShortName...)
				if prev, ok := c.StartupOptions[name]; ok {
					o.DeprecatedNames = append(prev.DeprecatedNames, o.DeprecatedNames...)
					if o.Short == "" {
						o.Short = prev.Short
					}
				}
				o.DeprecatedNames = uniqSorted(o.DeprecatedNames)
				c.StartupOptions[name] = o
			}
		case "server_parameters":
			var m map[string]idlParam
			if err := val.Decode(&m); err != nil {
				errs = append(errs, "server_parameters: "+err.Error())
				continue
			}
			for name, sp := range m {
				p := catalog.Parameter{Name: name, Source: rel, TestOnly: sp.TestOnly}
				for _, s := range sp.SetAt {
					s = strings.Trim(s, `"' `)
					if s != "" {
						p.SetAt = append(p.SetAt, s)
					}
				}
				p.SetAt = uniqSorted(p.SetAt)
				p.DeprecatedNames = uniqSorted(sp.DeprecatedName)
				if prev, ok := c.ServerParameters[name]; ok {
					// Same parameter declared for mongod and mongos: merge.
					p.SetAt = uniqSorted(append(prev.SetAt, p.SetAt...))
					p.DeprecatedNames = uniqSorted(append(prev.DeprecatedNames, p.DeprecatedNames...))
					p.TestOnly = prev.TestOnly && p.TestOnly
					p.Source = prev.Source
				}
				c.ServerParameters[name] = p
			}
		case "commands":
			var m map[string]idlCommand
			if err := val.Decode(&m); err != nil {
				errs = append(errs, "commands: "+err.Error())
				continue
			}
			for key, cmd := range m {
				name := cmd.CommandName
				if name == "" {
					name = key
				}
				addCommand(c, name, cmd.CommandAlias, rel)
			}
		case "enums":
			if path_base(rel) != "action_type.idl" {
				continue
			}
			var m map[string]yaml.Node
			if err := val.Decode(&m); err != nil {
				errs = append(errs, "enums: "+err.Error())
				continue
			}
			node, ok := m["ActionType"]
			if !ok {
				continue
			}
			var e idlEnum
			if err := node.Decode(&e); err != nil {
				errs = append(errs, "enums.ActionType: "+err.Error())
				continue
			}
			for _, v := range e.Values {
				actions[v] = true
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func addCommand(c *catalog.Catalog, name string, aliases []string, rel string) {
	cmd, ok := c.Commands[name]
	if !ok {
		cmd = catalog.Command{Name: name, Source: rel}
	}
	for _, a := range aliases {
		if a != name {
			cmd.Aliases = append(cmd.Aliases, a)
		}
	}
	cmd.Aliases = uniqSorted(cmd.Aliases)
	c.Commands[name] = cmd
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	m := map[string]bool{}
	for _, s := range in {
		m[s] = true
	}
	return sortedKeys(m)
}

var (
	// A constructor call in an initializer list ("Foo() : BasicCommand(...)")
	// whose arguments are only names: string literals or in-file k-constants,
	// optionally with an alias list. The class name is checked separately.
	reCmdCtor = regexp.MustCompile(`[:,]\s*(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)(?:<[^<>()]*>)?\(\s*` +
		`("[A-Za-z_]\w*"|k[A-Z]\w*)\s*` +
		`(?:,\s*\{?\s*("[A-Za-z_]\w*"|k[A-Z]\w*)\s*(?:,\s*("[A-Za-z_]\w*"|k[A-Z]\w*)\s*)?\}?\s*)?[,)]`)
	// Class names that are command base classes (or subclasses).
	reCmdClass = regexp.MustCompile(`Command|Cmd`)
	// Base classes whose second/third name argument is an alias (others,
	// e.g. BalancerControlCommand, pass a different command's name there).
	reAliasClass = regexp.MustCompile(`^(?:Command|Basic\w*Command\w*|ErrmsgCommandDeprecated|Cmd\w+)$`)
	// String constants: constexpr auto kFoo = "foo"_sd; const std::string X::kCommandName = "foo";
	reConst    = regexp.MustCompile(`\b(k[A-Z]\w*)\s*=\s*"([A-Za-z_]\w*)"`)
	reRegister = regexp.MustCompile(`\bREGISTER_([A-Z_]+)\(\s*\$?([A-Za-z_][A-Za-z0-9_]*)`)
)

// stripCpp drops // comment lines and #define blocks (macro parameters look
// like registrations).
func stripCpp(src string) string {
	var b strings.Builder
	inDefine := false
	for _, line := range strings.Split(src, "\n") {
		trim := strings.TrimSpace(line)
		if inDefine || strings.HasPrefix(trim, "#define") {
			inDefine = strings.HasSuffix(trim, "\\")
			continue
		}
		if strings.HasPrefix(trim, "//") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// parseCpp extracts C++-registered command names and aggregation stages,
// expressions, accumulators and window functions.
func parseCpp(c *catalog.Catalog, rel, p string, stages, exprs map[string]bool) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	src := stripCpp(string(raw))
	if !strings.HasSuffix(rel, ".h") {
		for _, m := range reRegister.FindAllStringSubmatch(src, -1) {
			macro, name := m[1], "$"+m[2]
			switch {
			case strings.Contains(macro, "TEST"),
				strings.Contains(macro, "FLE"),
				strings.Contains(macro, "ENCRYPTED"),
				strings.Contains(macro, "GRANULARITY"),
				strings.Contains(macro, "FAST_PATH"),
				strings.Contains(macro, "REWRITE"):
			case strings.Contains(macro, "DOCUMENT_SOURCE"):
				stages[name] = true
			case strings.Contains(macro, "EXPRESSION"),
				strings.Contains(macro, "ACCUMULATOR"),
				strings.Contains(macro, "WINDOW_FUNCTION"):
				exprs[name] = true
			}
		}
	}
	// Shell-side JS scripting registers client commands, not server ones.
	if strings.HasPrefix(rel, "src/mongo/scripting/") {
		return nil
	}
	consts := map[string]string{}
	for _, m := range reConst.FindAllStringSubmatch(src, -1) {
		consts[m[1]] = m[2]
		if m[1] == "kCommandName" {
			addCommand(c, m[2], nil, rel)
		}
	}
	resolve := func(arg string) string {
		if arg == "" {
			return ""
		}
		if strings.HasPrefix(arg, `"`) {
			return strings.Trim(arg, `"`)
		}
		return consts[arg]
	}
	for _, m := range reCmdCtor.FindAllStringSubmatch(src, -1) {
		if !reCmdClass.MatchString(m[1]) {
			continue
		}
		name := resolve(m[2])
		if name == "" {
			continue
		}
		var aliases []string
		if !reAliasClass.MatchString(m[1]) {
			m = m[:3]
		}
		for _, a := range m[3:] {
			if v := resolve(a); v != "" {
				aliases = append(aliases, v)
			}
		}
		addCommand(c, name, aliases, rel)
	}
	return nil
}

type releasesFile struct {
	FCVs []string `yaml:"featureCompatibilityVersions"`
	LTS  []string `yaml:"longTermSupportReleases"`
}

// ParseReleases derives which FCVs a binary of series `version` accepts.
func ParseReleases(b []byte, version string) (catalog.FCVInfo, error) {
	var r releasesFile
	if err := yaml.Unmarshal(b, &r); err != nil {
		return catalog.FCVInfo{}, err
	}
	info := catalog.FCVInfo{Latest: version}
	for _, v := range r.FCVs {
		if v == "100.0" || catalog.CompareVersions(v, version) >= 0 {
			continue
		}
		if info.LastContinuous == "" || catalog.CompareVersions(v, info.LastContinuous) > 0 {
			info.LastContinuous = v
		}
	}
	for _, v := range r.LTS {
		if catalog.CompareVersions(v, version) >= 0 {
			continue
		}
		if info.LastLTS == "" || catalog.CompareVersions(v, info.LastLTS) > 0 {
			info.LastLTS = v
		}
	}
	if info.LastContinuous == "" || info.LastLTS == "" {
		return info, fmt.Errorf("could not derive lastContinuous/lastLTS for %s", version)
	}
	return info, nil
}
