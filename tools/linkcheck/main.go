// Command linkcheck checks the relative links of Markdown files: every linked
// file must exist and every #anchor must match a heading (GitHub slug rules)
// or an explicit id/name in the target file. External links are not fetched.
//
//	go run ./tools/linkcheck README.md docs
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"README.md", "docs"}
	}
	files, err := markdownFiles(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "linkcheck:", err)
		os.Exit(2)
	}
	problems := Check(files)
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "linkcheck: %d broken link(s) in %d file(s)\n", len(problems), len(files))
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "linkcheck: %d file(s), no broken links\n", len(files))
}

// markdownFiles expands directories into the .md files they contain.
func markdownFiles(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		fi, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			out = append(out, a)
			continue
		}
		err = filepath.WalkDir(a, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".md") {
				out = append(out, p)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

var (
	mdLink   = regexp.MustCompile(`!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	htmlRef  = regexp.MustCompile(`(?i)<(?:a|img)\b[^>]*\s(?:href|src)="([^"]+)"`)
	htmlID   = regexp.MustCompile(`(?i)\s(?:id|name)="([^"]+)"`)
	heading  = regexp.MustCompile(`^#{1,6}\s+(.*?)\s*#*\s*$`)
	inlineCo = regexp.MustCompile("`[^`]*`")
	scheme   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
)

// Check returns one line per broken link, as "file:line: target: reason".
func Check(files []string) []string {
	anchors := map[string]map[string]bool{}
	anchorsOf := func(path string) (map[string]bool, error) {
		if a, ok := anchors[path]; ok {
			return a, nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		a := Anchors(string(b))
		anchors[path] = a
		return a, nil
	}
	var problems []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", f, err))
			continue
		}
		for _, l := range Links(string(b)) {
			target := l.Target
			if isExternal(target) {
				continue
			}
			path, frag, _ := strings.Cut(target, "#")
			resolved := f
			if path != "" {
				resolved = filepath.Join(filepath.Dir(f), path)
				fi, err := os.Stat(resolved)
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s:%d: %s: file not found", f, l.Line, target))
					continue
				}
				if fi.IsDir() || !strings.HasSuffix(resolved, ".md") {
					if frag != "" && !fi.IsDir() {
						problems = append(problems, fmt.Sprintf("%s:%d: %s: anchor on a non-Markdown file", f, l.Line, target))
					}
					continue
				}
			}
			if frag == "" {
				continue
			}
			a, err := anchorsOf(resolved)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s:%d: %s: %v", f, l.Line, target, err))
				continue
			}
			if !a[strings.ToLower(frag)] {
				problems = append(problems, fmt.Sprintf("%s:%d: %s: no heading or id %q in %s", f, l.Line, target, frag, resolved))
			}
		}
	}
	return problems
}

// Link is one link found in a Markdown file.
type Link struct {
	Line   int
	Target string
}

// Links returns the link targets outside fenced code blocks and inline code.
func Links(md string) []Link {
	var out []Link
	inFence := false
	for i, line := range strings.Split(md, "\n") {
		if fence(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		line = inlineCo.ReplaceAllString(line, "")
		for _, re := range []*regexp.Regexp{mdLink, htmlRef} {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				t := strings.Trim(m[1], "<>")
				if t != "" {
					out = append(out, Link{Line: i + 1, Target: t})
				}
			}
		}
	}
	return out
}

// Anchors returns the anchors a Markdown file defines: GitHub heading slugs
// (with -1, -2 … for repeats) and explicit id/name attributes.
func Anchors(md string) map[string]bool {
	out := map[string]bool{}
	seen := map[string]int{}
	inFence := false
	for _, line := range strings.Split(md, "\n") {
		if fence(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range htmlID.FindAllStringSubmatch(line, -1) {
			out[strings.ToLower(m[1])] = true
		}
		m := heading.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s := Slug(m[1])
		if n := seen[s]; n > 0 {
			out[fmt.Sprintf("%s-%d", s, n)] = true
		} else {
			out[s] = true
		}
		seen[s]++
	}
	return out
}

var (
	mdLinkText = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)`)
	htmlTag    = regexp.MustCompile(`<[^>]+>`)
)

// Slug turns heading text into its GitHub anchor: link text kept, markup
// removed, lowercased, spaces to hyphens, punctuation other than hyphens and
// underscores dropped.
func Slug(text string) string {
	text = mdLinkText.ReplaceAllString(text, "$1")
	text = htmlTag.ReplaceAllString(text, "")
	var b strings.Builder
	for _, r := range strings.ToLower(text) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

func fence(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~")
}

func isExternal(target string) bool {
	if strings.HasPrefix(target, "//") {
		return true
	}
	return scheme.MatchString(target)
}
