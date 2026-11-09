// Package report renders check and audit results in the layout of MySQL
// Shell's upgrade checker. Every check follows one pattern:
//
//	N) Title (rule-id)
//	   <Status>: text, wrapped at 80 columns with a 3-space hanging indent
//
//	   - affected item
//
//	   Solution:
//	   - what to do
//	        command to copy (never wrapped)
//
//	   More information:
//	     https://...
//
// Sections (deployment-wide checks, each upgrade step, the audit) open with
// a banner, and the report closes with the counts and the checks to act on.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jenunes/ucfm/internal/rules"
	"github.com/jenunes/ucfm/internal/upgradepath"
)

// Formats.
const (
	FormatText     = "text"
	FormatJSON     = "json"
	FormatMarkdown = "md"
)

// Options tweak rendering.
type Options struct {
	Color      bool // ANSI colors in text output
	IssuesOnly bool // hide checks with no issues or that do not apply
}

// section is a titled group of checks (deployment-wide, or one upgrade step).
type section struct {
	title    string
	subtitle string
	checks   []rules.CheckResult
}

// Write renders an upgrade check.
func Write(w io.Writer, res *rules.Result, format string, o Options) error {
	return WriteWith(w, res, nil, format, o)
}

// WriteWith renders an upgrade check optionally followed by a production
// audit (check --with-audit). In JSON the audit is a separate "audit" key.
func WriteWith(w io.Writer, res *rules.Result, audit *rules.AuditResult, format string, o Options) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, res, audit)
	case FormatText, "", FormatMarkdown, "markdown":
	default:
		return fmt.Errorf("unknown format %q (use text, json or md)", format)
	}
	md := format == FormatMarkdown || format == "markdown"
	r := newRenderer(w, md, o)
	r.check(res)
	if audit != nil {
		r.raw("\n")
		r.audit(audit)
	}
	return r.err
}

// WriteAudit renders a production-readiness audit on its own.
func WriteAudit(w io.Writer, a *rules.AuditResult, format string, o Options) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonAudit{SchemaVersion: JSONSchemaVersion, Tool: "ucfm audit", Summary: summary(a.Counts()), AuditResult: a})
	case FormatText, "", FormatMarkdown, "markdown":
	default:
		return fmt.Errorf("unknown format %q (use text, json or md)", format)
	}
	r := newRenderer(w, format != FormatText && format != "", o)
	r.audit(a)
	return r.err
}

// ---------------------------------------------------------------- JSON

// JSONSchemaVersion is bumped on incompatible changes to the JSON report.
const JSONSchemaVersion = 1

type jsonReport struct {
	SchemaVersion int            `json:"schemaVersion"`
	Tool          string         `json:"tool"`
	Summary       map[string]int `json:"summary"`
	*rules.Result
	Audit *jsonAudit `json:"audit,omitempty"`
}

type jsonAudit struct {
	SchemaVersion int            `json:"schemaVersion,omitempty"` // set when the audit is the whole report
	Tool          string         `json:"tool,omitempty"`
	Summary       map[string]int `json:"summary"`
	*rules.AuditResult
}

func writeJSON(w io.Writer, res *rules.Result, audit *rules.AuditResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	r := jsonReport{SchemaVersion: JSONSchemaVersion, Tool: "ucfm", Summary: summary(res.Counts()), Result: res}
	if audit != nil {
		r.Audit = &jsonAudit{Summary: summary(audit.Counts()), AuditResult: audit}
	}
	return enc.Encode(r)
}

func summary(c map[rules.Severity]int) map[string]int {
	return map[string]int{"errors": c[rules.Error], "warnings": c[rules.Warning], "notices": c[rules.Notice]}
}

// ---------------------------------------------------------------- text / md

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
	ansiDim    = "\033[2m"
	width      = 80
)

type renderer struct {
	w   io.Writer
	md  bool
	o   Options
	n   int // running check number
	err error
	// marks lists the checks with findings of each severity, by title, for
	// the closing summary.
	marks map[rules.Severity][]string
}

func newRenderer(w io.Writer, md bool, o Options) *renderer {
	if md {
		o.Color = false
	}
	return &renderer{w: w, md: md, o: o}
}

func (r *renderer) raw(s string) {
	if r.err == nil {
		_, r.err = io.WriteString(r.w, s)
	}
}

func (r *renderer) printf(format string, a ...any) { r.raw(fmt.Sprintf(format, a...)) }

func (r *renderer) c(code, s string) string {
	if !r.o.Color {
		return s
	}
	return code + s + ansiReset
}

func (r *renderer) check(res *rules.Result) {
	intro := fmt.Sprintf("The MongoDB deployment at %s (%s), %s, will now be checked for compatibility issues for upgrade to MongoDB %s (path %s)...",
		res.EntryHost, res.Deployment, res.Versions, res.Target, pathString(res))
	switch {
	case len(res.PlannedPath) > len(res.Hops) && len(res.Hops) > 0:
		intro = fmt.Sprintf("The MongoDB deployment at %s (%s), %s, will now be checked for compatibility issues for upgrade to MongoDB %s, the next step of the path %s...",
			res.EntryHost, res.Deployment, res.Versions, res.CheckedTarget, hopsString(res.PlannedPath))
	case len(res.Hops) > 1:
		intro = fmt.Sprintf("The MongoDB deployment at %s (%s), %s, will now be checked for compatibility issues for upgrade to MongoDB %s (path %s; the steps after %s are a projection)...",
			res.EntryHost, res.Deployment, res.Versions, res.Target, pathString(res), res.Hops[0].Hop)
	}
	sections := []section{{title: "Deployment-wide checks", checks: res.Checks}}
	for i, h := range res.Hops {
		sub := "Checked against " + h.Catalog
		if h.Provisional {
			sub += " (provisional: target not GA)"
		}
		if i > 0 {
			sub += " (projection: assumes the previous steps are done)"
		}
		sections = append(sections, section{title: "Upgrade " + h.Hop.String(), subtitle: sub, checks: h.Checks})
	}
	r.document("Upgrade readiness report", intro, sections)
	c := res.Counts()
	r.footer(c, func() string {
		switch {
		case c[rules.Error] > 0:
			return fmt.Sprintf("%d %s found. Correct %s before upgrading to avoid compatibility issues.", c[rules.Error], plural(c[rules.Error], "error was", "errors were"), plural(c[rules.Error], "it", "them"))
		case c[rules.Warning] > 0:
			return fmt.Sprintf("No errors were found. Review the %d %s before upgrading.", c[rules.Warning], plural(c[rules.Warning], "warning", "warnings"))
		}
		return "No errors or warnings were found."
	}())
}

func (r *renderer) audit(a *rules.AuditResult) {
	host := "Host settings are not part of this run: run ucfm with --local on each database host to include them."
	if a.Host != "" {
		host = "Host settings are read from " + a.Host + "."
	}
	intro := fmt.Sprintf("The MongoDB deployment at %s (%s), %s, will now be checked against the MongoDB Production Notes and Operations Checklist... %s",
		a.EntryHost, a.Deployment, a.Versions, host)
	r.n = 0
	r.document("Production readiness audit", intro, []section{{title: "Production readiness checks", checks: a.Checks}})
	c := a.Counts()
	msg := "No deviations from the production recommendations were found."
	if c[rules.Warning] > 0 {
		msg = fmt.Sprintf("Review the %d %s; the audit lists deviations from the production recommendations.", c[rules.Warning], plural(c[rules.Warning], "warning", "warnings"))
	}
	r.footer(c, msg)
}

// Layout of the text format (MySQL Shell's print_paragraph: 80 columns, body
// at 3, continuation lines 3 further in).
const (
	bodyIndent = 3
	hanging    = 3
	linkIndent = 5
	cmdIndent  = 8
)

// document writes the introduction and every section.
func (r *renderer) document(mdTitle, intro string, sections []section) {
	r.marks = map[rules.Severity][]string{}
	if r.md {
		r.printf("# %s\n\n%s\n", mdTitle, intro)
	} else {
		r.paragraph(intro, 0, 0)
	}
	for _, s := range sections {
		visible := r.visible(s.checks)
		if len(visible) == 0 && r.o.IssuesOnly {
			continue
		}
		if s.title != "" {
			r.banner(s.title, s.subtitle)
		}
		for _, ch := range visible {
			r.n++
			r.entry(r.n, ch)
		}
	}
}

// banner opens a section so it cannot be missed.
func (r *renderer) banner(title, subtitle string) {
	if r.md {
		r.printf("\n## %s\n", title)
		if subtitle != "" {
			r.printf("\n_%s_\n", subtitle)
		}
		return
	}
	rule := strings.Repeat("=", width)
	r.printf("\n%s\n%s\n", rule, r.c(ansiBold, title))
	if subtitle != "" {
		r.paragraph(subtitle, 0, 0)
	}
	r.printf("%s\n", rule)
}

func (r *renderer) visible(cs []rules.CheckResult) []rules.CheckResult {
	if !r.o.IssuesOnly {
		return cs
	}
	var out []rules.CheckResult
	for _, c := range cs {
		if c.Status == rules.StatusIssues || c.Status == rules.StatusNotChecked {
			out = append(out, c)
		}
	}
	return out
}

var (
	severityLabel = map[rules.Severity]string{rules.Error: "Error", rules.Warning: "Warning", rules.Notice: "Notice"}
	severityColor = map[rules.Severity]string{rules.Error: ansiRed + ansiBold, rules.Warning: ansiYellow, rules.Notice: ansiCyan}
)

// entry writes one numbered check: its title, then the status first.
func (r *renderer) entry(n int, ch rules.CheckResult) {
	title := fmt.Sprintf("%d) %s (%s)", n, ch.Title, ch.RuleID)
	if r.md {
		r.printf("\n### %d) %s (`%s`)\n\n", n, ch.Title, ch.RuleID)
	} else {
		// Long titles wrap with the rule ID; continuation lines sit at 4,
		// never at the body indent.
		lines := strings.Split(wrapLines(title, 0, 4), "\n")
		r.raw("\n")
		for _, l := range lines {
			r.printf("%s\n", r.c(ansiBold, l))
		}
	}
	switch ch.Status {
	case rules.StatusOK:
		text := "No issues found"
		if ch.Summary != "" {
			text = "No issues found: " + ch.Summary
		}
		r.status("No issues found", ansiGreen, strings.TrimPrefix(text, "No issues found"))
		return
	case rules.StatusNotApplicable:
		r.status("Not applicable", ansiDim, ": "+sentence(ch.Reason))
		return
	case rules.StatusNotChecked:
		r.status("Not checked", ansiYellow, ": "+sentence(ch.Reason))
		if ch.DocURL != "" {
			r.links([]string{ch.DocURL})
		}
		return
	}
	var urls []string
	marked := map[rules.Severity]bool{}
	for i, f := range ch.Findings {
		if i > 0 {
			r.raw("\n")
		}
		r.finding(f)
		if !marked[f.Severity] {
			marked[f.Severity] = true
			r.marks[f.Severity] = append(r.marks[f.Severity], title)
		}
		for _, u := range append([]string{f.DocURL}, f.DocURLs...) {
			if u != "" && !contains(urls, u) {
				urls = append(urls, u)
			}
		}
	}
	r.links(urls)
}

// status writes the first body line of a check: a colored label and the
// rest of the sentence (rest starts with ":" or is empty).
func (r *renderer) status(label, color, rest string) {
	if r.md {
		r.printf("**%s**%s\n", label, rest)
		return
	}
	r.labelled(label, color, rest)
}

// labelled writes "<label><rest>" as a body paragraph with only the label
// colored.
func (r *renderer) labelled(label, color, rest string) {
	lines := strings.SplitN(wrapLines(label+rest, bodyIndent, hanging), "\n", 2)
	first := strings.Replace(lines[0], label, r.c(color, label), 1)
	r.raw(first + "\n")
	if len(lines) > 1 {
		r.raw(lines[1] + "\n")
	}
}

func (r *renderer) finding(f rules.Finding) {
	label := severityLabel[f.Severity]
	if r.md {
		r.printf("**%s:** %s\n\n", label, f.Message)
		for _, it := range f.Items {
			r.printf("- `%s`\n", strings.ReplaceAll(it, "`", "'"))
		}
		if len(f.Items) > 0 {
			r.raw("\n")
		}
		if f.Action != "" || len(f.Commands) > 0 {
			r.raw("**Solution:**\n\n")
			if f.Action != "" {
				r.printf("- %s\n", f.Action)
			}
			if len(f.Commands) > 0 {
				r.printf("\n```bash\n%s\n```\n", strings.Join(f.Commands, "\n"))
			}
			r.raw("\n")
		}
		return
	}
	r.labelled(label, severityColor[f.Severity], ": "+f.Message)
	if len(f.Items) > 0 {
		r.raw("\n")
		r.bullets(f.Items)
	}
	if f.Action != "" || len(f.Commands) > 0 {
		r.raw("\n")
		r.printf("%sSolution:\n", strings.Repeat(" ", bodyIndent))
		if f.Action != "" {
			r.bullets([]string{f.Action})
		}
		for _, c := range f.Commands {
			// Never wrapped, so it can be copied.
			r.printf("%s%s\n", strings.Repeat(" ", cmdIndent), c)
		}
	}
}

// bullets writes one "- item" per line with a hanging indent.
func (r *renderer) bullets(items []string) {
	for _, it := range items {
		r.paragraph("- "+it, bodyIndent, hanging)
	}
}

// paragraph writes text wrapped at 80 columns: the first line at indent,
// continuation lines hang further in.
func (r *renderer) paragraph(text string, indent, hang int) {
	r.raw(wrapLines(text, indent, hang) + "\n")
}

func (r *renderer) links(urls []string) {
	if len(urls) == 0 {
		return
	}
	if r.md {
		r.raw("More information:\n\n")
		for _, u := range urls {
			r.printf("- <%s>\n", u)
		}
		return
	}
	r.printf("\n%sMore information:\n", strings.Repeat(" ", bodyIndent))
	for _, u := range urls {
		r.printf("%s%s\n", strings.Repeat(" ", linkIndent), u)
	}
}

// footer writes the counts, the checks to act on, and the closing sentence.
func (r *renderer) footer(c map[rules.Severity]int, msg string) {
	if r.md {
		r.printf("\n---\n\n| Errors | Warnings | Notices |\n|---|---|---|\n| %d | %d | %d |\n\n", c[rules.Error], c[rules.Warning], c[rules.Notice])
		for _, sev := range []rules.Severity{rules.Error, rules.Warning} {
			if len(r.marks[sev]) > 0 {
				r.printf("Checks with %ss:\n\n", strings.ToLower(severityLabel[sev]))
				for _, t := range r.marks[sev] {
					r.printf("- %s\n", t)
				}
				r.raw("\n")
			}
		}
		r.printf("%s\n", msg)
		return
	}
	rule := strings.Repeat("=", width)
	r.printf("\n%s\nErrors:   %d\nWarnings: %d\nNotices:  %d\n", rule, c[rules.Error], c[rules.Warning], c[rules.Notice])
	for _, sev := range []rules.Severity{rules.Error, rules.Warning} {
		if len(r.marks[sev]) > 0 {
			r.printf("\nChecks with %ss:\n", strings.ToLower(severityLabel[sev]))
			r.bullets(r.marks[sev])
		}
	}
	r.raw("\n")
	r.paragraph(msg, 0, 0)
}

func pathString(res *rules.Result) string {
	if len(res.Hops) == 0 {
		return res.Source + " → " + res.Target
	}
	parts := []string{res.Hops[0].Hop.From}
	for _, h := range res.Hops {
		parts = append(parts, h.Hop.To)
	}
	return strings.Join(parts, " → ")
}

// hopsString writes a planned path as "6.0 → 7.0 → 8.0".
func hopsString(hops []upgradepath.Hop) string {
	parts := []string{hops[0].From}
	for _, h := range hops {
		parts = append(parts, h.To)
	}
	return strings.Join(parts, " → ")
}

// sentence ends s with a period unless it already ends a sentence.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, ".") || strings.HasSuffix(s, "?") || strings.HasSuffix(s, "!") {
		return s
	}
	return s + "."
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// wrap word-wraps s to width columns. The first line starts at column
// first (after a label already printed); continuation lines are indented by
// indent spaces.
func wrap(s string, first, indent, w int) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := first
	for i, word := range words {
		n := utf8.RuneCountInString(word)
		if i > 0 {
			if col+1+n > w {
				b.WriteString("\n" + strings.Repeat(" ", indent))
				col = indent
			} else {
				b.WriteString(" ")
				col++
			}
		}
		b.WriteString(word)
		col += n
	}
	return b.String()
}

// wrapLines indents text at indent and wraps it at the report width, with
// continuation lines at indent+hang.
func wrapLines(text string, indent, hang int) string {
	return strings.Repeat(" ", indent) + wrap(text, indent, indent+hang, width)
}
