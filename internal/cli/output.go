package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jenunes/ucfm/internal/rules"
)

// openOutput returns the report writer (stdout or a file), its closer, and
// whether ANSI colors should be used.
func openOutput(cmd *cobra.Command, path, format string) (io.Writer, func() error, bool, error) {
	if path == "" {
		color := format == "text" && os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout) && cmd.OutOrStdout() == os.Stdout
		return cmd.OutOrStdout(), func() error { return nil }, color, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, false, err
	}
	return f, f.Close, false, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// exitFor maps the worst severity to the process exit code.
func exitFor(res interface{ Max() rules.Severity }) error {
	switch res.Max() {
	case rules.Error:
		return exitError{ExitErrors}
	case rules.Warning:
		return exitError{ExitWarnings}
	}
	return nil
}

func listRules(w io.Writer, format string) error {
	var b strings.Builder
	all := rules.All()
	if format == "md" {
		b.WriteString("| Rule | Scope | Max severity | Category | Title |\n|---|---|---|---|---|\n")
		for _, r := range all {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", r.ID, scopeName(r), r.Severity, r.Category, r.Title)
		}
	} else {
		for _, r := range all {
			fmt.Fprintf(&b, "%-32s %-22s %-8s %-11s %s\n", r.ID, scopeName(r), r.Severity, r.Category, r.Title)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func scopeName(r rules.Rule) string {
	if r.Scope == rules.ScopeGlobal {
		return "deployment"
	}
	if r.Scope == rules.ScopeProduction {
		return "audit"
	}
	if len(r.Hops) == 0 {
		return "every hop"
	}
	var hs []string
	for _, h := range r.Hops {
		hs = append(hs, h.From+"→"+h.To)
	}
	return strings.Join(hs, ",")
}
