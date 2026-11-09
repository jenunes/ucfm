package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jenunes/ucfm/internal/report"
	"github.com/jenunes/ucfm/internal/rules"
)

func newCollectCmd() *cobra.Command {
	var (
		conn   connFlags
		out    string
		local  bool
		config string
	)
	cmd := &cobra.Command{
		Use: "collect",
		Example: `  ucfm collect --uri "mongodb://ucfm:PASS@db1:27017/?authSource=admin" -o snapshot.json
  ucfm collect --uri "mongodb://ucfm:PASS@localhost:27017/?authSource=admin" --local -o db1.json`,
		Short: "Collect a read-only snapshot of a deployment for offline analysis",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return errors.New("--output is required")
			}
			src := sourceFlags{connFlags: conn, saveSnapshot: out, local: local, configFile: config}
			if err := src.validate(); err != nil {
				return err
			}
			snap, err := src.snapshot(cmd.Context())
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "snapshot written to %s (%d nodes, %d collection errors)\n", out, len(snap.Nodes), len(snap.Errors))
			return nil
		},
	}
	conn.register(cmd)
	cmd.Flags().StringVarP(&out, "output", "o", "", "snapshot file to write")
	cmd.Flags().BoolVar(&local, "local", false, "also collect host/OS facts (must run on the database host)")
	cmd.Flags().StringVar(&config, "config", "", "path to mongod.conf to include (implies --local)")
	return cmd
}

func newCheckCmd() *cobra.Command {
	var (
		src        sourceFlags
		target     string
		format     string
		output     string
		withAudit  bool
		issuesOnly bool
		future     bool
	)
	cmd := &cobra.Command{
		Use: "check",
		Example: `  ucfm check --uri "mongodb://ucfm:PASS@db1:27017/?authSource=admin" --target 8.0
  ucfm check --uri "mongodb://ucfm:PASS@mongos1:27017/?authSource=admin" --target 9.0 --format md -o report.md
  ucfm check --uri "mongodb://ucfm:PASS@localhost:27017/?authSource=admin" --target 8.0 --local
  ucfm check --from-snapshot snapshot.json --target 8.0`,
		Short: "Check upgrade readiness for a target version and report action items",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := src.validate(); err != nil {
				return err
			}
			if target == "" {
				return errors.New("--target is required")
			}
			snap, err := src.snapshot(cmd.Context())
			if err != nil {
				return err
			}
			res, err := rules.Run(snap, target, rules.Options{SeeTheFuture: future})
			if err != nil {
				return err
			}
			var audit *rules.AuditResult
			if withAudit {
				if audit, err = rules.Audit(snap); err != nil {
					return err
				}
			}
			w, closeFn, color, err := openOutput(cmd, output, format)
			if err != nil {
				return err
			}
			if err := report.WriteWith(w, res, audit, format, report.Options{Color: color, IssuesOnly: issuesOnly}); err != nil {
				return err
			}
			if err := closeFn(); err != nil {
				return err
			}
			if src.local && !withAudit && snap.Host != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ucfm: note: --local checked the host settings that matter for upgrading to %s. For this host's full production checklist (swappiness, readahead, limits, filesystem, NUMA, clock, ...), add --with-audit or run: ucfm audit --local\n", res.CheckedTarget)
			}
			// The audit is informational here: the exit code reflects the
			// upgrade check only.
			return exitFor(res)
		},
	}
	src.register(cmd)
	cmd.Flags().StringVar(&target, "target", "", "target version (6.0, 7.0, 8.0, 8.3, 9.0)")
	cmd.Flags().BoolVar(&withAudit, "with-audit", false, "append the production-readiness audit (does not change the exit code)")
	cmd.Flags().BoolVar(&issuesOnly, "issues-only", false, "list only checks that found issues or could not run")
	cmd.Flags().StringVar(&format, "format", "text", "report format: text, json or md")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the report to this file instead of stdout")
	cmd.Flags().BoolVar(&future, "see-the-future", false, "check every upgrade step to --target now; the steps after the first are a projection of a deployment that does not exist yet")
	_ = cmd.Flags().MarkHidden("see-the-future")
	return cmd
}

func newListRulesCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list-rules",
		Short: "List the checks the tool runs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return listRules(cmd.OutOrStdout(), format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or md")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the tool version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, c := buildVersion()
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "ucfm %s (commit %s)\n", v, c)
			return err
		},
	}
}
