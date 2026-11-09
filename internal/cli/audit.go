package cli

import (
	"github.com/spf13/cobra"

	"github.com/jenunes/ucfm/internal/report"
	"github.com/jenunes/ucfm/internal/rules"
)

func newAuditCmd() *cobra.Command {
	var (
		src        sourceFlags
		format     string
		output     string
		issuesOnly bool
	)
	cmd := &cobra.Command{
		Use: "audit",
		Example: `  ucfm audit --uri "mongodb://ucfm:PASS@db1:27017/?authSource=admin"
  ucfm audit --uri "mongodb://ucfm:PASS@localhost:27017/?authSource=admin" --local`,
		Short: "Audit the deployment against the MongoDB Production Notes and Operations Checklist",
		Long: `audit checks the running deployment against the MongoDB Production Notes and
Operations Checklist (THP, swappiness, NUMA, filesystem, readahead, limits,
clock sync, access control, replica set layout, oplog window, ...).

It is separate from 'check': it needs no --target and never affects upgrade
findings. Run it with --local on each database host to include host settings.
Exit codes: 0 no findings above NOTICE, 1 warnings, 3 tool failure.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := src.validate(); err != nil {
				return err
			}
			snap, err := src.snapshot(cmd.Context())
			if err != nil {
				return err
			}
			res, err := rules.Audit(snap)
			if err != nil {
				return err
			}
			w, closeFn, color, err := openOutput(cmd, output, format)
			if err != nil {
				return err
			}
			if err := report.WriteAudit(w, res, format, report.Options{Color: color, IssuesOnly: issuesOnly}); err != nil {
				return err
			}
			if err := closeFn(); err != nil {
				return err
			}
			return exitFor(res)
		},
	}
	src.register(cmd)
	cmd.Flags().StringVar(&format, "format", "text", "report format: text, json or md")
	cmd.Flags().BoolVar(&issuesOnly, "issues-only", false, "list only checks that found issues or could not run")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write the report to this file instead of stdout")
	return cmd
}
