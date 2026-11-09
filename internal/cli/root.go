// Package cli wires the cobra command tree.
package cli

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

// Exit codes, mirroring the severity model of the report.
const (
	ExitOK          = 0 // no findings above NOTICE
	ExitWarnings    = 1 // at least one WARNING, no ERROR
	ExitErrors      = 2 // at least one ERROR (fix before upgrading)
	ExitToolFailure = 3 // the tool itself failed (connection, bad flags, ...)
)

// Build metadata, set via -ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
)

// buildVersion returns the version and commit set at build time, or, for a
// plain `go install` build, the module version and VCS revision Go records.
func buildVersion() (version, commit string) {
	version, commit = Version, Commit
	if version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		version = v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && commit == "none" && len(s.Value) >= 7 {
			commit = s.Value[:7]
		}
	}
	return
}

// exitError carries a specific exit code out of a command.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// connFlags are shared by every subcommand that talks to a live deployment.
type connFlags struct {
	uri           string
	uriFile       string
	entryOnly     bool
	skipData      bool
	skipSecurity  bool
	maxNamespaces int
	verbose       bool
	deepCheck     bool
}

func (c *connFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&c.uri, "uri", "", `connection string of any replica set member, a mongos or a standalone, e.g. "mongodb://user@db1:27017/?authSource=admin" (credentials and TLS options are reused for every member; without a password ucfm asks for it; or use UCFM_URI / --uri-file)`)
	cmd.Flags().StringVar(&c.uriFile, "uri-file", "", "read the connection string from the first line of this file (keep it chmod 600)")
	cmd.Flags().BoolVar(&c.entryOnly, "entry-only", false, "inspect only the node in --uri; do not connect to other members, shards or routers")
	cmd.Flags().BoolVar(&c.skipData, "skip-data", false, "do not list databases, collections, views and indexes")
	cmd.Flags().BoolVar(&c.skipSecurity, "skip-security", false, "do not read users and roles")
	cmd.Flags().IntVar(&c.maxNamespaces, "max-namespaces", 20000, "stop listing collections after this many namespaces")
	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v", false, "log collection progress to stderr")
	cmd.Flags().BoolVar(&c.deepCheck, "deep-check", false, "sample up to 1000 documents per collection to verify data-dependent changes (reads documents)")
}

// sourceFlags let analysis commands run live or from a saved snapshot.
type sourceFlags struct {
	connFlags
	fromSnapshot string
	saveSnapshot string
	local        bool
	configFile   string
}

func (s *sourceFlags) register(cmd *cobra.Command) {
	s.connFlags.register(cmd)
	cmd.Flags().StringVar(&s.fromSnapshot, "from-snapshot", "", "analyze a snapshot file written by 'collect' instead of connecting")
	cmd.Flags().StringVar(&s.saveSnapshot, "save-snapshot", "", "also write the collected snapshot to this file")
	cmd.Flags().BoolVar(&s.local, "local", false, "run host/OS checks (must run on the database host)")
	cmd.Flags().StringVar(&s.configFile, "config", "", "path to mongod.conf to inspect (implies --local)")
}

func (s *sourceFlags) validate() error {
	return s.validateWith(defaultURISource())
}

func (s *sourceFlags) validateWith(src uriSource) error {
	if s.fromSnapshot != "" && (s.uri != "" || s.uriFile != "") {
		return errors.New("--uri and --from-snapshot are mutually exclusive")
	}
	if s.fromSnapshot == "" {
		if err := s.resolveURI(src); err != nil {
			return err
		}
	}
	if s.fromSnapshot == "" && s.uri == "" {
		return errors.New("one of --uri, --uri-file, " + envURI + " or --from-snapshot is required")
	}
	if s.configFile != "" {
		s.local = true
	}
	return nil
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ucfm",
		Short: "UCFM (Upgrade Checker For MongoDB): check whether a MongoDB upgrade can break anything",
		Long: `ucfm (Upgrade Checker For MongoDB) checks a MongoDB or Percona Server for MongoDB
deployment before an upgrade. It is read-only: it never changes the deployment.

  check     compatibility issues for an upgrade to --target (ERROR / WARNING / NOTICE)
  audit     deviations from the MongoDB Production Notes and Operations Checklist
  collect   save a snapshot to analyze later with --from-snapshot

Supported versions: 6.0, 7.0, 8.0, 8.3, 9.0.

CONNECTING
  Pass a standard MongoDB connection string with --uri. Point it at one node;
  ucfm discovers the rest and connects to each member with the same
  credentials and TLS options.

    Replica set       any member:  --uri "mongodb://USER:PASS@db1:27017/?authSource=admin"
    Sharded cluster   a mongos:    --uri "mongodb://USER:PASS@mongos1:27017/?authSource=admin"
    Standalone        the server:  --uri "mongodb://USER:PASS@db1:27017/?authSource=admin"
    TLS               add options: "...?authSource=admin&tls=true&tlsCAFile=/etc/ssl/ca.pem"

  Keep the password off the command line (it shows in ps and shell history):
  leave it out of --uri and ucfm asks for it, or put the whole string in the
  UCFM_URI environment variable or in a file given with --uri-file.

  The host running ucfm must reach every member by the host names in the
  replica set configuration; otherwise add --entry-only to check only the
  node in --uri. Add --local when running on a database server to include
  host checks (THP, kernel, limits, filesystem).

  The user needs clusterMonitor and readAnyDatabase (plus viewUser/viewRole
  for the user and role checks). See docs/getting-started/requirements.md.`,
		Example: `  ucfm check   --uri "mongodb://ucfm:PASS@db1:27017/?authSource=admin" --target 8.0
  ucfm audit   --uri "mongodb://ucfm:PASS@localhost:27017/?authSource=admin" --local
  ucfm collect --uri "mongodb://ucfm:PASS@db1:27017/?authSource=admin" -o snapshot.json
  ucfm check   --from-snapshot snapshot.json --target 9.0`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		// "ucfm --uri ..." without a command: say what is missing.
		if c.Parent() == nil && strings.HasPrefix(err.Error(), "unknown flag") {
			return fmt.Errorf("%v: options go after a command, for example:\n  ucfm check --uri \"mongodb://...\" --target 8.0\ncommands: check, audit, collect, list-rules, version (see ucfm --help)", err)
		}
		return err
	})
	root.AddCommand(
		newCollectCmd(),
		newCheckCmd(),
		newListRulesCmd(),
		newAuditCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	err := newRootCmd().Execute()
	if err == nil {
		return ExitOK
	}
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return ExitToolFailure
}
