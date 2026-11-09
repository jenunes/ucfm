package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestHelpListsSubcommands(t *testing.T) {
	out, err := run(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"collect", "check", "audit", "list-rules", "version"} {
		if !strings.Contains(out, sub) {
			t.Errorf("help output missing subcommand %q", sub)
		}
	}
}

func TestVersion(t *testing.T) {
	out, err := run(t, "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "ucfm ") {
		t.Errorf("unexpected version output %q", out)
	}
}

func TestCheckFlagValidation(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"check", "--target", "8.0"}, "one of --uri, --uri-file, UCFM_URI or --from-snapshot"},
		{[]string{"check", "--uri", "mongodb://x", "--from-snapshot", "s.json", "--target", "8.0"}, "mutually exclusive"},
		{[]string{"check", "--uri", "mongodb://x"}, "--target is required"},
	}
	for _, c := range cases {
		_, err := run(t, c.args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: got err %v, want containing %q", c.args, err, c.want)
		}
	}
}

func exitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	if ee, ok := err.(exitError); ok {
		return ee.code
	}
	return ExitToolFailure
}

// The audit is informational inside check: --with-audit must not change the
// upgrade check's exit code, even when the audit itself has warnings.
func TestWithAuditKeepsCheckExitCode(t *testing.T) {
	snap := "../../testdata/snapshots/rs80.json"
	_, plain := run(t, "check", "--from-snapshot", snap, "--target", "8.3", "--format", "json")
	out, with := run(t, "check", "--from-snapshot", snap, "--target", "8.3", "--format", "json", "--with-audit")
	if exitCode(plain) != exitCode(with) {
		t.Fatalf("exit code changed: %d vs %d", exitCode(plain), exitCode(with))
	}
	if !strings.Contains(out, `"audit"`) || !strings.Contains(out, "prod-authorization") {
		t.Errorf("audit section missing from --with-audit output")
	}
	_, auditErr := run(t, "audit", "--from-snapshot", snap)
	if exitCode(auditErr) != ExitWarnings {
		t.Errorf("audit exit = %d, want %d (rs80 has no access control)", exitCode(auditErr), ExitWarnings)
	}
}

func TestFlagsWithoutCommandSayWhatIsMissing(t *testing.T) {
	_, err := run(t, "--uri", "mongodb://x", "--target", "7.0")
	if err == nil || !strings.Contains(err.Error(), "options go after a command") || !strings.Contains(err.Error(), "ucfm check --uri") {
		t.Fatalf("got %v", err)
	}
	if _, err := run(t, "check", "--bogus"); err == nil || strings.Contains(err.Error(), "options go after a command") {
		t.Fatalf("a bad flag on a command keeps cobra's message, got %v", err)
	}
}

func TestNoRunbookCommand(t *testing.T) {
	if _, err := run(t, "runbook", "--target", "8.0"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("ucfm only checks; runbook must not exist, got %v", err)
	}
}
