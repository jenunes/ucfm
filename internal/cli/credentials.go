package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// envURI names the environment variable that can hold the connection string,
// so the password does not appear in the process list or shell history.
const envURI = "UCFM_URI"

// uriSource is where resolveURI reads from; tests replace its fields.
type uriSource struct {
	getenv   func(string) string
	readFile func(string) ([]byte, error)
	stat     func(string) (os.FileInfo, error)
	// prompt asks for a password without echo; nil when stdin is not a
	// terminal.
	prompt func(label string) (string, error)
	warn   io.Writer
}

func defaultURISource() uriSource {
	src := uriSource{getenv: os.Getenv, readFile: os.ReadFile, stat: os.Stat, warn: os.Stderr}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		src.prompt = func(label string) (string, error) {
			fmt.Fprint(os.Stderr, label)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		}
	}
	return src
}

// resolveURI fills c.uri from, in order: --uri, --uri-file, UCFM_URI. When
// the connection string names a user without a password, it asks for the
// password on the terminal.
func (c *connFlags) resolveURI(src uriSource) error {
	if c.uri != "" && c.uriFile != "" {
		return errors.New("--uri and --uri-file are mutually exclusive")
	}
	switch {
	case c.uri != "":
	case c.uriFile != "":
		u, err := readURIFile(c.uriFile, src)
		if err != nil {
			return err
		}
		c.uri = u
	default:
		c.uri = strings.TrimSpace(src.getenv(envURI))
	}
	if c.uri == "" {
		return nil
	}
	user, needs := needsPassword(c.uri)
	if !needs {
		return nil
	}
	if src.prompt == nil {
		return fmt.Errorf("the connection string has user %q but no password, and there is no terminal to ask for it; put the password in %s or in a file given with --uri-file", user, envURI)
	}
	pw, err := src.prompt(fmt.Sprintf("Password for %s: ", user))
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	c.uri = withPassword(c.uri, pw)
	return nil
}

// readURIFile returns the first non-empty line of path and warns when other
// users can read the file.
func readURIFile(path string, src uriSource) (string, error) {
	b, err := src.readFile(path)
	if err != nil {
		return "", fmt.Errorf("--uri-file: %w", err)
	}
	if fi, err := src.stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 && src.warn != nil {
		_, _ = fmt.Fprintf(src.warn, "ucfm: warning: %s can be read by other users (mode %04o); run: chmod 600 %s\n", path, fi.Mode().Perm(), path)
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			return line, nil
		}
	}
	return "", fmt.Errorf("--uri-file: %s holds no connection string", path)
}

// splitUserinfo returns the parts of a mongodb:// or mongodb+srv:// URI around
// its user information: prefix ("mongodb://"), userinfo (may be empty) and
// the rest ("host:port,.../?options").
func splitUserinfo(uri string) (prefix, userinfo, rest string, ok bool) {
	i := strings.Index(uri, "://")
	if i < 0 {
		return "", "", "", false
	}
	prefix, rest = uri[:i+3], uri[i+3:]
	end := len(rest)
	if j := strings.IndexAny(rest, "/?"); j >= 0 {
		end = j
	}
	if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
		return prefix, rest[:at], rest[at+1:], true
	}
	return prefix, "", rest, true
}

// needsPassword reports whether the URI names a user without a password and
// uses a mechanism that needs one (x.509, Kerberos and AWS IAM do not).
func needsPassword(uri string) (string, bool) {
	_, userinfo, rest, ok := splitUserinfo(uri)
	if !ok || userinfo == "" || strings.Contains(userinfo, ":") {
		return "", false
	}
	lower := strings.ToLower(rest)
	for _, mech := range []string{"mongodb-x509", "gssapi", "mongodb-aws", "mongodb-oidc"} {
		if strings.Contains(lower, "authmechanism="+mech) {
			return "", false
		}
	}
	return userinfo, true
}

// withPassword inserts a percent-encoded password into the URI's userinfo.
func withPassword(uri, pw string) string {
	prefix, userinfo, rest, _ := splitUserinfo(uri)
	return prefix + userinfo + ":" + percentEncode(pw) + "@" + rest
}

// percentEncode escapes every byte outside RFC 3986's unreserved set, as the
// MongoDB connection string spec requires for user names and passwords.
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.IndexByte("-._~", ch) >= 0 {
			b.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", ch)
	}
	return b.String()
}
