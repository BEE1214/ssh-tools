package cli

// P7 clauses M1 and M2 at the CLI (PLAN-p7.md): a write addressed by one pattern
// of a multi-pattern Host line, or by its whole line text, is refused with the
// fixed text and changes nothing. The App-level clauses are in
// internal/app/multipattern_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mpMain = "Include @M@\nInclude @D@/extra.conf\n\nHost mm-1 mm-2\n  HostName 10.0.2.1\n"

const mpManaged = cliManagedHeader + `
Host web-1
  HostName 10.0.0.1

Host sign-1
  HostName 10.0.0.4
  IdentityFile @D@/keys/sign1

Host db-1 db-2
  HostName 10.0.2.20

Host dup-1
  HostName 10.0.2.30

Host dc-1 dc-2 # pair
  HostName 10.0.2.21
`

func mpText(name, file string) string {
	return `"Host ` + name + `" in ` + file + ` has several patterns, which sshm cannot edit`
}

func TestMultiPatternCLI_WritesAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		host  string // block name
		where func(e *cliEnv) string
	}{
		{"edit by pattern (managed file)", []string{"edit", "db-1", "--user", "zed"}, "db-1 db-2", func(e *cliEnv) string { return e.managed }},
		{"edit by the other pattern", []string{"edit", "db-2", "--user", "zed"}, "db-1 db-2", func(e *cliEnv) string { return e.managed }},
		{"edit by the whole line text (M2)", []string{"edit", "db-1 db-2", "--user", "zed"}, "db-1 db-2", func(e *cliEnv) string { return e.managed }},
		// the name has the comment stripped (N1, item 13): "dc-1 dc-2", not "dc-1 dc-2 # pair"
		{"edit by pattern, line with a comment", []string{"edit", "dc-1", "--user", "zed"}, "dc-1 dc-2", func(e *cliEnv) string { return e.managed }},
		{"edit by the whole name, line with a comment", []string{"edit", "dc-1 dc-2", "--user", "zed"}, "dc-1 dc-2", func(e *cliEnv) string { return e.managed }},
		{"edit by pattern (main file, wins over the import hint)", []string{"edit", "mm-1", "--user", "zed"}, "mm-1 mm-2", func(e *cliEnv) string { return e.main }},
		{"forward --clear", []string{"forward", "--clear", "db-1"}, "db-1 db-2", func(e *cliEnv) string { return e.managed }},
		{"cert sign", []string{"cert", "sign", "db-1", "--ca-key", "@D@/keys/ca"}, "db-1 db-2", func(e *cliEnv) string { return e.managed }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := nsNew(t, mpMain, mpManaged)
			marker := nsFakeKeygen(t)
			before := nsSnap(t, e.dir)
			args := make([]string, len(c.args))
			for i, a := range c.args {
				args[i] = e.sub(a)
			}
			_, stderr, err := runCLI(t, args...)
			want := mpText(c.host, c.where(e))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want one containing %q", err, want)
			}
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
			if strings.Contains(err.Error(), "sshm import") {
				t.Errorf("the import hint must not be offered for a multi-pattern line: %v", err)
			}
			if _, serr := os.Stat(marker); serr == nil {
				t.Error("ssh-keygen ran")
			}
			if _, serr := os.Stat(filepath.Join(e.dir, "keys", "sign1-cert.pub")); serr == nil {
				t.Error("a certificate was created")
			}
			// lock files stay behind after a refused save; everything else is untouched
			after := nsSnap(t, e.dir)
			for _, d := range nsDiff(before, after) {
				if !strings.HasSuffix(d, ".sshm.lock") {
					t.Errorf("the ssh dir changed: %s", d)
				}
			}
		})
	}
}

// M2: a single-pattern block of the typed name still edits normally.
func TestMultiPatternCLI_SingleBlockStillEdits(t *testing.T) {
	e := nsNew(t, mpMain, mpManaged)
	if _, stderr, err := runCLI(t, "edit", "dup-1", "--user", "zed"); err != nil {
		t.Fatalf("edit dup-1: %v\n%s", err, stderr)
	}
	if got := e.readManaged(t); !strings.Contains(got, "Host dup-1\n  HostName 10.0.2.30\n  User zed") {
		t.Errorf("single block not edited:\n%s", got)
	}
}
