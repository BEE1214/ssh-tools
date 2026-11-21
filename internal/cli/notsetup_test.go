package cli

// P7 clauses G1-G6 at the CLI (PLAN-p7.md): every command that writes an ssh
// config is refused with ErrNotSetUp's text on a config that is not set up and
// changes nothing; read-only commands are unchanged; no setup hint is printed.
// The App-level clauses are in internal/app/notsetup_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nsCmd struct {
	name      string
	args      []string // @D@ is the temp dir
	emptyPath bool     // a bug would reach exec: stop at "not found" instead
	fakeKeyen bool
}

// nsGatedCommands are the commands of G1 (init is tested by init_fresh_test.go
// for the missing-main case, here for the existing one).
func nsGatedCommands() []nsCmd {
	return []nsCmd{
		{name: "add", args: []string{"add", "--name", "new-1", "--hostname", "10.9.9.9"}},
		{name: "add/G3 already exists", args: []string{"add", "--name", "web-1"}},
		{name: "add/G3 exists in included file", args: []string{"add", "--name", "inc-1"}},
		{name: "edit", args: []string{"edit", "web-1", "--user", "zed"}},
		{name: "edit/G3 not found", args: []string{"edit", "ghost", "--user", "zed"}},
		{name: "edit/G3 included host", args: []string{"edit", "inc-1", "--user", "zed"}},
		{name: "edit/G3 multi-pattern", args: []string{"edit", "p-1", "--user", "zed"}},
		{name: "forward --clear", args: []string{"forward", "--clear", "web-1"}},
		{name: "forward --clear/G3 not found", args: []string{"forward", "--clear", "ghost"}},
		{name: "forward --save", args: []string{"forward", "--save", "web-1", "8080:localhost:80"}, emptyPath: true},
		{name: "forward --save/G3 not found", args: []string{"forward", "--save", "ghost", "8080:localhost:80"}, emptyPath: true},
		{name: "cert sign with a host", args: []string{"cert", "sign", "sign-1", "--ca-key", "@D@/keys/ca"}, fakeKeyen: true},
		{name: "cert sign/G3 host not found", args: []string{"cert", "sign", "ghost", "--ca-key", "@D@/keys/ca"}, fakeKeyen: true},
		{name: "cert sign/clar 2 CA key missing", args: []string{"cert", "sign", "sign-1", "--ca-key", "@D@/keys/none"}, fakeKeyen: true},
		{name: "cert revoke of a cert a host references", args: []string{"cert", "revoke", "@D@/keys/web1-cert.pub"}},
		{name: "groups disable", args: []string{"groups", "disable", "web"}},
		{name: "groups enable", args: []string{"groups", "enable", "web"}},
		{name: "groups disable/clar 2 invalid group", args: []string{"groups", "disable", "bad#group"}},
		{name: "init on an existing main file", args: []string{"init"}},
	}
}

func nsRunGated(t *testing.T, e *cliEnv, c nsCmd) (stdout, stderr string, err error) {
	t.Helper()
	if c.emptyPath {
		nsEmptyPath(t)
	}
	args := make([]string, len(c.args))
	for i, a := range c.args {
		args[i] = e.sub(a)
	}
	return runCLI(t, args...)
}

// nsRequireRefused: the command failed with the gate text, nothing about a hint.
func nsRequireRefused(t *testing.T, stdout, stderr string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("the command succeeded, want the refusal %q\nstdout: %s\nstderr: %s", nsGateText, stdout, stderr)
	}
	if !strings.Contains(err.Error(), nsGateText) {
		t.Fatalf("error = %q, want it to contain %q", err, nsGateText)
	}
	if !strings.Contains(stderr, nsGateText) {
		t.Errorf("stderr does not show the refusal %q:\n%s", nsGateText, stderr)
	}
	if all := nsAll(stdout, stderr, err); strings.Contains(all, "hint:") || strings.Contains(all, "keep sshm-managed hosts") {
		t.Errorf("G5: the output mentions the setup hint:\n%s", all)
	}
}

// G1, G2, G3, G5: each write command is refused on a config that is not set up,
// whatever else is wrong with its arguments; nothing is created or changed.
func TestNotSetUpCLI_WriteCommandsAreRefused(t *testing.T) {
	for _, c := range nsGatedCommands() {
		t.Run(c.name, func(t *testing.T) {
			e := nsNotSetUp(t)
			marker := ""
			if c.fakeKeyen {
				marker = nsFakeKeygen(t)
			}
			before := nsSnap(t, e.dir)
			stdout, stderr, err := nsRunGated(t, e, c)
			nsRequireRefused(t, stdout, stderr, err)
			if marker != "" {
				if _, serr := os.Stat(marker); serr == nil {
					t.Errorf("G2: ssh-keygen was run (marker %s exists)", marker)
				}
			}
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// G2 for the certificate commands, spelled out: no certificate is created or
// overwritten, and the revoked certificate file is still there.
func TestNotSetUpCLI_CertCommandsTouchNoCertificate(t *testing.T) {
	e := nsNotSetUp(t)
	marker := nsFakeKeygen(t)
	cert := filepath.Join(e.dir, "keys", "sign1-cert.pub")
	_, _, err := runCLI(t, "cert", "sign", "sign-1", "--ca-key", filepath.Join(e.dir, "keys", "ca"))
	if err == nil || !strings.Contains(err.Error(), nsGateText) {
		t.Fatalf("cert sign = %v, want the gate refusal", err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Error("ssh-keygen ran")
	}
	if _, serr := os.Stat(cert); serr == nil {
		t.Errorf("certificate %s was created", cert)
	}

	old := filepath.Join(e.dir, "keys", "web1-cert.pub")
	_, _, err = runCLI(t, "cert", "revoke", old)
	if err == nil || !strings.Contains(err.Error(), nsGateText) {
		t.Fatalf("cert revoke = %v, want the gate refusal", err)
	}
	if b, rerr := os.ReadFile(old); rerr != nil || string(b) != "OLD-CERT\n" {
		t.Errorf("the certificate file was deleted or changed: %q, %v", b, rerr)
	}
}

// G4: the main file does not exist: every gated command except init says "not set
// up", not "read config: open ...", and creates nothing.
func TestNotSetUpCLI_MissingMainFileIsNotSetUp(t *testing.T) {
	for _, c := range nsGatedCommands() {
		if c.name == "init on an existing main file" {
			continue // init on a fresh machine sets up (I1), see init_fresh_test.go
		}
		if strings.HasPrefix(c.name, "cert revoke") {
			// RevokeCert is not itself gated: the gate fires when a referencing
			// host is found (clarification 4), and with no main file there is none.
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			e := nsNew(t, cliAbsent, cliAbsent)
			if c.fakeKeyen {
				nsFakeKeygen(t)
			}
			before := nsSnap(t, e.dir)
			stdout, stderr, err := nsRunGated(t, e, c)
			nsRequireRefused(t, stdout, stderr, err)
			if strings.Contains(nsAll(stdout, stderr, err), "no such file") {
				t.Errorf("G4: the refusal mentions the missing file:\n%s", stderr)
			}
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// G3: errors of cobra and of argument handling that need no config come first.
// Green now (they are raised before the config is touched).
func TestNotSetUpCLI_ArgumentErrorsComeBeforeTheGate(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"add without --name", []string{"add", "--hostname", "10.9.9.9"}, "name"},
		{"edit without a host", []string{"edit", "--user", "zed"}, "accepts 1 arg"},
		{"edit with an unknown flag", []string{"edit", "web-1", "--bogus", "x"}, "unknown flag"},
		{"edit without any change flag", []string{"edit", "web-1"}, "no changes specified"},
		{"groups disable without a group", []string{"groups", "disable"}, "accepts 1 arg"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := nsNotSetUp(t)
			before := nsSnap(t, e.dir)
			stdout, stderr, err := runCLI(t, c.args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one containing %q", err, c.want)
			}
			if strings.Contains(nsAll(stdout, stderr, err), nsGateText) {
				t.Errorf("the gate answered before the argument error:\n%s", stderr)
			}
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// G5 (+ control): on a set-up config the same commands succeed and print nothing
// about setup: no 'hint:' line, no mention of 'sshm setup'. Green now.
func TestSetUpCLI_WriteCommandsPrintNoSetupHint(t *testing.T) {
	cmds := []nsCmd{
		{name: "add", args: []string{"add", "--name", "new-1", "--hostname", "10.9.9.9"}},
		{name: "edit", args: []string{"edit", "web-1", "--user", "zed"}},
		{name: "forward --clear", args: []string{"forward", "--clear", "web-1"}},
		{name: "cert sign with a host", args: []string{"cert", "sign", "sign-1", "--ca-key", "@D@/keys/ca"}, fakeKeyen: true},
		{name: "groups disable", args: []string{"groups", "disable", "db"}},
		{name: "init", args: []string{"init"}},
	}
	for _, c := range cmds {
		t.Run(c.name, func(t *testing.T) {
			e := nsSetUp(t)
			if c.fakeKeyen {
				nsFakeKeygen(t)
			}
			stdout, stderr, err := nsRunGated(t, e, c)
			if err != nil {
				t.Fatalf("the command failed on a set-up config: %v\nstderr: %s", err, stderr)
			}
			if all := nsAll(stdout, stderr, err); strings.Contains(all, "hint:") || strings.Contains(all, "sshm setup") {
				t.Errorf("G5: the output mentions setup:\n%s", all)
			}
		})
	}
	t.Run("groups enable", func(t *testing.T) {
		nsSetUp(t)
		if _, _, err := runCLI(t, "groups", "disable", "db"); err != nil {
			t.Fatalf("disable: %v", err)
		}
		stdout, stderr, err := runCLI(t, "groups", "enable", "db")
		if err != nil {
			t.Fatalf("enable: %v", err)
		}
		if all := nsAll(stdout, stderr, err); strings.Contains(all, "hint:") || strings.Contains(all, "sshm setup") {
			t.Errorf("G5: the output mentions setup:\n%s", all)
		}
	})
}

// G6: read-only commands behave as before on a config that is not set up and
// change nothing. Characterization, green now.
func TestNotSetUpCLI_ReadOnlyCommandsUnchanged(t *testing.T) {
	e := nsNotSetUp(t)
	before := nsSnap(t, e.dir)

	check := func(name string, args []string, wantOut string) {
		t.Helper()
		stdout, stderr, err := runCLI(t, args...)
		if err != nil {
			t.Errorf("%s: %v\n%s", name, err, stderr)
			return
		}
		if !strings.Contains(stdout+stderr, wantOut) {
			t.Errorf("%s: output lacks %q:\nstdout: %s\nstderr: %s", name, wantOut, stdout, stderr)
		}
	}
	check("list", []string{"list"}, "web-1")
	check("list --flat", []string{"list", "--flat"}, "inc-1")
	check("search", []string{"search", "web"}, "web-1")
	check("dump", []string{"dump", "web-1"}, "HostName 10.0.0.1")
	check("validate", []string{"validate"}, "")
	check("groups", []string{"groups"}, "web (1)")
	check("cert list", []string{"cert", "list"}, "No certificates found")
	nsRequireSame(t, before, nsSnap(t, e.dir))

	nsEmptyPath(t)
	for name, args := range map[string][]string{
		"connect":      {"web-1"},
		"connect cmd":  {"connect", "web-1"},
		"copy":         {"copy", "web-1:/tmp/x", filepath.Join(e.dir, "x")},
		"forward only": {"forward", "web-1", "8080:localhost:80"},
	} {
		_, stderr, err := runCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), "not found in PATH") || strings.Contains(stderr, nsGateText) {
			t.Errorf("%s: error %v (stderr %q), want the 'not found in PATH' stop and no gate", name, err, stderr)
		}
	}
	nsRequireSame(t, before, nsSnap(t, e.dir))

	// cert revoke without a referencing host: deletes the file, config untouched
	cfg := cliRead(t, e.main)
	_, stderr, err := runCLI(t, "cert", "revoke", filepath.Join(e.dir, "keys", "orphan-cert.pub"))
	if err != nil || !strings.Contains(stderr, "Certificate revoked") {
		t.Errorf("cert revoke of an unreferenced cert: err %v, stderr %q", err, stderr)
	}
	if _, serr := os.Stat(filepath.Join(e.dir, "keys", "orphan-cert.pub")); serr == nil {
		t.Error("the unreferenced certificate was not deleted")
	}
	if cliRead(t, e.main) != cfg {
		t.Error("the config changed")
	}
}

// G6 + G4: with no main file the read-only commands keep the read error.
// Characterization, green now.
func TestNotSetUpCLI_ReadOnlyCommandsOnMissingMainKeepReadError(t *testing.T) {
	e := nsNew(t, cliAbsent, cliAbsent)
	want := "open " + e.main + ": no such file or directory"
	for name, args := range map[string][]string{
		"list":     {"list"},
		"search":   {"search", "web"},
		"dump":     {"dump", "web-1"},
		"validate": {"validate"},
		"groups":   {"groups"},
	} {
		_, stderr, err := runCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), nsGateText) {
			t.Errorf("%s: error %v, want the read error containing %q", name, err, want)
		}
		if !strings.Contains(stderr, "read config") {
			t.Logf("%s: stderr %q", name, stderr)
		}
	}
	if _, err := os.Stat(e.main); err == nil {
		t.Error("a read-only command created the main file")
	}
}
