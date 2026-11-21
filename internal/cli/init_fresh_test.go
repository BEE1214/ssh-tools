package cli

// P7 clauses I1-I4 and clarifications 1, 8, 9 at the CLI (PLAN-p7.md): `sshm
// init` on a machine without an ssh config performs the setup actions and stops
// there; the second `init` adds the Host * block; on an existing config that is
// not set up it is refused. The App-level clauses are in
// internal/app/init_fresh_test.go.
//
// The fresh-machine fixtures are empty directories. The twin run of `sshm setup`
// is the oracle for "exactly the setup actions" (this is the one place where a
// fixture is made by a command, because the clause is about that command).

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

type frEnv struct {
	base, sshDir, main, managed string
}

// frNew is a fresh machine: <tmp>/ssh does not exist. It points SSH_AUTH_CONFIG
// at <tmp>/ssh/config (not at <home>/.ssh/config, so the Include is absolute).
func frNew(t *testing.T) *frEnv {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Cleanup(config.SetHomeDirForTest(t.TempDir()))
	base := t.TempDir()
	e := &frEnv{base: base, sshDir: filepath.Join(base, "ssh")}
	e.main = filepath.Join(e.sshDir, "config")
	e.managed = filepath.Join(e.sshDir, "config.d", "sshm.conf")
	t.Setenv("SSH_AUTH_CONFIG", e.main)
	return e
}

// frRequireSetUpState: the files `sshm setup` leaves on a machine with nothing.
func frRequireSetUpState(t *testing.T, e *frEnv, wantManaged string) {
	t.Helper()
	for _, d := range []string{e.sshDir, filepath.Dir(e.managed)} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v, want a directory with 0700", d, fi.Mode())
		}
	}
	for path, want := range map[string]string{e.managed: wantManaged} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, want 0600", path, fi.Mode().Perm())
		}
		if got := cliRead(t, path); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	fi, err := os.Stat(e.main)
	if err != nil {
		t.Fatalf("main file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("main file mode %v, want 0600", fi.Mode().Perm())
	}
	content := cliLines(cliRead(t, e.main))
	if len(content) != 1 || content[0] != "Include "+e.managed {
		t.Errorf("main file lines = %q, want exactly [%q]", content, "Include "+e.managed)
	}
}

// I1 + I2: `sshm init` on a machine without an ssh config does what `sshm setup`
// does, prints what it prints (stderr) plus one closing line, writes no Host *
// block, and leaves a config that ssh, list and validate accept.
func TestInitFreshCLI_SetsUpAndStops(t *testing.T) {
	// the oracle: what `sshm setup` prints on an identical fresh machine
	tw := frNew(t)
	_, twinErr, err := runCLI(t, "setup")
	if err != nil {
		t.Fatalf("twin setup: %v", err)
	}
	if n := strings.Count(twinErr, "create "); n != 4 {
		t.Fatalf("twin setup printed %d 'create' lines, want 4:\n%s", n, twinErr)
	}

	e := frNew(t)
	stdout, stderr, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init: %v\nstderr: %s", err, stderr)
	}
	want := strings.ReplaceAll(twinErr, tw.base, e.base) +
		"created an empty " + e.managed + "; run 'sshm init' again to add the default Host * block\n"
	if stderr != want {
		t.Errorf("stderr =\n%s\nwant\n%s", stderr, want)
	}
	if strings.Contains(stdout, "create ") || strings.Contains(stdout, "created an empty") {
		t.Errorf("the setup lines are on stdout, want stderr like `sshm setup`:\n%s", stdout)
	}
	frRequireSetUpState(t, e, cliManagedHeader)
	for _, p := range []string{e.main, e.managed} {
		if strings.Contains(cliRead(t, p), "Host *") {
			t.Errorf("%s has a Host * block:\n%s", p, cliRead(t, p))
		}
	}

	cliNeedSSH(t)
	for _, host := range []string{"anyhost", "web-1.example"} {
		if got := cliSSHVal(t, e.main, host, "hostname"); got != host {
			t.Errorf("ssh -G %s: hostname %q, want %q", host, got, host)
		}
	}
	stdout, stderr, err = runCLI(t, "list")
	if err != nil || strings.TrimSpace(stdout) != "" {
		t.Errorf("list: err %v, stdout %q, want exit 0 and nothing printed (stderr %q)", err, stdout, stderr)
	}
	_, stderr, err = runCLI(t, "validate")
	if err != nil {
		t.Errorf("validate: %v", err)
	}
	for _, l := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(l, "error") {
			t.Errorf("validate reports an error: %s", l)
		}
	}
}

// I3 + I4: the second `init` on that machine is the normal set-up init: it adds
// the default Host * block at the end of the main file; the third finds it and
// writes nothing, with the existing note (clarification 9).
func TestInitFreshCLI_SecondAndThirdRun(t *testing.T) {
	cliNeedSSH(t)
	e := frNew(t)
	if _, stderr, err := runCLI(t, "init"); err != nil {
		t.Fatalf("first init: %v\n%s", err, stderr)
	}

	_, stderr, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("second init: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "Host * defaults block written to "+e.main) {
		t.Errorf("second init stderr lacks the 'written' line:\n%s", stderr)
	}
	if strings.Contains(stderr, "created an empty") || strings.Contains(stderr, "hint:") {
		t.Errorf("second init printed the fresh-machine line or a hint:\n%s", stderr)
	}
	body := cliRead(t, e.main)
	lines := strings.Split(body, "\n")
	if lines[0] != "Include "+e.managed || strings.Count(body, "Host *") != 1 {
		t.Errorf("main file after the second init:\n%s", body)
	}
	if i := strings.Index(body, "Host *\n"); i < len("Include ") {
		t.Errorf("Host * is not after the Include line:\n%s", body)
	}
	if got := cliRead(t, e.managed); got != cliManagedHeader {
		t.Errorf("managed file changed: %q", got)
	}
	if got := cliSSHVal(t, e.main, "anyhost", "serveraliveinterval"); got != "60" {
		t.Errorf("ssh -G anyhost: serveraliveinterval %q, want 60", got)
	}

	before := cliRead(t, e.main)
	_, stderr, err = runCLI(t, "init")
	if err != nil {
		t.Fatalf("third init: %v", err)
	}
	line := cliLineOf(t, before, "Host *")
	wantNote := "note: Host * is already defined at " + e.main + ":" + itoa(line) + "; sshm does not rewrite it (edit it by hand to change the defaults)\n"
	if stderr != wantNote {
		t.Errorf("third init stderr = %q, want %q", stderr, wantNote)
	}
	if cliRead(t, e.main) != before {
		t.Error("third init changed the main file")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// I3 + clarification 8: `init` on a main file that exists but is not set up
// (hosts, zero bytes, comments only) is refused and changes nothing, no
// directory included.
func TestInitFreshCLI_ExistingMainFileIsRefused(t *testing.T) {
	for name, mainBody := range map[string]string{
		"main file with hosts": nsNotSetUpMain,
		"zero-byte main file":  "",
		"comment-only main":    "# nothing here yet\n",
		"conditional Include":  "Host cond\n  Include @M@\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := nsNew(t, mainBody, cliAbsent)
			before := nsSnap(t, e.dir)
			stdout, stderr, err := runCLI(t, "init")
			nsRequireRefused(t, stdout, stderr, err)
			nsRequireSame(t, before, nsSnap(t, e.dir))
		})
	}
}

// I3, clarification 9 (characterization, green now): on a set-up config `init`
// adds the Host * block at the end of the main file; run again it prints the
// 'already defined' note; no setup hint either time.
func TestInitCLI_SetUpConfigAddsHostStarOnce(t *testing.T) {
	cliNeedSSH(t)
	e := nsNew(t, "Include @M@\n\nHost web-9\n  HostName 10.0.0.9\n", cliManagedHeader)
	_, stderr, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "Host * defaults block written to "+e.main) || strings.Contains(stderr, "hint:") {
		t.Errorf("stderr = %q, want the 'written' line and no hint", stderr)
	}
	body := cliRead(t, e.main)
	if !strings.HasSuffix(strings.TrimRight(body, "\n"), "ServerAliveInterval 60") || strings.Count(body, "Host *") != 1 {
		t.Errorf("main file after init:\n%s", body)
	}
	if i, j := strings.Index(body, "Host web-9"), strings.Index(body, "Host *"); i < 0 || j < i {
		t.Errorf("Host * must come after the specific host:\n%s", body)
	}
	_, stderr, err = runCLI(t, "init")
	line := cliLineOf(t, body, "Host *")
	want := "note: Host * is already defined at " + e.main + ":" + itoa(line) + "; sshm does not rewrite it (edit it by hand to change the defaults)\n"
	if err != nil || stderr != want {
		t.Errorf("second init: err %v, stderr %q, want %q", err, stderr, want)
	}
}

// I4: a failure inside the fresh setup leaves the previous state (nothing) or a
// complete set-up state. Here ssh rejects the new config (a fake ssh that always
// fails), so the verification step fails.
func TestInitFreshCLI_FailureLeavesPreviousOrCompleteState(t *testing.T) {
	e := frNew(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\necho 'fake ssh: refusing' >&2\nexit 255\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, stderr, err := runCLI(t, "init")
	if err == nil {
		t.Fatalf("init succeeded although ssh rejects the result; stderr: %s", stderr)
	}
	if strings.Contains(err.Error(), "read config: open") {
		t.Fatalf("init failed on reading the missing config, not inside the setup: %v", err)
	}
	if _, serr := os.Stat(e.main); serr == nil {
		frRequireSetUpState(t, e, cliManagedHeader) // complete state
		return
	}
	for _, p := range []string{e.managed, filepath.Dir(e.managed), e.sshDir} {
		if _, serr := os.Stat(p); serr == nil {
			t.Errorf("partial state: %s exists although the main file does not", p)
		}
	}
}
