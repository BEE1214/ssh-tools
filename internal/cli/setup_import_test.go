package cli

// CLI tests for `sshm setup`, `sshm import` and the legacy-mode hint line
// (PLAN-p3-p4.md sections 3-5, R14). They run the real root command; an error
// returned from Execute is exit status 1. None of these tests is parallel (they
// redirect the process streams and set environment variables).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

const cliSetupMain = "# my ssh config\nHost web-1\n  HostName 10.0.0.1\n  User alice\n\nHost *\n  User fallback\n"

// ---- setup ---------------------------------------------------------------------------

func TestSetupCmd_PrintsOneLinePerAction(t *testing.T) {
	e := newCLIEnv(t, cliSetupMain, cliAbsent)
	_, stderr, err := runCLI(t, "setup")
	if err != nil {
		t.Fatalf("setup failed: %v\nstderr:\n%s", err, stderr)
	}
	want := []string{
		"create " + filepath.Dir(e.managed) + " (0700)",
		"create " + e.managed + " (0600)",
		"insert Include line at line 1 of " + e.main,
	}
	if got := cliLines(stderr); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("stderr lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := e.readMain(t); got != "Include "+e.managed+"\n"+cliSetupMain {
		t.Errorf("main file:\n%s", got)
	}
	if fi, err := os.Stat(e.managed); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("managed file: %v %v", fi, err)
	}
}

func TestSetupCmd_DryRunPrefixesWouldAndChangesNothing(t *testing.T) {
	e := newCLIEnv(t, cliSetupMain, cliAbsent)
	before := cliSnap(t, e.dir)
	_, stderr, err := runCLI(t, "setup", "--dry-run")
	if err != nil {
		t.Fatalf("setup --dry-run failed: %v\nstderr:\n%s", err, stderr)
	}
	want := []string{
		"would create " + filepath.Dir(e.managed) + " (0700)",
		"would create " + e.managed + " (0600)",
		"would insert Include line at line 1 of " + e.main,
	}
	if got := cliLines(stderr); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("stderr lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
}

func TestSetupCmd_SecondRunSaysAlreadySetUp(t *testing.T) {
	e := newCLIEnv(t, cliSetupMain, cliAbsent)
	if _, stderr, err := runCLI(t, "setup"); err != nil {
		t.Fatalf("first setup failed: %v\n%s", err, stderr)
	}
	for _, p := range []string{e.main, e.managed} {
		if err := os.Chtimes(p, cliPast, cliPast); err != nil {
			t.Fatal(err)
		}
	}
	before := cliSnap(t, e.dir)
	_, stderr, err := runCLI(t, "setup")
	if err != nil {
		t.Fatalf("second setup failed: %v\n%s", err, stderr)
	}
	want := "already set up: " + e.managed + " is included from " + e.main
	if got := cliLines(stderr); len(got) != 1 || got[0] != want {
		t.Errorf("stderr lines = %q, want exactly %q", got, want)
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
}

func TestSetupCmd_ConditionalIncludeExitsWithAnError(t *testing.T) {
	e := newCLIEnv(t, "Host web-1\n  HostName 10.0.0.1\nInclude @M@\n", cliManagedHeader+"Host keep-1\n  HostName 10.0.0.60\n")
	before := cliSnap(t, e.dir)
	_, _, err := runCLI(t, "setup")
	if err == nil || errors.Is(err, app.ErrNotImplemented) {
		t.Fatalf("err = %v, want a refusal (exit 1)", err)
	}
	if !strings.Contains(err.Error(), "above the first Host/Match") {
		t.Errorf("error %q does not say to move the Include above the first Host/Match", err)
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
}

// Characterization: the command shapes the skeleton already fixes.
func TestSetupAndImportCmd_ArgsAndFlagsAreRegistered(t *testing.T) {
	newCLIEnv(t, cliSetupMain, cliAbsent)
	if _, _, err := runCLI(t, "setup", "extra"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("setup extra: err = %v, want an unknown-command error (no positional args)", err)
	}
	if _, _, err := runCLI(t, "import", "extra"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("import extra: err = %v, want an unknown-command error (no positional args)", err)
	}
	for _, args := range [][]string{{"setup", "--bogus"}, {"import", "--bogus"}, {"setup", "--apply"}, {"import", "--dry-run"}} {
		if _, _, err := runCLI(t, args...); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%v: err = %v, want an unknown-flag error", args, err)
		}
	}
	for _, args := range [][]string{{"setup", "--dry-run"}, {"import", "--apply"}, {"import", "--force"}} {
		if _, _, err := runCLI(t, args...); err != nil && (strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), "unknown command")) {
			t.Errorf("%v: flag not registered: %v", args, err)
		}
	}
}

// ---- import ---------------------------------------------------------------------------

const cliImportMain = `Include @M@

# global note about this file

# web servers
Host web-1
  HostName 10.0.0.1
  User alice
  # inner comment
  Port 2222

Host *-staging
  User stage

# group: infra
# database primary
Host db-1
    HostName 10.0.0.3

Host a b
  User multi

# DevPod Start demo
Host demo
  HostName localhost
# DevPod End demo

Match host matched.example.com
  User matchuser

Host solo
	HostName 10.0.0.4
	user tabby

Host *
  ServerAliveInterval 30
`

func TestImportCmd_DryRunPrintsThePlan(t *testing.T) {
	e := newCLIEnv(t, cliImportMain, cliManagedHeader)
	orig := e.readMain(t)
	before := cliSnap(t, e.dir)
	stdout, stderr, err := runCLI(t, "import")
	if err != nil {
		t.Fatalf("import failed: %v\nstderr:\n%s", err, stderr)
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))

	var got []string
	for _, l := range cliLines(stdout) {
		got = append(got, cliNorm(l))
	}
	span := func(from, to string) string {
		return fmt.Sprintf("%d-%d", cliLineOf(t, orig, from), cliLineOf(t, orig, to))
	}
	line := func(h string) int { return cliLineOf(t, orig, h) }
	wantHead := []string{
		fmt.Sprintf("would move 3 blocks from %s to %s:", e.main, e.managed),
		"web-1 lines " + span("# web servers", "  Port 2222"),
		"db-1 lines " + span("# group: infra", "    HostName 10.0.0.3"),
		"solo lines " + span("Host solo", "\tuser tabby"),
		"staying in " + e.main + ":",
	}
	if len(got) < len(wantHead)+1 || strings.Join(got[:len(wantHead)], "\n") != strings.Join(wantHead, "\n") {
		t.Fatalf("stdout:\n%s\nwant it to start with:\n%s", stdout, strings.Join(wantHead, "\n"))
	}
	if last := got[len(got)-1]; last != "run 'sshm import --apply' to perform the move" {
		t.Errorf("last line = %q", last)
	}
	stays := got[len(wantHead) : len(got)-1]
	wantStays := []string{
		fmt.Sprintf("*-staging line %d wildcard or pattern", line("Host *-staging")),
		fmt.Sprintf("demo line %d DevPod block", line("Host demo")),
		fmt.Sprintf("* line %d wildcard or pattern", line("Host *")),
	}
	for _, w := range wantStays {
		found := false
		for _, s := range stays {
			found = found || s == w
		}
		if !found {
			t.Errorf("staying section lacks %q:\n%s", w, strings.Join(stays, "\n"))
		}
	}
	// Names of a multi-pattern line and of a Match block are not fixed; line and reason are.
	for _, w := range []struct{ header, tail string }{
		{"Host a b", fmt.Sprintf("line %d multiple patterns", line("Host a b"))},
		{"Match host matched.example.com", fmt.Sprintf("line %d Match block", line("Match host matched.example.com"))},
	} {
		found := false
		for _, s := range stays {
			found = found || strings.HasSuffix(s, w.tail)
		}
		if !found {
			t.Errorf("staying section lacks an entry ending in %q:\n%s", w.tail, strings.Join(stays, "\n"))
		}
	}
	if len(stays) != 5 {
		t.Errorf("staying section has %d entries, want 5:\n%s", len(stays), strings.Join(stays, "\n"))
	}
	// Only disabled blocks show their group.
	for _, l := range got[1:4] {
		if strings.Contains(l, "group") || strings.Contains(l, "disabled") {
			t.Errorf("enabled block shows group/disabled info: %q", l)
		}
	}
}

func TestImportCmd_DryRunShowsGroupOfDisabledBlocksOnly(t *testing.T) {
	e := newCLIEnv(t, "Host web-1\n  HostName 10.0.0.1\n\nHost deploy-acq\n  HostName 192.168.1.10\n\nHost deploy-eu\n  HostName 192.168.1.11\n\nHost misc\n  HostName 10.0.0.9\n", cliAbsent)
	if _, stderr, err := runCLI(t, "groups", "disable", "deploy"); err != nil {
		t.Fatalf("groups disable (legacy mode) failed: %v\n%s", err, stderr)
	}
	e.write(t, e.main, "Include @M@\n"+e.readMain(t))
	e.write(t, e.managed, cliManagedHeader)
	before := cliSnap(t, e.dir)
	stdout, _, err := runCLI(t, "import")
	if err != nil {
		t.Fatal(err)
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
	var lines []string
	for _, l := range cliLines(stdout) {
		lines = append(lines, cliNorm(l))
	}
	has := func(re string) bool {
		for _, l := range lines {
			if regexp.MustCompile(re).MatchString(l) {
				return true
			}
		}
		return false
	}
	for _, re := range []string{
		`^deploy-acq lines \d+-\d+ \(disabled, group deploy\)$`,
		`^deploy-eu lines \d+-\d+ \(disabled, group deploy\)$`,
		`^web-1 lines \d+-\d+$`,
		`^misc lines \d+-\d+$`,
		`^would move 4 blocks from `,
	} {
		if !has(re) {
			t.Errorf("no output line matches %s:\n%s", re, stdout)
		}
	}
}

func TestImportCmd_ApplyReportsAndMoves(t *testing.T) {
	cliNeedSSH(t)
	e := newCLIEnv(t, cliImportMain, cliManagedHeader)
	stdout, stderr, err := runCLI(t, "import", "--apply")
	if err != nil {
		t.Fatalf("import --apply failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	const done = "moved 3 blocks; ssh resolves every host identically"
	found := false
	for _, l := range cliLines(stdout + "\n" + stderr) {
		found = found || l == done
	}
	if !found {
		t.Errorf("no line %q in the output:\n%s\n%s", done, stdout, stderr)
	}
	for _, h := range []string{"Host web-1", "Host db-1", "Host solo"} {
		if strings.Contains(e.readMain(t), h) || !strings.Contains(e.readManaged(t), h) {
			t.Errorf("%q was not moved from the main file to the managed file", h)
		}
	}
	if got := cliSSHVal(t, e.main, "web-1", "user"); got != "alice" {
		t.Errorf("ssh -G web-1 user = %q", got)
	}
}

func TestImportCmd_NothingToImport(t *testing.T) {
	cliNeedSSH(t)
	e := newCLIEnv(t, cliImportMain, cliManagedHeader)
	if _, stderr, err := runCLI(t, "import", "--apply"); err != nil {
		t.Fatalf("first import failed: %v\n%s", err, stderr)
	}
	for _, p := range []string{e.main, e.managed} {
		if err := os.Chtimes(p, cliPast, cliPast); err != nil {
			t.Fatal(err)
		}
	}
	before := cliSnap(t, e.dir)
	for _, args := range [][]string{{"import"}, {"import", "--apply"}} {
		stdout, stderr, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("%v failed: %v\n%s", args, err, stderr)
		}
		found := false
		for _, l := range cliLines(stdout + "\n" + stderr) {
			found = found || strings.TrimSpace(l) == "nothing to import"
		}
		if !found {
			t.Errorf("%v: no 'nothing to import' line:\n%s\n%s", args, stdout, stderr)
		}
		cliRequireUnchanged(t, before, cliSnap(t, e.dir))
	}
}

func TestImportCmd_NotSetUpIsAnErrorWithTheFixedMessage(t *testing.T) {
	e := newCLIEnv(t, strings.TrimPrefix(cliImportMain, "Include @M@\n\n"), cliAbsent)
	before := cliSnap(t, e.dir)
	for _, args := range [][]string{{"import"}, {"import", "--apply"}} {
		_, _, err := runCLI(t, args...)
		if err == nil || err.Error() != "sshm is not set up: run 'sshm setup' first" {
			t.Errorf("%v: err = %v, want the fixed not-set-up message", args, err)
		}
		cliRequireUnchanged(t, before, cliSnap(t, e.dir))
	}
}

const cliShadowMain = `Include @M@

Host pat-*
  ProxyJump none

Host *
  User fallback
  ProxyJump jump.example.com

Host web-1
  HostName 10.0.0.1
  User mainuser

Host proxy-1
  HostName 10.0.0.2
  ProxyJump none

Host pat-1
  HostName 10.0.0.3
  ProxyJump hop.example.com
`

var cliShadowDiff = []string{
	"web-1: -user fallback",
	"web-1: +user mainuser",
	"proxy-1: -proxyjump jump.example.com",
	"pat-1: +proxyjump hop.example.com",
}

func TestImportCmd_DifferenceExitsWithErrorPrintsDiffAndRestores(t *testing.T) {
	cliNeedSSH(t)
	e := newCLIEnv(t, cliShadowMain, cliManagedHeader)
	origMain, origManaged := e.readMain(t), e.readManaged(t)
	stdout, stderr, err := runCLI(t, "import", "--apply")
	if !errors.Is(err, app.ErrNotEquivalent) {
		t.Fatalf("err = %v, want ErrNotEquivalent (exit 1)", err)
	}
	out := cliLines(stdout + "\n" + stderr)
	for _, d := range cliShadowDiff {
		found := false
		for _, l := range out {
			found = found || strings.TrimSpace(l) == d
		}
		if !found {
			t.Errorf("output lacks the diff line %q:\n%s\n%s", d, stdout, stderr)
		}
	}
	cliRequireBytes(t, e.main, origMain)
	cliRequireBytes(t, e.managed, origManaged)
}

func TestImportCmd_ForceKeepsTheMoveAndPrintsTheDiff(t *testing.T) {
	cliNeedSSH(t)
	e := newCLIEnv(t, cliShadowMain, cliManagedHeader)
	stdout, stderr, err := runCLI(t, "import", "--apply", "--force")
	if err != nil {
		t.Fatalf("import --apply --force failed: %v\n%s", err, stderr)
	}
	out := cliLines(stdout + "\n" + stderr)
	for _, d := range cliShadowDiff {
		found := false
		for _, l := range out {
			found = found || strings.TrimSpace(l) == d
		}
		if !found {
			t.Errorf("output lacks the diff line %q:\n%s\n%s", d, stdout, stderr)
		}
	}
	if strings.Contains(e.readMain(t), "Host web-1") || !strings.Contains(e.readManaged(t), "Host web-1") {
		t.Error("--force did not keep the move")
	}
}

func TestImportCmd_ConflictListsTheNames(t *testing.T) {
	e := newCLIEnv(t, cliImportMain, cliManagedHeader+"\nHost web-1\n  HostName 10.0.0.77\n")
	before := cliSnap(t, e.dir)
	stdout, stderr, err := runCLI(t, "import", "--apply", "--force")
	if !errors.Is(err, app.ErrImportConflict) {
		t.Fatalf("err = %v, want ErrImportConflict (--force does not override it)", err)
	}
	if !strings.Contains(err.Error()+stdout+stderr, "web-1") {
		t.Errorf("output does not list the conflicting host web-1:\n%v\n%s\n%s", err, stdout, stderr)
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
}

func TestImportCmd_WithoutSSHRefusesUnlessForced(t *testing.T) {
	e := newCLIEnv(t, cliImportMain, cliManagedHeader)
	t.Setenv("PATH", t.TempDir())
	before := cliSnap(t, e.dir)
	_, _, err := runCLI(t, "import", "--apply")
	if !errors.Is(err, app.ErrCannotVerify) {
		t.Fatalf("err = %v, want ErrCannotVerify", err)
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
	if _, stderr, err := runCLI(t, "import", "--apply", "--force"); err != nil {
		t.Fatalf("--force failed: %v\n%s", err, stderr)
	}
	if !strings.Contains(e.readManaged(t), "Host web-1") {
		t.Error("--force did not move the blocks")
	}
}

// ---- R14: the hint line --------------------------------------------------------------------

const cliHintHosts = `Host web-1
  HostName 10.0.0.1
  User alice
  LocalForward 8080 127.0.0.1:80

Host deploy-acq
  HostName 192.168.1.10
  User deploy

Host deploy-eu
  HostName 192.168.1.11
  User deploy

Host cert-1
  HostName 10.0.0.90
  User signer
  IdentityFile @D@/keys/k1
`

func cliHintArgs(t *testing.T, e *cliEnv) [][]string {
	t.Helper()
	cmds := [][]string{
		{"add", "--name", "hint-1", "--hostname", "10.0.0.50", "--identity", "/keys/x"},
		{"edit", "web-1", "--user", "zed"},
		{"forward", "--clear", "web-1"},
		{"groups", "disable", "deploy"},
		{"groups", "enable", "deploy"},
		{"init"},
	}
	if _, err := exec.LookPath("ssh-keygen"); err == nil {
		keys := filepath.Join(e.dir, "keys")
		if err := os.MkdirAll(keys, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"ca", "k1"} {
			if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(keys, k)).CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen: %v\n%s", err, out)
			}
		}
		cmds = append(cmds, []string{"cert", "sign", "cert-1", "--ca-key", filepath.Join(keys, "ca"), "--validity", "+1h"})
	}
	return cmds
}

func TestWriteCommands_LegacyModePrintsTheSetupHintOnce(t *testing.T) {
	e := newCLIEnv(t, cliHintHosts, cliAbsent)
	hint := "hint: run 'sshm setup' to keep sshm-managed hosts in " + e.managed
	for _, args := range cliHintArgs(t, e) {
		_, stderr, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("sshm %s failed: %v\n%s", strings.Join(args, " "), err, stderr)
		}
		lines := cliLines(stderr)
		last := ""
		if len(lines) > 0 {
			last = lines[len(lines)-1]
		}
		if n := strings.Count(stderr, "hint:"); n != 1 || last != hint {
			t.Errorf("sshm %s: want exactly one hint as the last stderr line, got %d (last line %q):\n%s",
				strings.Join(args, " "), n, last, stderr)
		}
	}
	// A failed command prints no hint.
	_, stderr, err := runCLI(t, "edit", "no-such-host", "--user", "x")
	if err == nil {
		t.Fatal("edit of a missing host succeeded")
	}
	if strings.Contains(stderr, "hint:") {
		t.Errorf("hint printed after a failure:\n%s", stderr)
	}
}

func TestWriteCommands_ManagedModeWritesToTheManagedFileWithoutAHint(t *testing.T) {
	e := newCLIEnv(t, "Include @M@\n\nHost main-only\n  HostName 10.0.0.9\n", cliManagedHeader+"\n"+cliHintHosts)
	mainBefore := e.readMain(t) // before init
	mainNow := mainBefore       // what the main file must be after each command
	for _, args := range cliHintArgs(t, e) {
		stdout, stderr, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("sshm %s failed: %v\n%s", strings.Join(args, " "), err, stderr)
		}
		if strings.Contains(stdout+stderr, "hint:") {
			t.Errorf("sshm %s printed a hint in managed mode:\n%s", strings.Join(args, " "), stderr)
		}
		if args[0] == "init" {
			mainNow = e.readMain(t) // init may append Host * to the main file, and only that
		} else {
			cliRequireBytes(t, e.main, mainNow)
		}
	}
	m := e.readManaged(t)
	for _, want := range []string{"Host hint-1", "User zed"} {
		if !strings.Contains(m, want) {
			t.Errorf("managed file lacks %q:\n%s", want, m)
		}
	}
	// init: Host * went to the end of the main file; every earlier main byte is intact.
	if got := e.readMain(t); !strings.HasPrefix(got, mainBefore) || !strings.Contains(strings.TrimPrefix(got, mainBefore), "Host *") {
		t.Errorf("init did not append Host * to the end of the main file:\n%s", got)
	}
}

func TestEditCmd_ManagedModeRefusesAHostOfTheMainFile(t *testing.T) {
	e := newCLIEnv(t, "Include @M@\n\nHost main-only\n  HostName 10.0.0.9\n  LocalForward 7000 127.0.0.1:7000\n", cliManagedHeader+"\nHost web-1\n  HostName 10.0.0.1\n")
	before := cliSnap(t, e.dir)
	want := (&app.UnmanagedHostError{Host: "main-only", File: e.main, CanImport: true}).Error()
	for _, args := range [][]string{
		{"edit", "main-only", "--user", "x"},
		{"forward", "--clear", "main-only"},
	} {
		_, _, err := runCLI(t, args...)
		if err == nil || err.Error() != want {
			t.Errorf("sshm %s: err = %v, want %q", strings.Join(args, " "), err, want)
		}
		cliRequireUnchanged(t, before, cliSnap(t, e.dir))
	}
}
