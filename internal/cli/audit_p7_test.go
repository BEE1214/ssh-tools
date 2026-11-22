package cli

// Mutation-audit tests for P7 (black box, real binary + wrapper ssh from
// interrupt_test.go, temp dirs only).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

// R1: the exit status of the process (exitCode, root.go): 1 for every error,
// 128 plus the signal number after an interrupted save, also when the
// *InterruptedError is wrapped.
func TestAuditP7_ExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"plain error", errors.New("boom"), 1},
		{"not set up", app.ErrNotSetUp, 1},
		{"interrupted without a signal", &app.InterruptedError{File: "f", Restored: true}, 1},
		{"SIGINT", &app.InterruptedError{File: "f", Restored: true, Signal: syscall.SIGINT}, 130},
		{"SIGTERM", &app.InterruptedError{File: "f", Restored: true, Signal: syscall.SIGTERM}, 143},
		{"SIGHUP", &app.InterruptedError{File: "f", Signal: syscall.SIGHUP}, 129},
		{"wrapped", fmt.Errorf("save: %w", &app.InterruptedError{File: "f", Restored: true, Signal: syscall.SIGTERM}), 143},
	}
	for _, c := range cases {
		if got := exitCode(c.err); got != c.want {
			t.Errorf("exitCode(%s) = %d, want %d", c.name, got, c.want)
		}
	}
}

// R1 for `import`: when one of the two files cannot be restored (changed by
// somebody else during the verification) the message says so; it must not claim
// `restored`.
func TestAuditP7_InterruptedImportWithOneFileNotRestorable(t *testing.T) {
	rig := irNewRig(t)
	e := nsNew(t, "Include @M@\n\nHost moved-1\n  HostName 10.0.0.5\n", cliManagedHeader)
	preMain := cliRead(t, e.main)
	run := rig.start(t, e.main, e.managed, `^Host moved-1`, "import", "--apply")
	run.waitReady(t)
	const other = "# somebody else wrote this file during the import\n"
	if err := os.WriteFile(e.managed, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	exit, signaled, _ := run.finish(t, 30*time.Second)
	stderr := irRead(t, run.stderr)
	if signaled || exit != 128+int(syscall.SIGTERM) {
		t.Errorf("exit %d signaled %v, want 143\nstderr: %s", exit, signaled, stderr)
	}
	if !regexp.MustCompile(`interrupted: could not restore \S+`).MatchString(stderr) {
		t.Errorf("stderr lacks `interrupted: could not restore <file>`:\n%s", stderr)
	}
	if regexp.MustCompile(`interrupted: \S+ restored`).MatchString(stderr) {
		t.Errorf("stderr claims a full restore:\n%s", stderr)
	}
	if got := cliRead(t, e.managed); got != other {
		t.Errorf("the other party's managed file was overwritten:\n%s", got)
	}
	if got := cliRead(t, e.main); got != preMain {
		t.Errorf("the main file was not restored:\n%s", got)
	}
}

// The notes of setup (here: ssh is not available, so nothing is verified) are
// printed on stderr, like the action lines; `init` on a fresh machine prints the
// same.
func TestAuditP7_SetupAndFreshInitPrintNotesOnStderr(t *testing.T) {
	for _, cmd := range []string{"setup", "init"} {
		t.Run(cmd, func(t *testing.T) {
			e := frNew(t)
			nsEmptyPath(t)
			stdout, stderr, err := runCLI(t, cmd)
			if err != nil {
				t.Fatalf("%s: %v\n%s", cmd, err, stderr)
			}
			if !strings.Contains(stderr, "note: verification skipped: ssh not found in PATH\n") {
				t.Errorf("stderr lacks the verification note:\n%s", stderr)
			}
			if strings.Contains(stdout, "note:") || strings.Contains(stdout, "verification") {
				t.Errorf("the note is on stdout:\n%s", stdout)
			}
			if got := cliRead(t, e.main); got != "Include "+e.managed+"\n" {
				t.Errorf("main file = %q", got)
			}
		})
	}
}

// The line printed after init added the Host * block names the main file (the
// file that got the block), as a whole line.
func TestAuditP7_InitWrittenLineNamesMainFile(t *testing.T) {
	cliNeedSSH(t)
	e := frNew(t)
	if _, stderr, err := runCLI(t, "init"); err != nil {
		t.Fatalf("first init: %v\n%s", err, stderr)
	}
	_, stderr, err := runCLI(t, "init")
	if err != nil {
		t.Fatalf("second init: %v\n%s", err, stderr)
	}
	want := "Host * defaults block written to " + e.main + "\n"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr lacks the whole line %q:\n%s", want, stderr)
	}
}

// A command that fails (no interrupt) exits with status 1 through the real binary.
func TestAuditP7_FailedCommandExitsWithOne(t *testing.T) {
	rig := irNewRig(t)
	e := nsNotSetUp(t)
	run := rig.start(t, e.main, "", "", "add", "--name", "x-1", "--hostname", "10.0.0.1")
	exit, signaled, _ := run.finish(t, 30*time.Second)
	if signaled || exit != 1 {
		t.Errorf("exit %d signaled %v, want exit status 1\nstderr: %s", exit, signaled, irRead(t, run.stderr))
	}
}

// I4 + R1: a signal during the verification of `init` on a fresh machine leaves
// the previous state (nothing created), and the next `init` starts from scratch.
func TestAuditP7_InterruptedFreshInitLeavesNothingBehind(t *testing.T) {
	rig := irNewRig(t)
	for _, sig := range auditSigs() {
		t.Run(sig.String(), func(t *testing.T) {
			base := t.TempDir()
			sshDir := filepath.Join(base, "ssh")
			main := filepath.Join(sshDir, "config")
			run := rig.start(t, main, main, `^Include .*sshm\.conf`, "init")
			run.waitReady(t)
			if err := run.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			exit, signaled, _ := run.finish(t, 30*time.Second)
			stderr := irRead(t, run.stderr)
			if signaled || exit != 128+int(sig) {
				t.Errorf("exit %d signaled %v, want %d\nstderr: %s", exit, signaled, 128+int(sig), stderr)
			}
			if !regexp.MustCompile(`interrupted: \S+ restored`).MatchString(stderr) {
				t.Errorf("stderr lacks `interrupted: <file> restored`:\n%s", stderr)
			}
			if strings.Contains(stderr, "created an empty") {
				t.Errorf("the closing line of a finished init was printed:\n%s", stderr)
			}
			ents, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			if len(ents) != 0 {
				var names []string
				for _, e := range ents {
					names = append(names, e.Name())
				}
				t.Errorf("the fresh machine is not back to nothing: %v left in %s", names, base)
			}
			next := rig.start(t, main, "", "", "init")
			if exit, signaled, _ := next.finish(t, 60*time.Second); exit != 0 || signaled {
				t.Errorf("the next init failed (exit %d)\nstderr: %s", exit, irRead(t, next.stderr))
			}
			if got := cliRead(t, main); got != "Include "+filepath.Join(sshDir, "config.d", "sshm.conf")+"\n" {
				t.Errorf("main file after the next init:\n%s", got)
			}
		})
	}
}

func auditSigs() []syscall.Signal {
	return []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
}

// R1: the exit status after an interrupted save is 128 plus the signal number
// (the CLI contract in root.go), not just "non-zero".
func TestAuditP7_InterruptedSaveExitsWith128PlusSignal(t *testing.T) {
	rig := irNewRig(t)
	for _, sig := range auditSigs() {
		t.Run(sig.String(), func(t *testing.T) {
			e := nsNew(t, nsSetUpMain, nsSetUpManaged)
			run := rig.start(t, e.main, e.managed, `^Host audit-1`, "add", "--name", "audit-1", "--hostname", "10.9.9.9")
			run.waitReady(t)
			if err := run.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			exit, signaled, got := run.finish(t, 30*time.Second)
			if signaled {
				t.Fatalf("killed by %v, want a handled interrupt", got)
			}
			if want := 128 + int(sig); exit != want {
				t.Errorf("exit status %d after %v, want %d\nstderr: %s", exit, sig, want, irRead(t, run.stderr))
			}
		})
	}
}

// R1: when the restore cannot be done (somebody else changed the file during
// the verification) the message is `interrupted: could not restore <file>;
// backup: <path>`, the file is left as the other party made it, and the backup
// holds the pre-write bytes.
func TestAuditP7_InterruptWithFailedRestoreNamesBackup(t *testing.T) {
	rig := irNewRig(t)
	e := nsNew(t, nsSetUpMain, nsSetUpManaged)
	pre := cliRead(t, e.managed)
	run := rig.start(t, e.main, e.managed, `^Host audit-2`, "add", "--name", "audit-2", "--hostname", "10.9.9.8")
	run.waitReady(t)
	other := pre + "# written by hand during the save\n"
	if err := os.WriteFile(e.managed, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run.cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	exit, signaled, _ := run.finish(t, 30*time.Second)
	stderr := irRead(t, run.stderr)
	if signaled || exit != 128+int(syscall.SIGINT) {
		t.Errorf("exit %d signaled %v, want exit 130\nstderr: %s", exit, signaled, stderr)
	}
	m := regexp.MustCompile(`interrupted: could not restore (\S+); backup: (\S+)`).FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("stderr lacks `interrupted: could not restore <file>; backup: <path>`:\n%s", stderr)
	}
	if filepath.Base(m[1]) != "sshm.conf" {
		t.Errorf("message names %q, want the managed file", m[1])
	}
	if strings.Contains(stderr, "restored") && !strings.Contains(stderr, "not restored") && regexp.MustCompile(`interrupted: \S+ restored`).MatchString(stderr) {
		t.Errorf("the message claims a restore that did not happen:\n%s", stderr)
	}
	b, err := os.ReadFile(m[2])
	if err != nil {
		t.Fatalf("the named backup %s is not readable: %v", m[2], err)
	}
	if string(b) != pre {
		t.Errorf("the named backup does not hold the pre-write bytes:\n%s", b)
	}
	if got := cliRead(t, e.managed); got != other {
		t.Errorf("the other party's content was overwritten:\n%s", got)
	}
}

// R1 for a save of the MAIN file (init appends the Host * block there): a
// signal during its verification restores the main file too.
func TestAuditP7_InterruptDuringInitRestoresMainFile(t *testing.T) {
	rig := irNewRig(t)
	for _, sig := range auditSigs() {
		t.Run(sig.String(), func(t *testing.T) {
			e := nsNew(t, "Include @M@\n", nsSetUpManaged)
			pre := cliRead(t, e.main)
			wantG := irSSHG(t, e.main, "web-1")
			run := rig.start(t, e.main, e.main, `^Host \*`, "init")
			run.waitReady(t)
			if err := run.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			exit, signaled, got := run.finish(t, 30*time.Second)
			stderr := irRead(t, run.stderr)
			if signaled || exit != 128+int(sig) {
				t.Errorf("exit %d signaled %v (%v), want %d\nstderr: %s", exit, signaled, got, 128+int(sig), stderr)
			}
			m := regexp.MustCompile(`interrupted: (\S+) restored`).FindStringSubmatch(stderr)
			if m == nil || filepath.Base(m[1]) != "config" {
				t.Errorf("stderr lacks `interrupted: <main file> restored`:\n%s", stderr)
			}
			if got := cliRead(t, e.main); got != pre {
				t.Errorf("the main file is not restored:\n%s", got)
			}
			if gotG := irSSHG(t, e.main, "web-1"); gotG != wantG {
				t.Errorf("ssh -G web-1 differs after the interrupt:\n%s", irLineDiff(wantG, gotG))
			}
			next := rig.start(t, e.main, "", "", "init")
			if exit, signaled, _ := next.finish(t, 60*time.Second); exit != 0 || signaled {
				t.Errorf("the next init failed (exit %d): a lock is left\nstderr: %s", exit, irRead(t, next.stderr))
			}
			if !strings.Contains(cliRead(t, e.main), "Host *") {
				t.Errorf("the next init did not add Host *:\n%s", cliRead(t, e.main))
			}
		})
	}
}
