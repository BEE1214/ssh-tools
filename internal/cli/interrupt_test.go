package cli

// P7 clause R1 (PLAN-p7.md): SIGINT, SIGTERM and SIGHUP received while a verified
// save is between its first write and the end of its verification roll the
// files back like a failed verification, release the lock, exit non-zero and
// print `interrupted: <file> restored`; outside that window the default
// behaviour stays. R2 (the backup hint in the refusal) is in
// internal/app/interrupt_test.go.
//
// The tests build the real binary and run it against temp dirs. A wrapper `ssh`
// first in PATH stands in for the real one: it execs the real ssh (resolved
// before PATH is changed), except that an `ssh -G` call made while a watched
// file contains a marker line writes a ready file and sleeps. The marker only
// appears in the file once the save has written it, so the sleep is exactly the
// verification step of the save, and the test sends the signal then.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const irWrapper = `#!/bin/sh
case " $* " in
*" -G "*)
	if [ -n "$SSHM_TEST_WATCH" ] && grep -q -E "$SSHM_TEST_PATTERN" "$SSHM_TEST_WATCH" 2>/dev/null; then
		echo $$ > "$SSHM_TEST_PID"
		: > "$SSHM_TEST_READY"
		cd /
		exec sleep 30
	fi
	;;
esac
exec "$SSHM_TEST_REAL_SSH" "$@"
`

// irRig is the binary, the wrapper directory and the real ssh.
type irRig struct {
	bin, wrapDir string
}

func irNewRig(t *testing.T) *irRig {
	t.Helper()
	cliNeedSSH(t)
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go not in PATH, cannot build the binary: %v", err)
	}
	r := &irRig{bin: filepath.Join(t.TempDir(), "sshm"), wrapDir: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, goBin, "build", "-o", r.bin, "../../cmd/sshm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ../../cmd/sshm: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(r.wrapDir, "ssh"), []byte(irWrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	return r
}

// irRun is one run of the binary.
type irRun struct {
	cmd            *exec.Cmd
	stdout, stderr string // file paths
	ready, pid     string
	done           chan error
}

// irStart starts the binary with SSH_AUTH_CONFIG=main. watch/pattern arm the
// wrapper (watch "" = never sleeps).
func (r *irRig) start(t *testing.T, main, watch, pattern string, args ...string) *irRun {
	t.Helper()
	dir := t.TempDir()
	run := &irRun{
		stdout: filepath.Join(dir, "stdout"),
		stderr: filepath.Join(dir, "stderr"),
		ready:  filepath.Join(dir, "ready"),
		pid:    filepath.Join(dir, "pid"),
		done:   make(chan error, 1),
	}
	run.cmd = exec.Command(r.bin, args...)
	run.cmd.Dir = dir
	run.cmd.Env = append(os.Environ(),
		"PATH="+r.wrapDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SSH_AUTH_CONFIG="+main,
		"HOME="+t.TempDir(),
		"SSHM_TEST_REAL_SSH="+cliRealSSH,
		"SSHM_TEST_WATCH="+watch,
		"SSHM_TEST_PATTERN="+pattern,
		"SSHM_TEST_READY="+run.ready,
		"SSHM_TEST_PID="+run.pid,
	)
	// Files, not pipes: the sleeping ssh child may outlive the process and
	// would keep a pipe open, so that Wait could not return.
	so, err := os.Create(run.stdout)
	if err != nil {
		t.Fatal(err)
	}
	se, err := os.Create(run.stderr)
	if err != nil {
		t.Fatal(err)
	}
	run.cmd.Stdout, run.cmd.Stderr = so, se
	if err := run.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", r.bin, err)
	}
	so.Close()
	se.Close()
	t.Cleanup(func() {
		run.cmd.Process.Kill()
		if b, err := os.ReadFile(run.pid); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	go func() { run.done <- run.cmd.Wait() }()
	return run
}

// waitReady polls for the ready file; it fails when the process ends first.
func (run *irRun) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(run.ready); err == nil {
			return
		}
		select {
		case err := <-run.done:
			run.done <- err
			t.Fatalf("the process ended (%v) before the verification step was reached\nstderr: %s", err, irRead(t, run.stderr))
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Fatalf("the verification step was not reached within 30s\nstderr: %s", irRead(t, run.stderr))
}

// finish waits for the process to end and returns how.
func (run *irRun) finish(t *testing.T, limit time.Duration) (exit int, signaled bool, sig syscall.Signal) {
	t.Helper()
	select {
	case err := <-run.done:
		var ee *exec.ExitError
		switch {
		case err == nil:
			return 0, false, 0
		case errors.As(err, &ee):
			ws := ee.Sys().(syscall.WaitStatus)
			if ws.Signaled() {
				return -1, true, ws.Signal()
			}
			return ee.ExitCode(), false, 0
		default:
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(limit):
		run.cmd.Process.Kill()
		t.Fatalf("the process did not end within %v after the signal\nstderr: %s", limit, irRead(t, run.stderr))
	}
	return 0, false, 0
}

func irRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func irSSHG(t *testing.T, main, host string) string {
	t.Helper()
	out, err := exec.Command(cliRealSSH, "-F", main, "-G", host).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -F %s -G %s: %v\n%s", main, host, err, out)
	}
	return string(out)
}

// irBackupsWith returns the files in dir/sshm-backups named <base>.* that hold want.
func irBackupsWith(t *testing.T, dir, base, want string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, "sshm-backups"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), base+".") {
			continue
		}
		p := filepath.Join(dir, "sshm-backups", e.Name())
		if b, err := os.ReadFile(p); err == nil && string(b) == want {
			out = append(out, p)
		}
	}
	return out
}

type irScenario struct {
	name    string
	build   func(t *testing.T) *cliEnv
	args    []string
	watch   func(e *cliEnv) string
	pattern string
	host    string   // a host that resolves before the run; it must resolve identically after
	files   []string // files the save writes: names (not paths) the message may name
	// after the interrupt: the second run of args must work and leave this in
	// the managed file.
	next     []string
	nextWant string
	// what the interrupted run must have restored
	restored func(t *testing.T, e *cliEnv, pre map[string]string)
	backups  func(t *testing.T, e *cliEnv, pre map[string]string)
}

func irScenarios() []irScenario {
	return []irScenario{
		{
			name:     "managed save (sshm add)",
			build:    func(t *testing.T) *cliEnv { return nsNew(t, nsSetUpMain, nsSetUpManaged) },
			args:     []string{"add", "--name", "interrupt-probe", "--hostname", "10.9.9.9"},
			watch:    func(e *cliEnv) string { return e.managed },
			pattern:  `^Host interrupt-probe`,
			host:     "web-1",
			files:    []string{"sshm.conf"},
			next:     []string{"add", "--name", "after-1", "--hostname", "10.9.9.8"},
			nextWant: "Host after-1",
			restored: func(t *testing.T, e *cliEnv, pre map[string]string) {
				if got := cliRead(t, e.managed); got != pre[e.managed] {
					t.Errorf("the managed file is not restored:\n%s", got)
				}
			},
			backups: func(t *testing.T, e *cliEnv, pre map[string]string) {
				if len(irBackupsWith(t, e.dir, "sshm.conf", pre[e.managed])) == 0 {
					t.Errorf("no backup of the managed file with its old bytes in %s/sshm-backups", e.dir)
				}
			},
		},
		{
			name:    "setup",
			build:   func(t *testing.T) *cliEnv { return nsNew(t, "Host web-1\n  HostName 10.0.0.1\n", cliAbsent) },
			args:    []string{"setup"},
			watch:   func(e *cliEnv) string { return e.main },
			pattern: `^Include .*sshm\.conf`,
			host:    "web-1",
			files:   []string{"config", "sshm.conf"},
			next:    []string{"setup"},
			restored: func(t *testing.T, e *cliEnv, pre map[string]string) {
				if got := cliRead(t, e.main); got != pre[e.main] {
					t.Errorf("the main file is not restored:\n%s", got)
				}
				for _, p := range []string{e.managed, filepath.Dir(e.managed)} {
					if _, err := os.Stat(p); err == nil {
						t.Errorf("%s exists, want the state before setup (it did not)", p)
					}
				}
			},
			backups: func(t *testing.T, e *cliEnv, pre map[string]string) {
				if len(irBackupsWith(t, e.dir, "config", pre[e.main])) == 0 {
					t.Errorf("no backup of the main file with its old bytes in %s/sshm-backups", e.dir)
				}
			},
		},
		{
			name: "import",
			build: func(t *testing.T) *cliEnv {
				return nsNew(t, "Include @M@\n\nHost moved-1\n  HostName 10.0.0.5\n", cliManagedHeader)
			},
			args:     []string{"import", "--apply"},
			watch:    func(e *cliEnv) string { return e.managed },
			pattern:  `^Host moved-1`,
			host:     "moved-1",
			files:    []string{"config", "sshm.conf"},
			next:     []string{"import", "--apply"},
			nextWant: "Host moved-1",
			restored: func(t *testing.T, e *cliEnv, pre map[string]string) {
				for _, p := range []string{e.main, e.managed} {
					if got := cliRead(t, p); got != pre[p] {
						t.Errorf("%s is not restored:\n%s", p, got)
					}
				}
			},
			backups: func(t *testing.T, e *cliEnv, pre map[string]string) {
				if len(irBackupsWith(t, e.dir, "config", pre[e.main])) == 0 || len(irBackupsWith(t, e.dir, "sshm.conf", pre[e.managed])) == 0 {
					t.Errorf("want a backup of each file with its old bytes in %s/sshm-backups", e.dir)
				}
			},
		},
	}
}

// R1: a signal during the verification of a save rolls the save back.
func TestInterrupt_SignalDuringVerifiedSaveRollsBack(t *testing.T) {
	rig := irNewRig(t)
	for _, sc := range irScenarios() {
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
			t.Run(sc.name+"/"+sig.String(), func(t *testing.T) {
				e := sc.build(t)
				pre := map[string]string{}
				for _, p := range []string{e.main, e.managed} {
					if b, err := os.ReadFile(p); err == nil {
						pre[p] = string(b)
					}
				}
				wantG := irSSHG(t, e.main, sc.host)

				run := rig.start(t, e.main, sc.watch(e), sc.pattern, sc.args...)
				run.waitReady(t)
				if err := run.cmd.Process.Signal(sig); err != nil {
					t.Fatalf("signal: %v", err)
				}
				exit, signaled, got := run.finish(t, 30*time.Second)
				stderr := irRead(t, run.stderr)

				if signaled {
					t.Errorf("the process was killed by %v: the default behaviour, no rollback ran\nstderr: %s", got, stderr)
				} else if exit == 0 {
					t.Errorf("exit status 0 after %v, want non-zero\nstderr: %s", sig, stderr)
				}
				m := regexp.MustCompile(`interrupted: (.+) restored`).FindStringSubmatch(stderr)
				if m == nil {
					t.Errorf("stderr lacks `interrupted: <file> restored`:\n%s", stderr)
				} else if !irNames(m[1], sc.files) {
					t.Errorf("the message names %q, want a path ending in one of %v", m[1], sc.files)
				}
				sc.restored(t, e, pre)
				sc.backups(t, e, pre)
				if gotG := irSSHG(t, e.main, sc.host); gotG != wantG {
					t.Errorf("ssh -G %s resolves differently after the interrupt:\n%s", sc.host, irLineDiff(wantG, gotG))
				}

				// no stale lock: the next run of the same kind goes through
				next := rig.start(t, e.main, "", "", sc.next...)
				if exit, signaled, _ := next.finish(t, 60*time.Second); exit != 0 || signaled {
					t.Errorf("the next run failed (exit %d signaled %v): a lock or a half state is left\nstderr: %s", exit, signaled, irRead(t, next.stderr))
				}
				if sc.nextWant != "" && !strings.Contains(cliRead(t, e.managed), sc.nextWant) {
					t.Errorf("the next run did not write %q:\n%s", sc.nextWant, cliRead(t, e.managed))
				}
				if sc.name == "setup" {
					if got := cliRead(t, e.main); !strings.HasPrefix(got, "Include "+e.managed+"\n") {
						t.Errorf("after the next setup the main file is:\n%s", got)
					}
				}
			})
		}
	}
}

func irNames(got string, files []string) bool {
	for _, f := range files {
		if filepath.Base(got) == f {
			return true
		}
	}
	return false
}

func irLineDiff(a, b string) string {
	as, bs := map[string]bool{}, map[string]bool{}
	for _, l := range strings.Split(a, "\n") {
		as[l] = true
	}
	for _, l := range strings.Split(b, "\n") {
		bs[l] = true
	}
	var out []string
	for _, l := range strings.Split(a, "\n") {
		if !bs[l] {
			out = append(out, "- "+l)
		}
	}
	for _, l := range strings.Split(b, "\n") {
		if !as[l] {
			out = append(out, "+ "+l)
		}
	}
	return strings.Join(out, "\n")
}

// R1, "signals outside that window keep default behavior" (characterization,
// green now): a signal while the save is still only probing ssh (before its first
// write) kills the process the default way; nothing is written, nothing says
// `interrupted:`.
func TestInterrupt_SignalBeforeTheFirstWriteKeepsDefaultBehavior(t *testing.T) {
	rig := irNewRig(t)
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			e := nsNew(t, nsSetUpMain, nsSetUpManaged)
			pre := cliRead(t, e.managed)
			// `Host web-1` is in the managed file from the start, so the first
			// `ssh -G` of the save (the BEFORE probes) already sleeps.
			run := rig.start(t, e.main, e.managed, `^Host web-1`, "add", "--name", "early-1", "--hostname", "10.9.9.7")
			run.waitReady(t)
			if err := run.cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			exit, signaled, got := run.finish(t, 30*time.Second)
			if !signaled || got != sig {
				t.Errorf("exit %d signaled %v signal %v, want the process killed by %v (default behaviour)", exit, signaled, got, sig)
			}
			if stderr := irRead(t, run.stderr); strings.Contains(stderr, "interrupted:") {
				t.Errorf("stderr says 'interrupted:' for a signal before the first write:\n%s", stderr)
			}
			if got := cliRead(t, e.managed); got != pre {
				t.Errorf("the managed file changed:\n%s", got)
			}
			if _, err := os.Stat(filepath.Join(e.dir, "sshm-backups")); err == nil {
				t.Error("a backup was made before the first write")
			}
		})
	}
}
