package app

// Helpers of the P7 mutation-audit tests: signal scenarios run in a re-executed
// copy of the test binary, because a signal sent to the real test process would
// reach every other test that has an interrupt window open (many tests run in
// parallel) and, outside a window, kill the whole run.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const auditCaseEnv = "AUDIT_P7_CASE"

// auditRun is the outcome of one helper process.
type auditRun struct {
	exit     int
	signaled bool
	sig      syscall.Signal
	out      string
}

func (r auditRun) has(s string) bool { return strings.Contains(r.out, s) }

// auditHelper runs scenario `name` of TestAuditP7_Helper in a child process.
func auditHelper(t *testing.T, name string, env ...string) auditRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAuditP7_Helper$", "-test.count=1")
	cmd.Env = append(os.Environ(), auditCaseEnv+"="+name)
	cmd.Env = append(cmd.Env, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	r := auditRun{out: out.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		ws := ee.Sys().(syscall.WaitStatus)
		r.exit, r.signaled = ee.ExitCode(), ws.Signaled()
		if ws.Signaled() {
			r.sig = ws.Signal()
		}
	} else if err != nil {
		t.Fatalf("helper %s: %v\n%s", name, err, out.String())
	}
	return r
}

// auditWaitFired waits (up to 3s) until a signal has been recorded by the
// window of a.
func auditWaitFired(a *App) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		a.winMu.Lock()
		w := a.win
		a.winMu.Unlock()
		if w.fired() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// auditSelfSignal sends sig to the (helper) process itself.
func auditSelfSignal(sig syscall.Signal) { syscall.Kill(os.Getpid(), sig) }
