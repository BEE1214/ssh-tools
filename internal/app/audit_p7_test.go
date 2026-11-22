package app

// Mutation-audit tests for P7 (PLAN-p7.md G, R1, R2, X): every test here was
// written to kill a mutant that survived the existing suite. Temp dirs only,
// absolute Include paths, real `ssh -F` as the oracle where ssh matters.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// ---- G3 / G6 ---------------------------------------------------------------

// G3: `forward --save` of a host name ssh would read as an option on a config
// that is not set up is refused by the gate, not by the host-argument check.
func TestAuditP7_RunForwardSaveGateBeforeHostArgCheck(t *testing.T) {
	e := nsNotSetUp(t)
	before := nsSnap(t, e.dir)
	err := e.a.RunForward("-oProxyCommand=true", domain.ForwardLocal, []string{"8080:localhost:80"}, true)
	nsRequireGate(t, err)
	nsRequireSame(t, before, nsSnap(t, e.dir))
}

// G6: the group read paths work on a config that is not set up.
func TestAuditP7_GroupReadsWorkWithoutSetup(t *testing.T) {
	e := nsNotSetUp(t)
	if _, err := e.a.IsGroupDisabled("p"); err != nil {
		t.Errorf("IsGroupDisabled on a config that is not set up: %v", err)
	}
	if _, err := e.a.ListGroupsState(); err != nil {
		t.Errorf("ListGroupsState on a config that is not set up: %v", err)
	}
}

// Characterization (spec section 4, item 5): on a set-up config an unknown host
// is still "nothing to clear".
func TestAuditP7_ClearCertificateFileUnknownHostOnSetUpConfigIsNil(t *testing.T) {
	e := nsSetUp(t)
	before := nsSnap(t, e.dir)
	if err := e.a.ClearCertificateFile("no-such-host"); err != nil {
		t.Errorf("ClearCertificateFile(unknown) on a set-up config = %v, want nil", err)
	}
	nsRequireSame(t, before, nsSnap(t, e.dir))
}

// ---- snapshot --------------------------------------------------------------

// On a config that is not set up the read-only reason of a host defined in
// several included files names the FIRST of them (the one ssh reads first).
func TestAuditP7_SnapshotReasonNamesFirstIncludedFile(t *testing.T) {
	e := nsNew(t, "Include @D@/a.conf\nInclude @D@/b.conf\n", mgAbsent)
	a := filepath.Join(e.dir, "a.conf")
	b := filepath.Join(e.dir, "b.conf")
	mgWrite(t, a, "Host dup-1\n  HostName 10.0.0.1\n", 0o600)
	mgWrite(t, b, "Host dup-1\n  HostName 10.0.0.2\n", 0o600)
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, h := range snap.Hosts {
		if h.Name != "dup-1" {
			continue
		}
		n++
		if !h.Included || !strings.Contains(h.ReadOnlyReason, a) || strings.Contains(h.ReadOnlyReason, b) {
			t.Errorf("entry from %s: Included=%v reason=%q, want a reason naming %s only", h.SourceFile, h.Included, h.ReadOnlyReason, a)
		}
	}
	if n != 2 {
		t.Fatalf("found %d dup-1 entries, want 2", n)
	}
}

// ---- R2 --------------------------------------------------------------------

// R2 for `init`: its refusal names the newest backup of the MAIN file (the file
// it writes), not of the managed file.
func TestAuditP7_InitRefusalNamesBackupOfMainFile(t *testing.T) {
	e := nsNew(t, "Include @M@\n", irBrokenManaged)
	irRequireBroken(t, e.main)
	irBackup(t, e.dir, "config.20240101-090000.000000")
	mainNewest := irBackup(t, e.dir, "config.20240303-090000.000000")
	irBackup(t, e.dir, "sshm.conf.20250505-090000.000000")
	_, _, err := e.a.InitDefaultsReport()
	if err == nil || !strings.Contains(err.Error(), "already broken") {
		t.Fatalf("InitDefaultsReport = %v, want the 'already broken' refusal", err)
	}
	want := "(newest backup of " + e.main + ": " + mainNewest + ")"
	if !strings.HasSuffix(err.Error(), want) {
		t.Errorf("does not end with %q:\n%s", want, err)
	}
}

// R2, import form: whichever of the two files has a backup is named; with none
// the text is unchanged.
func TestAuditP7_ImportRefusalHintWithOneBackupOnly(t *testing.T) {
	const main = "Include @M@\n\nHost imp-1\n  HostName 10.0.0.5\n  NoSuchOptionX yes\n"
	for _, c := range []struct {
		name, backup string
		file         func(e *mgEnv) string
	}{
		{"main only", "config.20240202-120000.000000", func(e *mgEnv) string { return e.main }},
		{"managed only", "sshm.conf.20240303-120000.000000", func(e *mgEnv) string { return e.managed }},
		{"none", "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := nsNew(t, main, mgManagedHeader)
			irRequireBroken(t, e.main)
			var bak string
			if c.backup != "" {
				bak = irBackup(t, e.dir, c.backup)
			}
			_, err := e.a.Import(ImportOptions{Apply: true})
			if err == nil || !strings.Contains(err.Error(), "the current ssh configuration is already broken: ") {
				t.Fatalf("Import = %v, want the 'already broken' refusal", err)
			}
			if c.file == nil {
				if strings.Contains(err.Error(), "newest backup") {
					t.Errorf("a hint although there is no backup: %v", err)
				}
				return
			}
			want := "(newest backup of " + c.file(e) + ": " + bak + ")"
			if !strings.HasSuffix(err.Error(), want) {
				t.Errorf("does not end with %q:\n%s", want, err)
			}
		})
	}
}

// R2 when the main file is a symlink: backups are named after the file the link
// points to (BackupTo follows it), and so is the lookup.
func TestAuditP7_SetupRefusalFindsBackupOfSymlinkedMain(t *testing.T) {
	e := nsNew(t, mgAbsent, mgAbsent)
	real := filepath.Join(e.dir, "dotfiles", "ssh_config")
	mgWrite(t, real, "Host web-1\n  HostName 10.0.0.1\n  NoSuchOptionX yes\n", 0o600)
	if err := os.Symlink(real, e.main); err != nil {
		t.Fatal(err)
	}
	irRequireBroken(t, e.main)
	bak := irBackup(t, e.dir, "ssh_config.20240404-120000.000000")
	_, err := e.a.Setup(SetupOptions{})
	if err == nil || !strings.Contains(err.Error(), "already broken") {
		t.Fatalf("Setup = %v, want the 'already broken' refusal", err)
	}
	want := "(newest backup of " + e.main + ": " + bak + ")"
	if !strings.HasSuffix(err.Error(), want) {
		t.Errorf("does not end with %q:\n%s", want, err)
	}
}

// ---- InterruptedError ------------------------------------------------------

func TestAuditP7_InterruptedErrorForms(t *testing.T) {
	for _, c := range []struct {
		e    *InterruptedError
		want string
	}{
		{&InterruptedError{File: "/x/sshm.conf", Restored: true}, "interrupted: /x/sshm.conf restored"},
		{&InterruptedError{File: "/x/sshm.conf", Err: errors.New("boom")}, "interrupted: could not restore /x/sshm.conf"},
		{&InterruptedError{File: "/x/sshm.conf", Backup: "/x/sshm-backups/b", Err: errors.New("boom")}, "interrupted: could not restore /x/sshm.conf; backup: /x/sshm-backups/b"},
	} {
		if got := c.e.Error(); got != c.want {
			t.Errorf("Error() = %q, want %q", got, c.want)
		}
		if !errors.Is(c.e, ErrInterrupted) {
			t.Errorf("errors.Is(%q, ErrInterrupted) = false", c.e)
		}
	}
	cause := fmt.Errorf("x: %w", ErrNotRolledBack)
	ie := &InterruptedError{File: "f", Err: cause}
	if !errors.Is(ie, ErrNotRolledBack) {
		t.Error("the restore error is not reachable through errors.Is (Unwrap)")
	}
	if errors.Is(&InterruptedError{File: "f", Restored: true}, ErrNotRolledBack) {
		t.Error("an InterruptedError without a cause matches an unrelated error")
	}
}

func TestAuditP7_InterruptedBuilder(t *testing.T) {
	e := nsSetUp(t)
	w := &interruptWindow{}
	w.sig.Store(int32(syscall.SIGTERM))
	bak := irBackup(t, e.dir, "sshm.conf.20240101-090000.000000")
	irBackup(t, e.dir, "sshm.conf.20230101-090000.000000")

	ok := e.a.interrupted(w, e.managed, nil)
	if !ok.Restored || ok.Err != nil || ok.Backup != "" || ok.File != e.managed || ok.Signal != syscall.SIGTERM {
		t.Errorf("restored: %+v, want Restored, no Err, no Backup, File=%s, Signal=SIGTERM", ok, e.managed)
	}
	if got, want := ok.Error(), "interrupted: "+e.managed+" restored"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	boom := errors.New("boom")
	bad := e.a.interrupted(w, e.managed, boom)
	if bad.Restored || bad.Err != boom || bad.Backup != bak || bad.Signal != syscall.SIGTERM {
		t.Errorf("not restored: %+v, want Err=boom, Backup=%s, Signal=SIGTERM", bad, bak)
	}
	if got, want := bad.Error(), "interrupted: could not restore "+e.managed+"; backup: "+bak; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	nobak := e.a.interrupted(w, e.main, boom) // no backup of the main file
	if nobak.Restored || nobak.Backup != "" {
		t.Errorf("no backup exists: %+v", nobak)
	}
	if got, want := nobak.Error(), "interrupted: could not restore "+e.main; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// ---- locks are released after saves of every kind -------------------------------

// auditNoGC stops the garbage collector for the test: an os.File whose unlock
// was never called is closed by its finalizer at the next collection, which
// would hide the leak.
func auditNoGC(t *testing.T) {
	t.Helper()
	old := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(old) })
}

func auditRequireLockFree(t *testing.T, file string) {
	t.Helper()
	lp, err := managedLockPath(file)
	if err != nil {
		t.Fatal(err)
	}
	// The lock belongs to an open file: a save that does not call its unlock
	// leaves that descriptor open (until a garbage collection happens to close
	// it, which would hide the leak from the check below). Look at the process's
	// descriptors right away.
	if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
		for _, e := range ents {
			if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && target == lp {
				t.Fatalf("the lock file %s is still open after the save: unlock was not called", lp)
			}
		}
	}
	unlock, err := config.LockFile(lp, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("the lock of %s is still held after the save: %v", file, err)
	}
	unlock()
}

func TestAuditP7_LockReleasedAfterMainFileSave(t *testing.T) {
	mgNeedSSH(t)
	auditNoGC(t)
	e := nsNew(t, "Include @M@\n", nsSetUpManaged)
	written, _, err := e.a.InitDefaultsReport()
	if err != nil || !written {
		t.Fatalf("InitDefaultsReport = %v, %v", written, err)
	}
	auditRequireLockFree(t, e.main)
}

func TestAuditP7_LockReleasedAfterSetup(t *testing.T) {
	mgNeedSSH(t)
	auditNoGC(t)
	e := nsNew(t, "Host web-1\n  HostName 10.0.0.1\n", mgAbsent)
	if _, err := e.a.Setup(SetupOptions{}); err != nil {
		t.Fatal(err)
	}
	auditRequireLockFree(t, e.main)
}

func TestAuditP7_LockReleasedAfterImport(t *testing.T) {
	mgNeedSSH(t)
	auditNoGC(t)
	e := nsNew(t, "Include @M@\n\nHost moved-1\n  HostName 10.0.0.5\n", mgManagedHeader)
	res, err := e.a.Import(ImportOptions{Apply: true})
	if err != nil || !res.Applied {
		t.Fatalf("Import = %+v, %v", res, err)
	}
	auditRequireLockFree(t, e.main)
	auditRequireLockFree(t, e.managed)
}

// ---- verification must not run ssh's Match exec ---------------------------------

// X: the managed content that is about to be included counts when deciding
// whether `ssh -G` may be run: a Match exec line in an existing managed file
// must not be run by the check of `setup`.
func TestAuditP7_SetupSkipsVerificationForMatchExecInManagedFile(t *testing.T) {
	mgNeedSSH(t)
	e := nsNew(t, "Host web-1\n  HostName 10.0.0.1\n", mgManagedHeader+"\nMatch exec \"touch @D@/ran\"\n  User nobody\n")
	res, err := e.a.Setup(SetupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !mgNoteHas(res.Notes, "verification skipped") {
		t.Errorf("notes %q lack 'verification skipped'", res.Notes)
	}
	if mgExists(filepath.Join(e.dir, "ran")) {
		t.Error("ssh -G ran the Match exec command of the managed file")
	}
}

// A Match exec line that is the LAST line of a loaded file is found (the file is
// split into lines without losing the last one).
func TestAuditP7_SaveSkipsVerificationForMatchExecOnLastLine(t *testing.T) {
	mgNeedSSH(t)
	e := nsNew(t, "Include @M@\n\nHost *\n  ServerAliveInterval 30\n\nMatch exec \"touch @D@/ran-last\"\n", nsSetUpManaged)
	if err := e.a.AddHost(domain.Host{Name: "last-1", HostName: "10.7.7.7"}); err != nil {
		t.Fatal(err)
	}
	if mgExists(filepath.Join(e.dir, "ran-last")) {
		t.Error("ssh -G ran the Match exec command on the last line of the main file")
	}
	if !strings.Contains(e.readManaged(t), "Host last-1") {
		t.Errorf("the host was not added:\n%s", e.readManaged(t))
	}
}

// ---- groups ----------------------------------------------------------------

const auditGroupManaged = mgManagedHeader + "\nHost web-1\n  HostName 10.0.0.1\n\nHost web-2\n  HostName 10.0.0.2\n"

// `groups enable` refuses only for DISABLED blocks outside the managed file; an
// enabled member of the group in another file does not stop it.
func TestAuditP7_EnableGroupIgnoresEnabledMembersOutsideManagedFile(t *testing.T) {
	mgNeedSSH(t)
	e := nsNew(t, "Include @M@\n", auditGroupManaged)
	if err := e.a.DisableGroup("web"); err != nil {
		t.Fatal(err)
	}
	mgWrite(t, filepath.Join(e.dir, "extra2.conf"), "Host web-9\n  HostName 10.0.0.9\n", 0o600)
	mgWrite(t, e.main, "Include "+e.managed+"\nInclude "+e.dir+"/extra2.conf\n", 0o600)
	if err := e.a.EnableGroup("web"); err != nil {
		t.Fatalf("EnableGroup = %v, want success (web-9 is enabled, in another file)", err)
	}
	if !regexp.MustCompile(`(?m)^Host web-1$`).MatchString(e.readManaged(t)) {
		t.Errorf("web-1 was not re-enabled:\n%s", e.readManaged(t))
	}
}

// A `Host *` block carrying the group comment in another file is not a member
// of the group that keeps it from being disabled.
func TestAuditP7_DisableGroupIgnoresWildcardOutsideManagedFile(t *testing.T) {
	mgNeedSSH(t)
	e := nsNew(t, "Include @M@\n\n# group: web\nHost *\n  ServerAliveInterval 30\n", auditGroupManaged)
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var star *HostEntry
	for i := range snap.Hosts {
		if snap.Hosts[i].Name == "*" {
			star = &snap.Hosts[i]
		}
	}
	if star == nil || star.Group != "web" {
		t.Fatalf("fixture: Host * does not carry group web: %+v", star)
	}
	if err := e.a.DisableGroup("web"); err != nil {
		t.Fatalf("DisableGroup = %v, want success: the wildcard is not a member", err)
	}
}

// Writes that would change a block of a disabled group are refused for duplicate
// and for clearing the certificate, as they are for edit.
func TestAuditP7_DisabledHostsRefuseDuplicateAndClearCertificate(t *testing.T) {
	mgNeedSSH(t)
	e := nsNew(t, "Include @M@\n", auditGroupManaged)
	if err := e.a.DisableGroup("web"); err != nil {
		t.Fatal(err)
	}
	before := e.readManaged(t)
	// the refusal of edit names the command that helps (ensureEditable); the
	// other writes say the same
	const hint = "sshm groups enable web"
	if err := e.a.DuplicateHost("web-1", "web-7"); err == nil || !strings.Contains(err.Error(), "disabled group") || !strings.Contains(err.Error(), hint) {
		t.Errorf("DuplicateHost of a disabled host = %v, want the disabled-group refusal naming %q", err, hint)
	}
	if err := e.a.ClearCertificateFile("web-1"); err == nil || !strings.Contains(err.Error(), "disabled group") || !strings.Contains(err.Error(), hint) {
		t.Errorf("ClearCertificateFile of a disabled host = %v, want the disabled-group refusal naming %q", err, hint)
	}
	if got := e.readManaged(t); got != before {
		t.Errorf("the managed file changed:\n%s", got)
	}
}

// ---- signal scenarios (child process) -----------------------------------------

func TestAuditP7_Interrupt_WindowRefcount(t *testing.T) {
	r := auditHelper(t, "refs")
	if r.signaled || r.exit != 0 || !r.has("RESULT first-close-keeps-window=true") ||
		!r.has("RESULT signal-seen-after-first-close=true") || !r.has("RESULT last-close-uninstalls=true") {
		t.Errorf("exit %d signaled %v (%v)\n%s", r.exit, r.signaled, r.sig, r.out)
	}
}

func TestAuditP7_Interrupt_DefaultBehaviorAfterWindowClosed(t *testing.T) {
	for _, c := range []string{"default-after-close", "default-after-save"} {
		t.Run(c, func(t *testing.T) {
			e := nsSetUp(t)
			r := auditHelper(t, c, "AUDIT_P7_MAIN="+e.main)
			if !r.signaled || r.sig != syscall.SIGINT {
				t.Errorf("exit %d signaled %v (%v), want death by SIGINT (the handler must be gone)\n%s", r.exit, r.signaled, r.sig, r.out)
			}
		})
	}
}

// A signal that came after the last check of a save that went through is
// delivered again with the default behavior; the first signal received counts.
func TestAuditP7_Interrupt_LateSignalIsRaisedAgain(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			r := auditHelper(t, "reraise", fmt.Sprintf("AUDIT_P7_SIG=%d", int(sig)))
			if !r.signaled || r.sig != sig {
				t.Errorf("exit %d signaled %v (%v), want death by %v\n%s", r.exit, r.signaled, r.sig, sig, r.out)
			}
		})
	}
	t.Run("first signal wins", func(t *testing.T) {
		r := auditHelper(t, "first-wins")
		if !r.signaled || r.sig != syscall.SIGINT {
			t.Errorf("exit %d signaled %v (%v), want death by the first signal (SIGINT)\n%s", r.exit, r.signaled, r.sig, r.out)
		}
	})
	t.Run("save failed for another reason", func(t *testing.T) {
		r := auditHelper(t, "other-error")
		if !r.signaled || r.sig != syscall.SIGINT {
			t.Errorf("exit %d signaled %v (%v), want death by SIGINT: only an *InterruptedError counts as handled\n%s", r.exit, r.signaled, r.sig, r.out)
		}
	})
	t.Run("interrupted save is not raised again", func(t *testing.T) {
		r := auditHelper(t, "handled")
		if r.signaled || r.exit != 0 || !r.has("RESULT survived=true") {
			t.Errorf("exit %d signaled %v (%v)\n%s", r.exit, r.signaled, r.sig, r.out)
		}
	})
}

// Only SIGINT, SIGTERM and SIGHUP are taken over: another signal arriving in the
// window (Go ignores SIGUSR1 by default) must not roll a save back.
func TestAuditP7_Interrupt_OtherSignalsAreNotAnInterrupt(t *testing.T) {
	r := auditHelper(t, "usr1")
	if r.signaled || r.exit != 0 || !r.has("RESULT window-saw-usr1=false") || !r.has("RESULT survived=true") {
		t.Errorf("exit %d signaled %v (%v)\n%s", r.exit, r.signaled, r.sig, r.out)
	}
}

// The signal cancels the ssh call that is running (the context of every ssh call
// of the App is the window's).
func TestAuditP7_Interrupt_SignalCancelsRunningSSHCall(t *testing.T) {
	e := nsSetUp(t)
	r := auditHelper(t, "ctx-cancel", "AUDIT_P7_MAIN="+e.main)
	if r.signaled || r.exit != 0 || !r.has("RESULT ctx-cancelled=true") {
		t.Errorf("exit %d signaled %v (%v)\n%s", r.exit, r.signaled, r.sig, r.out)
	}
}

// A signal that arrives while ssh verifies the result, and that ssh survives, is
// still an interrupt: the save is rolled back (managed save, setup, import).
func TestAuditP7_Interrupt_SignalDuringLastVerificationStillRollsBack(t *testing.T) {
	mgNeedSSH(t)
	for _, c := range []struct {
		name, main, managed string
		want                []string
	}{
		{"managed save", "Include @M@\n", nsSetUpManaged, []string{"RESULT interrupted=true", "RESULT restored=true"}},
		{"setup", "Host web-1\n  HostName 10.0.0.1\n", mgAbsent, []string{"RESULT interrupted=true", "RESULT restored=true"}},
		{"import", "Include @M@\n\nHost moved-1\n  HostName 10.0.0.5\n", mgManagedHeader, []string{"RESULT interrupted=true", "RESULT restored=true", "RESULT applied=false", "RESULT equivalent=false"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := nsNew(t, c.main, c.managed)
			r := auditHelper(t, "inflight-"+strings.Fields(c.name)[0], "AUDIT_P7_MAIN="+e.main)
			if r.signaled || r.exit != 0 {
				t.Fatalf("exit %d signaled %v (%v): the interrupted save was reported as done and the signal raised again\n%s", r.exit, r.signaled, r.sig, r.out)
			}
			for _, w := range c.want {
				if !r.has(w) {
					t.Errorf("output lacks %q:\n%s", w, r.out)
				}
			}
		})
	}
}

// TestAuditP7_Helper is the body of the child processes (not a test by itself).
func TestAuditP7_Helper(t *testing.T) {
	name := os.Getenv(auditCaseEnv)
	if name == "" {
		t.Skip("helper process of the TestAuditP7_Interrupt_* tests")
	}
	main := os.Getenv("AUDIT_P7_MAIN")
	a := NewAppWithPath(main)
	out := func(k string, v any) { fmt.Printf("RESULT %s=%v\n", k, v) }
	hasWin := func() bool { a.winMu.Lock(); defer a.winMu.Unlock(); return a.win != nil }
	sig := syscall.SIGINT
	if s := os.Getenv("AUDIT_P7_SIG"); s != "" {
		var n int
		fmt.Sscanf(s, "%d", &n)
		sig = syscall.Signal(n)
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	realRun := sshRun
	// signalOnce makes sshRun send sig to this process the first time cond holds,
	// wait until the window has seen it, and then run ssh WITHOUT the cancelled
	// context, so ssh itself succeeds.
	signalOnce := func(cond func() bool) {
		done := false
		sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
			if !done && cond() {
				done = true
				auditSelfSignal(syscall.SIGINT)
				if !auditWaitFired(a) {
					fmt.Println("RESULT window-never-saw-signal=true")
				}
			}
			return realRun(context.Background(), args...)
		}
	}
	wait := func() { time.Sleep(1500 * time.Millisecond) }
	var err error
	switch name {
	case "refs":
		w1 := a.openInterruptWindow()
		w2 := a.openInterruptWindow()
		a.closeInterruptWindow(w1, nil)
		out("first-close-keeps-window", hasWin())
		auditSelfSignal(syscall.SIGINT)
		out("signal-seen-after-first-close", auditWaitFired(a))
		a.closeInterruptWindow(w2, &InterruptedError{File: "f", Restored: true, Signal: syscall.SIGINT})
		out("last-close-uninstalls", !hasWin())
	case "default-after-close":
		w := a.openInterruptWindow()
		a.closeInterruptWindow(w, nil)
		auditSelfSignal(syscall.SIGINT)
		wait()
		out("survived", true)
	case "default-after-save":
		if err = a.AddHost(domain.Host{Name: "hs-1", HostName: "10.2.2.2"}); err != nil {
			out("add-error", err)
			os.Exit(3)
		}
		auditSelfSignal(syscall.SIGINT)
		wait()
		out("survived", true)
	case "reraise":
		w := a.openInterruptWindow()
		auditSelfSignal(sig)
		auditWaitFired(a)
		a.closeInterruptWindow(w, nil)
		wait()
		out("survived", true)
	case "first-wins":
		w := a.openInterruptWindow()
		auditSelfSignal(syscall.SIGINT)
		auditWaitFired(a)
		auditSelfSignal(syscall.SIGTERM)
		time.Sleep(300 * time.Millisecond)
		a.closeInterruptWindow(w, nil)
		wait()
		out("survived", true)
	case "other-error":
		w := a.openInterruptWindow()
		auditSelfSignal(syscall.SIGINT)
		auditWaitFired(a)
		a.closeInterruptWindow(w, errors.New("the save failed for another reason"))
		wait()
		out("survived", true)
	case "handled":
		w := a.openInterruptWindow()
		auditSelfSignal(syscall.SIGINT)
		auditWaitFired(a)
		a.closeInterruptWindow(w, &InterruptedError{File: "f", Restored: true, Signal: syscall.SIGINT})
		wait()
		out("survived", true)
	case "usr1":
		w := a.openInterruptWindow()
		auditSelfSignal(syscall.SIGUSR1)
		time.Sleep(400 * time.Millisecond)
		out("window-saw-usr1", w.fired())
		a.closeInterruptWindow(w, nil)
		out("survived", true)
	case "ctx-cancel":
		w := a.openInterruptWindow()
		sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
			auditSelfSignal(syscall.SIGINT)
			select {
			case <-ctx.Done():
				out("ctx-cancelled", true)
			case <-time.After(3 * time.Second):
				out("ctx-cancelled", false)
			}
			return nil, nil, ctx.Err()
		}
		_, err = a.sshG("web-1")
		a.closeInterruptWindow(w, &InterruptedError{File: "f", Restored: true, Signal: syscall.SIGINT})
	case "inflight-managed":
		managed := a.ManagedPath()
		before := read(managed)
		signalOnce(func() bool { return strings.Contains(read(managed), "Host sig-1") })
		err = a.AddHost(domain.Host{Name: "sig-1", HostName: "10.3.3.3"})
		out("interrupted", errors.Is(err, ErrInterrupted))
		out("restored", read(managed) == before)
	case "inflight-setup":
		before := read(main)
		signalOnce(func() bool { return strings.Contains(read(main), "Include ") })
		_, err = a.Setup(SetupOptions{})
		_, mErr := os.Stat(a.ManagedPath())
		out("interrupted", errors.Is(err, ErrInterrupted))
		out("restored", read(main) == before && os.IsNotExist(mErr))
	case "inflight-import":
		managed := a.ManagedPath()
		beforeMain, beforeManaged := read(main), read(managed)
		signalOnce(func() bool { return strings.Contains(read(managed), "Host moved-1") })
		var res ImportResult
		res, err = a.Import(ImportOptions{Apply: true})
		out("interrupted", errors.Is(err, ErrInterrupted))
		out("restored", read(main) == beforeMain && read(managed) == beforeManaged)
		out("applied", res.Applied)
		out("equivalent", res.Equivalent)
	default:
		fmt.Println("unknown case", name)
		os.Exit(4)
	}
	if err != nil {
		fmt.Println("err:", err)
	}
	os.Exit(0)
}

// ---- cert revoke: a host that is named by the certificate's identity ----------------

// G1/G2 through RevokeCert: a host is "referencing" a certificate also when the
// certificate's identity is the host's name (no CertificateFile line needed).
// On a config that is not set up that is refused with the gate and the
// certificate file is NOT deleted; on a set-up config the certificate goes.
func TestAuditP7_RevokeCertFindsHostByIdentity(t *testing.T) {
	mgNeedSSH(t)
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
	mk := func(t *testing.T, e *mgEnv) string {
		t.Helper()
		keys := filepath.Join(e.dir, "idkeys")
		if err := os.MkdirAll(keys, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(keys, "ca")},
			{"-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(keys, "user")},
			{"-q", "-s", filepath.Join(keys, "ca"), "-I", "id-host-1", "-n", "alice", "-V", "+1h", filepath.Join(keys, "user.pub")},
		} {
			if out, err := exec.Command(keygen, args...).CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
			}
		}
		return filepath.Join(keys, "user-cert.pub")
	}
	hosts := "Host id-host-1\n  HostName 10.0.0.8\n"

	t.Run("not set up", func(t *testing.T) {
		e := nsNew(t, hosts, mgAbsent)
		cert := mk(t, e)
		before := nsSnap(t, e.dir)
		err := e.a.RevokeCert(cert)
		nsRequireGate(t, err)
		if _, serr := os.Stat(cert); serr != nil {
			t.Errorf("the certificate file was deleted although the revoke was refused: %v", serr)
		}
		nsRequireSame(t, before, nsSnap(t, e.dir))
	})
	t.Run("set up", func(t *testing.T) {
		e := nsNew(t, "Include @M@\n", mgManagedHeader+"\n"+hosts)
		cert := mk(t, e)
		if err := e.a.RevokeCert(cert); err != nil {
			t.Fatalf("RevokeCert = %v", err)
		}
		if _, serr := os.Stat(cert); !os.IsNotExist(serr) {
			t.Errorf("the certificate file is still there: %v", serr)
		}
	})
}
