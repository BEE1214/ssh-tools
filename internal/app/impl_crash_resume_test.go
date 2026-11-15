package app

// I11 (crash window between the managed write and the main write) and I11b
// (resuming the interrupted import).
//
// The crash is simulated for real: a helper process (this test binary run with
// -test.run=TestHelperImportCrash) replaces the writeMainFile seam with
// os.Exit(3), so it dies right after the managed file was written. The parent
// then inspects the files it left behind. All fixtures live in temp dirs with
// absolute Include paths; ssh is always called with -F.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const crashMain = `Include @M@

# web servers
Host web-1
  HostName 10.0.0.1
  User alice

# group: infra
# database primary
Host db-1
  HostName 10.0.0.3
  Port 2222

Host *
  ServerAliveInterval 30
`

var crashHosts = []string{"web-1", "db-1", "other.example.com"}

// TestHelperImportCrash is the subprocess body; it does nothing in a normal run.
func TestHelperImportCrash(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_IMPORT_CRASH") != "1" {
		return
	}
	writeMainFile = func(string, []byte) error {
		// TestMain's temp home would be left behind by os.Exit.
		os.RemoveAll(testHome)
		os.Exit(3)
		return nil
	}
	_, err := NewAppWithPath(os.Getenv("GO_HELPER_MAIN")).Import(ImportOptions{Apply: true})
	os.Stderr.WriteString("helper: Import returned instead of crashing: " + errString(err) + "\n")
	os.RemoveAll(testHome)
	os.Exit(4)
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// crashedImport builds the fixture, runs the crashing import in a helper
// process and returns the environment with the files as the crash left them.
// before is `ssh -G` of every host as it was before the import.
func crashedImport(t *testing.T) (e *mgEnv, before map[string]string) {
	t.Helper()
	mgNeedSSH(t)
	e = newMgEnv(t, crashMain, mgManagedHeader)
	before = mgSSHAll(t, e.main, crashHosts)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperImportCrash$", "-test.count=1")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_IMPORT_CRASH=1", "GO_HELPER_MAIN="+e.main)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("helper: err = %v, want exit status 3 (the simulated crash)\n%s", err, out)
	}
	return e, before
}

// crashControl is an uninterrupted import of the same fixture in another dir.
func crashControl(t *testing.T) *mgEnv {
	t.Helper()
	c := newMgEnv(t, crashMain, mgManagedHeader)
	if _, err := c.a.Import(ImportOptions{Apply: true}); err != nil {
		t.Fatalf("control import: %v", err)
	}
	return c
}

func hostLineCount(text, name string) int {
	return strings.Count(text, "\nHost "+name+"\n") + b2i(strings.HasPrefix(text, "Host "+name+"\n"))
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// I11: the state a crash between the two writes leaves behind.
func TestImplImport_CrashBetweenTheWritesLeavesAnEquivalentConfig(t *testing.T) {
	t.Parallel()
	e, before := crashedImport(t)

	main, managed := e.readMain(t), e.readManaged(t)
	if main != e.sub(crashMain) {
		t.Errorf("main file changed although the crash came before its write:\n%s", main)
	}
	for _, h := range []string{"web-1", "db-1"} {
		if n := hostLineCount(managed, h); n != 1 {
			t.Errorf("managed file defines %s %d times, want 1:\n%s", h, n, managed)
		}
		if n := hostLineCount(main, h); n != 1 {
			t.Errorf("main file defines %s %d times, want 1 (the move was not finished)", h, n)
		}
	}
	mgRequireSameResolution(t, e.main, before)

	issues, err := e.a.Validate()
	mgRequireNoErr(t, err)
	got := map[string]bool{}
	for _, is := range issues {
		if is.Rule == "dup-host-cross-file" {
			got[is.HostName] = true
		}
	}
	for _, h := range []string{"web-1", "db-1"} {
		if !got[h] {
			t.Errorf("Validate() has no dup-host-cross-file issue for %s: %+v", h, issues)
		}
	}

	if b := mgBackupWith(t, e.dir, e.sub(crashMain)); len(b) == 0 {
		t.Error("no backup of the original main file in sshm-backups")
	}
	if b := mgBackupWith(t, e.dir, mgManagedHeader); len(b) == 0 {
		t.Error("no backup of the original managed file in sshm-backups")
	}
}

// I11b: import --apply completes an interrupted import.
func TestImplImport_ApplyResumesAnInterruptedImport(t *testing.T) {
	t.Parallel()
	e, before := crashedImport(t)
	c := crashControl(t)

	res, err := e.a.Import(ImportOptions{Apply: true})
	if err != nil {
		t.Errorf("resumed Import(Apply) failed: %v", err)
	}
	if names := imNames(res); strings.Join(names, ",") != "web-1,db-1" {
		t.Errorf("Move = %v, want [web-1 db-1] (the plan lists the blocks as moves)", names)
	}
	if !mgNoteHas(res.Notes, "resuming an interrupted import") {
		t.Errorf("Notes = %q, want one containing 'resuming an interrupted import'", res.Notes)
	}

	main, managed := e.readMain(t), e.readManaged(t)
	for _, h := range []string{"web-1", "db-1"} {
		if n := hostLineCount(main, h); n != 0 {
			t.Errorf("main file still defines %s (%d times):\n%s", h, n, main)
		}
		if n := hostLineCount(managed, h); n != 1 {
			t.Errorf("managed file defines %s %d times, want exactly 1:\n%s", h, n, managed)
		}
	}
	mgRequireSameResolution(t, e.main, before)

	norm := func(env *mgEnv, s string) string { return strings.ReplaceAll(s, env.dir, "@D@") }
	if got, want := norm(e, main), norm(c, c.readMain(t)); got != want {
		t.Errorf("main file differs from an uninterrupted import:\n%s", mgLineDiff(want, got))
	}
	if got, want := norm(e, managed), norm(c, c.readManaged(t)); got != want {
		t.Errorf("managed file differs from an uninterrupted import:\n%s", mgLineDiff(want, got))
	}
}

// I6 still holds for a resume: a block of the same name with DIFFERENT content
// in the managed file is a conflict, and nothing changes.
func TestImplImport_ResumeWithDifferentManagedContentIsStillAConflict(t *testing.T) {
	t.Parallel()
	e, _ := crashedImport(t)
	// web-1 differs from the main file's block; db-1 is still byte-identical.
	changed := strings.Replace(e.readManaged(t), "HostName 10.0.0.1", "HostName 10.0.0.99", 1)
	if changed == e.readManaged(t) {
		t.Fatal("fixture: web-1 not found in the managed file")
	}
	mgWrite(t, e.managed, changed, 0o600)
	before := e.snap(t)

	_, err := e.a.Import(ImportOptions{Apply: true})
	if !errors.Is(err, ErrImportConflict) {
		t.Fatalf("err = %v, want ErrImportConflict", err)
	}
	if !strings.Contains(err.Error(), "web-1") {
		t.Errorf("err = %v, want it to name web-1", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}
