package app

// Implementation-side tests for setup / import: the seams the frozen black-box
// tests cannot reach (lost updates, failing writes, rollback of a created
// layout) and the pure helpers. Tests that replace a package variable are not
// parallel.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestImplImport_LostUpdateBetweenPlanAndWriteIsAConflict(t *testing.T) {
	mgNeedSSH(t)
	for _, which := range []string{"main", "managed"} {
		t.Run(which, func(t *testing.T) {
			e := newImEnv(t)
			path := e.main
			if which == "managed" {
				path = e.managed
			}
			afterImportPlan = func() {
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Error(err)
					return
				}
				f.WriteString("# edited meanwhile\n")
				f.Close()
			}
			t.Cleanup(func() { afterImportPlan = func() {} })
			before := e.snap(t)
			_, err := e.a.Import(ImportOptions{Apply: true})
			afterImportPlan = func() {}
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("err = %v, want ErrConflict", err)
			}
			after := e.snap(t)
			// The only change is the one the test made; no backup, no half move.
			if d := mgDiff(before, after, false); !reflect.DeepEqual(d, []string{"changed " + path}) {
				t.Errorf("diff = %v, want only the concurrent edit", d)
			}
			if got := mgRead(t, path); !strings.HasSuffix(got, "# edited meanwhile\n") {
				t.Errorf("the concurrent edit was lost: %q", got)
			}
		})
	}
}

func TestImplImport_MainWriteFailureRestoresManagedAndBacksUp(t *testing.T) {
	mgNeedSSH(t)
	e := newImEnv(t)
	origMain, origManaged := e.readMain(t), e.readManaged(t)
	prev := writeMainFile
	writeMainFile = func(string, []byte) error { return errors.New("injected main write failure") }
	t.Cleanup(func() { writeMainFile = prev })

	before := e.snap(t)
	res, err := e.a.Import(ImportOptions{Apply: true})
	if err == nil || !strings.Contains(err.Error(), "injected main write failure") {
		t.Fatalf("err = %v", err)
	}
	if res.Applied {
		t.Error("Applied = true after a failed import")
	}
	if got := e.readManaged(t); got != origManaged {
		t.Errorf("managed file not restored:\n%s", got)
	}
	if got := e.readMain(t); got != origMain {
		t.Errorf("main file changed:\n%s", got)
	}
	mgRequireRestored(t, before, e.snap(t), e.managed)
	if len(mgBackupWith(t, e.dir, origMain)) != 1 || len(mgBackupWith(t, e.dir, origManaged)) != 1 {
		t.Errorf("both files should be backed up before the first write: %v", mgBackupFiles(t, e.dir))
	}
}

// ssh fails after the files were written: both are put back.
func TestImplImport_SSHFailureAfterTheWriteRestoresBoth(t *testing.T) {
	mgNeedSSH(t)
	e := newImEnv(t)
	origMain, origManaged := e.readMain(t), e.readManaged(t)
	// A control import on a copy of the fixture tells how many ssh calls the
	// "before" phase makes (the "after" phase makes as many).
	var probes int
	realRun := sshRun
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		probes++
		return realRun(ctx, args...)
	}
	_, cerr := newImEnv(t).a.Import(ImportOptions{Apply: true})
	sshRun = realRun
	if cerr != nil || probes == 0 || probes%2 != 0 {
		t.Fatalf("control import: err=%v, %d ssh calls", cerr, probes)
	}

	failAfter(t, probes/2)
	before := e.snap(t)
	_, err := e.a.Import(ImportOptions{Apply: true})
	if err == nil || errors.Is(err, ErrNotEquivalent) {
		t.Fatalf("err = %v, want an ssh error", err)
	}
	mgRequireRestored(t, before, e.snap(t), e.main, e.managed)
	if e.readMain(t) != origMain || e.readManaged(t) != origManaged {
		t.Error("files not restored byte for byte")
	}
}

// failAfter makes ssh fail from the (n+1)th call on.
func failAfter(t *testing.T, n int) {
	t.Helper()
	realRun := sshRun
	calls := 0
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		calls++
		if calls > n {
			return nil, []byte("injected ssh failure"), errors.New("exit status 255")
		}
		return realRun(ctx, args...)
	}
	t.Cleanup(func() { sshRun = realRun })
}

func TestImplSetup_RollbackRemovesWhatItCreated(t *testing.T) {
	mgNeedSSH(t)
	e := newMgEnv(t, sxMain, mgAbsent)
	failAfter(t, 3) // web-1, db-1 and the sentinel before; the first call after fails
	before := e.snap(t)
	_, err := e.a.Setup(SetupOptions{})
	mgRequireErr(t, err)
	mgRequireRestored(t, before, e.snap(t), e.main)
	if e.readMain(t) != sxMain {
		t.Errorf("main file not restored:\n%s", e.readMain(t))
	}
	if mgExists(e.managed) || mgExists(filepath.Dir(e.managed)) {
		t.Error("the managed file or config.d created by the failed setup is still there")
	}
}

// An unconditional Include that already names a managed file which does not exist
// yet: setup only creates the file; the main file is not touched (S5, 5.2).
func TestImplSetup_ExistingIncludeOfAMissingManagedFile(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, "Include @M@\n"+sxMain, mgAbsent)
	before := e.snap(t)
	res, err := e.a.Setup(SetupOptions{DryRun: true})
	mgRequireNoErr(t, err)
	want := []string{"create " + filepath.Dir(e.managed) + " (0700)", "create " + e.managed + " (0600)"}
	if res.AlreadySetUp || !reflect.DeepEqual(res.Actions, want) {
		t.Errorf("dry run: %+v, want actions %q", res, want)
	}
	mgRequireUnchanged(t, before, e.snap(t))

	res, err = e.a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if !reflect.DeepEqual(res.Actions, want) {
		t.Errorf("actions = %q, want %q", res.Actions, want)
	}
	if got := e.readMain(t); got != "Include "+e.managed+"\n"+sxMain {
		t.Errorf("main file changed:\n%s", got)
	}
	if !mgExists(e.managed) {
		t.Error("managed file not created")
	}
	active, err := e.a.ManagedActive()
	mgRequireNoErr(t, err)
	if !active {
		t.Error("not active after setup")
	}
}

func TestImplSetup_ConditionalIncludeOfAMissingManagedFileIsAnError(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, "Host web-1\n  HostName 10.0.0.1\nInclude @M@\n", mgAbsent)
	before := e.snap(t)
	_, err := e.a.Setup(SetupOptions{})
	mgRequireErr(t, err)
	if !strings.Contains(err.Error(), "above the first Host/Match") || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error %q", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

func TestImplSetup_QuotesAPathWithBlanks(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "my ssh")
	main := filepath.Join(dir, "config")
	mgWrite(t, main, "Host web-1\n  HostName 10.0.0.1\n", 0o600)
	a := NewAppWithPath(main)
	_, err := a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if got := mgRead(t, main); !strings.HasPrefix(got, "Include \""+a.ManagedPath()+"\"\n") {
		t.Errorf("main file:\n%s", got)
	}
	if active, err := a.ManagedActive(); err != nil || !active {
		t.Errorf("ManagedActive = %v, %v", active, err)
	}
}

func TestImplImport_DryRunReportsAConflictWithoutFailing(t *testing.T) {
	t.Parallel()
	e := newImEnvWith(t, imMain, mgManagedHeader+"\nHost web-1\n  HostName 10.0.0.77\n")
	before := e.snap(t)
	res, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)
	if !mgNoteHas(res.Notes, "web-1") {
		t.Errorf("Notes = %q, want a note naming web-1", res.Notes)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

// The legacy group disable writes the adjacent hosts of a group between ONE pair
// of markers: the entries split the region into consecutive ranges.
func TestImplImport_OneRegionManyHosts(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, groupFixture, mgAbsent)
	mgRequireNoErr(t, e.a.DisableGroup("deploy"))
	mgWrite(t, e.main, "Include "+e.managed+"\n"+e.readMain(t), 0o600)
	mgWrite(t, e.managed, mgManagedHeader, 0o600)
	orig := e.readMain(t)
	res, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)
	start := mgLineOf(t, orig, "# sshm disabled group=deploy start")
	end := mgLineOf(t, orig, "# sshm disabled group=deploy end")
	var acq, eu ImportBlock
	for _, b := range res.Move {
		switch b.Name {
		case "deploy-acq":
			acq = b
		case "deploy-eu":
			eu = b
		}
	}
	if acq.FromLine != start || acq.ToLine != eu.FromLine-1 || eu.ToLine != end {
		t.Errorf("deploy-acq %+v, deploy-eu %+v: want consecutive ranges from line %d to %d", acq, eu, start, end)
	}
}

// The last block of a file without a final newline moves; both files end in a
// newline afterwards and nothing else changes.
func TestImplImport_FileWithoutFinalNewline(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, "Include @M@\n\nHost keep-*\n  User k\n\nHost web-1\n  HostName 10.0.0.1", mgManagedHeader)
	_, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	if got, want := e.readMain(t), "Include "+e.managed+"\n\nHost keep-*\n  User k\n"; got != want {
		t.Errorf("main file %q, want %q", got, want)
	}
	if got, want := e.readManaged(t), mgManagedHeader+"\nHost web-1\n  HostName 10.0.0.1\n"; got != want {
		t.Errorf("managed file %q, want %q", got, want)
	}
}

// Group state: only the groups whose disabled blocks moved leave the main
// sidecar; the others stay where they are.
func TestImplImport_OnlyMovedGroupsLeaveTheMainSidecar(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, groupFixture, mgAbsent)
	mgRequireNoErr(t, e.a.DisableGroup("deploy"))
	mgWrite(t, mgSidecar(e.main), "# state\nother\ndeploy\n", 0o600)
	mgWrite(t, e.main, "Include "+e.managed+"\n"+e.readMain(t), 0o600)
	mgWrite(t, e.managed, mgManagedHeader, 0o600)
	mgWrite(t, mgSidecar(e.managed), "# state\nalready\n", 0o600)
	_, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	main := mgRead(t, mgSidecar(e.main))
	managed := mgRead(t, mgSidecar(e.managed))
	if !mgHasLine(main, "other") || mgHasLine(main, "deploy") {
		t.Errorf("main sidecar:\n%s", main)
	}
	if !mgHasLine(managed, "already") || !mgHasLine(managed, "deploy") || mgHasLine(managed, "other") {
		t.Errorf("managed sidecar:\n%s", managed)
	}
}

func TestImplDiffResolved(t *testing.T) {
	t.Parallel()
	before := map[string]string{
		"a": "user x\nport 22\nidentityfile k1\nidentityfile k2",
		"b": "user x",
		"c": "user x\nidentityfile k1\nidentityfile k2",
	}
	after := map[string]string{
		"a": "user y\nidentityfile k1\nidentityfile k3\nproxyjump j",
		"b": "user x",
		"c": "user x\nidentityfile k2\nidentityfile k1",
	}
	want := []string{
		"a: -user x", "a: +user y",
		"a: -port 22",
		"a: -identityfile k2", "a: +identityfile k3",
		"a: +proxyjump j",
		"c: -identityfile k1", "c: -identityfile k2", "c: +identityfile k2", "c: +identityfile k1",
	}
	if got := diffResolved(before, after); !reflect.DeepEqual(got, want) {
		t.Errorf("diffResolved =\n%q\nwant\n%q", got, want)
	}
	if got := diffResolved(before, before); got != nil {
		t.Errorf("identical outputs: %q", got)
	}
	if got := diffResolved(map[string]string{"d": "x 1\n"}, map[string]string{"d": "x 1"}); len(got) != 1 {
		t.Errorf("outputs that differ only in a newline must still be reported once: %q", got)
	}
}
