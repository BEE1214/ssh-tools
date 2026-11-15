package app

// Audit additions: tests that kill mutants which survived the frozen suite.
// Each test names the mutant id of the mutation audit it is aimed at.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// s07 (5.2): a CONDITIONAL Include of a managed file that does not exist yet is an
// error naming the line; nothing is created or changed.
func TestAudit_Setup_ConditionalIncludeOfAMissingManagedFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	main := "Host web-1\n  HostName 10.0.0.1\n\nInclude @M@\n"
	e := newMgEnv(t, main, mgAbsent)
	before := e.snap(t)
	// The dry run must already refuse: without the check up front it would report
	// "create sshm.conf" (the post-write safety net only fires on a real run).
	_, err := e.a.Setup(SetupOptions{DryRun: true})
	mgRequireErr(t, err)
	if !strings.Contains(err.Error(), "line 4") {
		t.Errorf("dry run: err = %v, want it to name line 4", err)
	}
	_, err = e.a.Setup(SetupOptions{})
	mgRequireErr(t, err)
	if !strings.Contains(err.Error(), "line 4") || strings.Contains(err.Error(), "setup undone") {
		t.Errorf("err = %v, want the up-front refusal naming line 4", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

// s23: an unconditional Include spelled through a symlinked directory counts as set up
// even though the managed file does not exist yet: no second Include line is added.
func TestAudit_Setup_IncludeSpelledThroughASymlinkedDirIsSetUp(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, "Include @D@/link/sshm.conf\n\nHost a\n  HostName 10.0.0.1\n", mgAbsent)
	if err := os.Mkdir(filepath.Dir(e.managed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(e.managed), filepath.Join(e.dir, "link")); err != nil {
		t.Fatal(err)
	}
	e.backdate(t)
	orig := e.readMain(t)
	if _, err := e.a.Setup(SetupOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := e.readMain(t); got != orig {
		t.Errorf("main file changed (a second Include was added?):\n%s", got)
	}
	if !mgExists(e.managed) {
		t.Error("managed file not created")
	}
}

// s14: the main file is edited between planning and the write (ssh probes take time):
// setup must not overwrite the edit.
func TestAudit_Setup_LostUpdateIsAConflict(t *testing.T) {
	mgNeedSSH(t)
	body := "Host web-1\n  HostName 10.0.0.1\n"
	e := newMgEnv(t, body, mgAbsent)
	real := sshRun
	edited := false
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		if !edited {
			edited = true
			f, err := os.OpenFile(e.main, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Error(err)
			} else {
				f.WriteString("# edited meanwhile\n")
				f.Close()
			}
		}
		return real(ctx, args...)
	}
	t.Cleanup(func() { sshRun = real })
	_, err := e.a.Setup(SetupOptions{})
	sshRun = real
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if got := e.readMain(t); got != body+"# edited meanwhile\n" {
		t.Errorf("the concurrent edit was lost or the Include was inserted:\n%s", got)
	}
	if mgExists(filepath.Dir(e.managed)) {
		t.Error("config.d left behind")
	}
}

// r38 / r45: hosts of a disabled group (in the managed file) are refused by edit and by
// forward --save, and nothing changes.
func TestAudit_Routing_DisabledGroupHostsAreRefused(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnvWith(t, rtMain, rtManaged+"\n# sshm disabled group=ops start\n# Host ops-1\n#   HostName 10.0.0.41\n# sshm disabled group=ops end\n")
	for name, op := range map[string]func() error{
		"edit":    func() error { return e.a.EditHost("ops-1", map[string]string{"user": "x"}) },
		"forward": func() error { return e.a.AddForward("ops-1", domain.ForwardLocal, []string{"8000:localhost:80"}) },
		"clear":   func() error { return e.a.ClearForwards("ops-1") },
	} {
		before := e.snap(t)
		err := op()
		// The Doc layer refuses a commented-out block too, but with a different
		// message; the user-facing refusal names the command that fixes it.
		if err == nil || !strings.Contains(err.Error(), "sshm groups enable ops") {
			t.Errorf("%s: err = %v, want the 'run sshm groups enable ops' refusal", name, err)
		}
		mgRequireUnchanged(t, before, e.snap(t))
	}
}

// i29: hosts already in the managed file are not "staying in an included file" and not movable.
func TestAudit_Import_ManagedHostsAreNeitherMovedNorListedAsStaying(t *testing.T) {
	t.Parallel()
	e := newImEnvWith(t, imMain, mgManagedHeader+"\nHost pre-existing\n  HostName 10.9.9.9\n")
	res, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)
	for _, s := range res.Stay {
		if s.File == e.managed || s.Name == "pre-existing" {
			t.Errorf("managed-file host listed as staying: %+v", s)
		}
	}
	for _, n := range imNames(res) {
		if n == "pre-existing" {
			t.Error("managed-file host listed as movable")
		}
	}
}

// i40: a "# DevPod End" line directly above a Host line belongs to the block above; the
// block below moves without it.
func TestAudit_Import_DevPodEndLineStaysInTheMainFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	main := "Include @M@\n\n# DevPod Start demo\nHost demo\n  HostName localhost\n# DevPod End demo\nHost web-9\n  HostName 10.0.0.9\n"
	e := newMgEnv(t, main, mgManagedHeader)
	res, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	if len(res.Move) != 1 || res.Move[0].Name != "web-9" || res.Move[0].FromLine != mgLineOf(t, main, "Host web-9") {
		t.Errorf("Move = %+v, want web-9 starting at its Host line", res.Move)
	}
	if m := e.readManaged(t); strings.Contains(m, "DevPod End") || !strings.Contains(m, "Host web-9") {
		t.Errorf("managed file:\n%s", m)
	}
	if m := e.readMain(t); !strings.Contains(m, "# DevPod End demo\n") || !strings.Contains(m, "Host demo") {
		t.Errorf("main file lost the DevPod block's end marker:\n%s", m)
	}
}

// i41: a marker region that holds no Host line is plain text and stays.
func TestAudit_Import_HostlessDisabledRegionStays(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	main := "Include @M@\n\n# sshm disabled group=ops start\n# just a note\n# sshm disabled group=ops end\n\nHost web-9\n  HostName 10.0.0.9\n"
	e := newMgEnv(t, main, mgManagedHeader)
	_, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	if m := e.readManaged(t); strings.Contains(m, "sshm disabled") || strings.Contains(m, "just a note") {
		t.Errorf("host-less region moved to the managed file:\n%s", m)
	}
	if m := e.readMain(t); !strings.Contains(m, "# sshm disabled group=ops start\n# just a note\n# sshm disabled group=ops end\n") {
		t.Errorf("main file lost the region:\n%s", m)
	}
}

// i23: the managed file is written first. If THAT write fails, the main file must not
// have been touched (it would otherwise lose hosts that exist nowhere). The lock file is
// created beforehand so the failure happens at the write, not at the lock.
func TestAudit_Import_ManagedWriteFailureLeavesMainUntouched(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not work as root")
	}
	e := newImEnv(t)
	cd := filepath.Dir(e.managed)
	lock, err := managedLockPath(e.managed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	origMain, origManaged := e.readMain(t), e.readManaged(t)
	if err := os.Chmod(cd, 0o500); err != nil { // temp file + rename in config.d now fail
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cd, 0o700) })
	_, err = e.a.Import(ImportOptions{Apply: true})
	mgRequireErr(t, err)
	if got := e.readMain(t); got != origMain {
		t.Errorf("main file changed although the managed write failed:\n%s", got)
	}
	if got := e.readManaged(t); got != origManaged {
		t.Errorf("managed file changed:\n%s", got)
	}
}
