package app

// Implementation-side tests for managed-mode routing: details the frozen
// black-box tests do not pin down.

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// An edit that changes no byte, and a clear of something that is not there,
// write nothing: no backup, no new mtime.
func TestImplRouting_NoOpWritesNothing(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	before := e.snap(t)
	mgRequireNoErr(t, e.a.EditHost("web-1", map[string]string{"user": "alice"})) // already alice
	mgRequireNoErr(t, e.a.EditHost("web-1", map[string]string{"loglevel": ""}))  // not set
	mgRequireNoErr(t, e.a.ClearForwards("db-1"))                                 // no forwards
	mgRequireNoErr(t, e.a.ClearCertificateFile("db-1"))                          // no certificate
	mgRequireNoErr(t, e.a.AddForward("web-2", domain.ForwardLocal, []string{"9000:127.0.0.1:9000"}))
	mgRequireUnchanged(t, before, e.snap(t))
}

// A single IdentityFile line is patched where it stands; a list is replaced.
func TestImplRouting_IdentityFileEditKeepsThePositionOfASingleLine(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t)
	mgRequireNoErr(t, e.a.EditHost("web-1", map[string]string{"identityfile": "/keys/only"}))
	mgRequireNoErr(t, e.a.EditHost("web-1", map[string]string{"identityfile": "/keys/second"}))
	// The first edit replaces a list of two (the new line goes after the last
	// option line of the block); the second finds one line and patches it there.
	want := strings.Replace(rtManaged, "    # inner comment\n    IdentityFile /keys/web1_a\n    IdentityFile /keys/web1_b\n",
		"    IdentityFile /keys/second\n    # inner comment\n", 1)
	if got := e.readManaged(t); got != want {
		t.Errorf("managed file:\n%s\nwant:\n%s", got, want)
	}
}

func TestImplRouting_EditRefusesWhatItCannotPatch(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	managed := mgManagedHeader + "\nHost dup-1\n  HostName 10.0.0.1\n  User a\n  User b\n\n# sshm disabled group=ops start\n# Host ops-1\n#   HostName 10.0.0.2\n# sshm disabled group=ops end\n"
	e := newRtEnvWith(t, rtMain, managed)
	before := e.snap(t)
	err := e.a.EditHost("dup-1", map[string]string{"user": "c"})
	mgRequireErr(t, err)
	if !strings.Contains(err.Error(), "by hand") {
		t.Errorf("error %q does not point to the file", err)
	}
	mgRequireErr(t, e.a.EditHost("ops-1", map[string]string{"user": "c"}))
	mgRequireErr(t, e.a.DeleteHost("nope-1"))
	mgRequireErr(t, e.a.EditHost("nope-1", map[string]string{"user": "c"}))
	mgRequireUnchanged(t, before, e.snap(t))
}

// `Host web-1 # prod` is the host web-1 for edit, add and the unmanaged check.
func TestImplRouting_HostLineWithAnInlineComment(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	managed := mgManagedHeader + "\nHost cm-1 # prod\n  HostName 10.0.0.5\n  User u\n"
	main := "Include @M@\n\nHost cm-2 # staging\n  HostName 10.0.0.6\n"
	e := newMgEnv(t, main, managed)
	mgRequireNoErr(t, e.a.EditHost("cm-1", map[string]string{"user": "v"}))
	if want := strings.Replace(managed, "User u", "User v", 1); e.readManaged(t) != want {
		t.Errorf("managed file:\n%s", e.readManaged(t))
	}
	err := e.a.AddHost(domain.Host{Name: "cm-1", HostName: "10.0.0.7"})
	mgRequireErr(t, err)
	var ume *UnmanagedHostError
	if err := e.a.EditHost("cm-2", map[string]string{"user": "x"}); !errors.As(err, &ume) || ume.Host != "cm-2" {
		t.Errorf("EditHost(cm-2) err = %v, want an *UnmanagedHostError for cm-2", err)
	}
}

func TestImplRouting_RunForwardNotifyCallsBackAfterTheSaveOnly(t *testing.T) {
	mgNoSSHOnPath(t)
	e := newRtEnv(t)
	calls := 0
	notify := func() { calls++ }

	// not saved: no callback
	_ = e.a.RunForwardNotify("web-1", domain.ForwardLocal, []string{"8080:localhost:80"}, false, notify)
	// refused: no callback
	err := e.a.RunForwardNotify("main-1", domain.ForwardLocal, []string{"8080:localhost:80"}, true, notify)
	var ume *UnmanagedHostError
	if !errors.As(err, &ume) {
		t.Fatalf("err = %v", err)
	}
	if calls != 0 {
		t.Fatalf("callback called %d times without a save", calls)
	}
	// saved: one callback, then the run stops at the missing ssh
	err = e.a.RunForwardNotify("web-1", domain.ForwardLocal, []string{"8080:localhost:80"}, true, notify)
	if err == nil || !strings.Contains(err.Error(), "ssh not found") || calls != 1 {
		t.Errorf("err = %v, callbacks = %d, want the ssh-not-found stop after one callback", err, calls)
	}
}

// R11: every existing byte of the main file stays, whatever its ending.
func TestImplRouting_InitKeepsTheMainFileBytes(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	for name, tail := range map[string]string{"no newline": "", "newline": "\n", "blank lines": "\n\n\n", "crlf": "\r\n"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			orig := "Include @M@\n\nHost main-1\r\n  HostName 10.0.0.9" + tail
			e := newMgEnv(t, orig, rtManaged)
			orig = e.readMain(t)
			_, err := e.a.InitDefaults()
			mgRequireNoErr(t, err)
			got := e.readMain(t)
			if !strings.HasPrefix(got, orig) {
				t.Errorf("existing bytes changed:\n%q\nwant prefix\n%q", got, orig)
			}
			if !strings.HasSuffix(got, "\n") || !strings.Contains(got[len(orig):], "Host *") {
				t.Errorf("appended part: %q", got[len(orig):])
			}
		})
	}
}

// R11 + R14 through InitDefaultsReport.
func TestImplRouting_InitReport(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newRtEnv(t) // main has a Host *
	written, note, err := e.a.InitDefaultsReport()
	mgRequireNoErr(t, err)
	if written || note == "" {
		t.Errorf("existing Host *: written=%v note=%q", written, note)
	}
	setUp := newMgEnv(t, "Include @M@\n\nHost a\n  HostName 10.0.0.1\n", mgManagedHeader)
	written, _, err = setUp.a.InitDefaultsReport()
	mgRequireNoErr(t, err)
	if !written {
		t.Error("init without a Host * reported nothing written")
	}
}

// Disabling a group needs the Doc to find plain names; a member that is a
// pattern block cannot be disabled and nothing changes.
func TestImplRouting_GroupWithAPatternMemberCannotBeDisabled(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	managed := mgManagedHeader + "\nHost ops-1\n  HostName 10.0.0.1\n\nHost ops-*\n  User ops\n"
	e := newRtEnvWith(t, rtMain, managed)
	before := e.snap(t)
	mgRequireErr(t, e.a.DisableGroup("ops"))
	mgRequireUnchanged(t, before, e.snap(t))
}

// A group that is only recorded in the sidecar (its hosts were removed by hand)
// can be enabled to clear the record, as in legacy mode.
func TestImplRouting_EnableClearsATrackedGroupWithoutBlocks(t *testing.T) {
	t.Parallel()
	e := newRtEnv(t)
	mgWrite(t, mgSidecar(e.managed), "# state\nghost\n", 0o600)
	mgRequireNoErr(t, e.a.EnableGroup("ghost"))
	if side := mgRead(t, mgSidecar(e.managed)); mgHasLine(side, "ghost") {
		t.Errorf("sidecar still lists the group:\n%s", side)
	}
	err := e.a.EnableGroup("ghost")
	mgRequireErr(t, err)
	if !strings.Contains(err.Error(), "not disabled") {
		t.Errorf("error %q", err)
	}
}

// The group error unwraps to the first offending host.
func TestImplRouting_GroupErrorUnwraps(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, "Include @M@\n\nHost g-1\n  HostName 10.0.0.1\n", mgManagedHeader)
	err := e.a.DisableGroup("g")
	var ume *UnmanagedHostError
	if !errors.As(err, &ume) || !reflect.DeepEqual([]string{ume.Host, ume.File}, []string{"g-1", e.main}) || !ume.CanImport {
		t.Errorf("err = %v", err)
	}
}

// Hosts that exist only in the managed file gate on the managed sidecar: a
// group recorded there is refused by connect-style gates, one recorded in the
// main file's sidecar (legacy state) is not looked at in managed mode.
func TestImplRouting_GateReadsTheManagedSidecar(t *testing.T) {
	t.Parallel()
	e := newRtEnv(t)
	mgWrite(t, mgSidecar(e.main), "# state\nweb\n", 0o600)
	if dis, err := e.a.IsGroupDisabled("web"); err != nil || dis {
		t.Errorf("IsGroupDisabled(web) = %v, %v with only the main sidecar", dis, err)
	}
	mgWrite(t, mgSidecar(e.managed), "# state\nweb\n", 0o600)
	if dis, err := e.a.IsGroupDisabled("web"); err != nil || !dis {
		t.Errorf("IsGroupDisabled(web) = %v, %v with the managed sidecar", dis, err)
	}
}
