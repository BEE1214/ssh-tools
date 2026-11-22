package app

// P7 clauses I1-I4 and clarifications 1, 8, 9 at the App level
// (PLAN-p7.md). `init` on a machine without an ssh config is
// InitFresh followed (on the next run) by InitDefaultsReport.
// The CLI side is in internal/cli/init_fresh_test.go.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// frEnv is a fresh machine: <tmp>/ssh does not exist, so neither does the main
// file, config.d or the managed file.
type frEnv struct {
	base, sshDir, main, managed string
	a                           *App
}

func frNew(t *testing.T) *frEnv {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	base := t.TempDir()
	e := &frEnv{base: base, sshDir: filepath.Join(base, "ssh")}
	e.main = filepath.Join(e.sshDir, "config")
	e.managed = filepath.Join(e.sshDir, "config.d", "sshm.conf")
	e.a = NewAppWithPath(e.main)
	return e
}

// wantActions are the lines `sshm setup` prints for a machine with nothing.
func (e *frEnv) wantActions() []string {
	return []string{
		"create " + e.sshDir + " (0700)",
		"create " + filepath.Join(e.sshDir, "config.d") + " (0700)",
		"create " + e.managed + " (0600)",
		"create " + e.main + " (0600) with Include line",
	}
}

func frRequireActions(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Actions =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// frRequireSetUpState checks the files setup leaves behind (I1).
func frRequireSetUpState(t *testing.T, e *frEnv, wantManaged string) {
	t.Helper()
	for dir, name := range map[string]string{e.sshDir: "ssh dir", filepath.Dir(e.managed): "config.d"} {
		fi, err := os.Stat(dir)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s %s: mode %v, want a directory with 0700", name, dir, fi.Mode())
		}
	}
	if mgExists(e.managed) {
		if m := mgMode(t, e.managed); m != 0o600 {
			t.Errorf("managed file mode %v, want 0600", m)
		}
		if got := mgRead(t, e.managed); got != wantManaged {
			t.Errorf("managed file = %q, want %q", got, wantManaged)
		}
	} else {
		t.Errorf("managed file %s does not exist", e.managed)
	}
	if !mgExists(e.main) {
		t.Fatalf("main file %s does not exist", e.main)
	}
	if m := mgMode(t, e.main); m != 0o600 {
		t.Errorf("main file mode %v, want 0600", m)
	}
	var content []string
	for _, l := range mgLines(mgRead(t, e.main)) {
		if strings.TrimSpace(l) != "" {
			content = append(content, l)
		}
	}
	if len(content) != 1 || content[0] != "Include "+e.managed {
		t.Errorf("main file lines = %q, want exactly [%q]", content, "Include "+e.managed)
	}
}

// I1: the main file does not exist: InitFresh performs the setup actions, writes
// no Host * block, and ssh works afterwards.
func TestInitFresh_PerformsSetupAndWritesNoHostStar(t *testing.T) {
	e := frNew(t)
	res, fresh, err := e.a.InitFresh()
	mgRequireNoErr(t, err)
	if !fresh {
		t.Fatal("fresh = false, want true for a main file that did not exist")
	}
	if res.AlreadySetUp {
		t.Error("AlreadySetUp = true")
	}
	frRequireActions(t, res.Actions, e.wantActions())
	if mgRealSSH != "" && len(res.Notes) != 0 {
		t.Errorf("Notes = %q, want none (ssh is available)", res.Notes)
	}
	frRequireSetUpState(t, e, mgManagedHeader)

	for _, p := range []string{e.main, e.managed} {
		if strings.Contains(mgRead(t, p), "Host *") {
			t.Errorf("%s contains a Host * block:\n%s", p, mgRead(t, p))
		}
	}
	snap, err := e.a.Snapshot()
	mgRequireNoErr(t, err)
	if !snap.Managed || len(snap.Hosts) != 0 {
		t.Errorf("Snapshot Managed=%v with %d hosts, want a managed config without hosts", snap.Managed, len(snap.Hosts))
	}
	issues, err := e.a.Validate()
	mgRequireNoErr(t, err)
	if domain.HasErrors(issues) {
		t.Errorf("Validate reports errors: %v", issues)
	}
	mgNeedSSH(t)
	for _, host := range []string{"anyhost", "web-1.example"} {
		if got := mgVal(mgSSHG(t, e.main, host), "hostname"); got != host {
			t.Errorf("ssh -G %s: hostname %q, want %q", host, got, host)
		}
	}
}

// Clarification 8: fresh is true whenever the main file was missing and the
// setup actions ran, also when config.d/sshm.conf already existed; its content
// is not touched.
func TestInitFresh_ManagedFileAlreadyExists(t *testing.T) {
	e := frNew(t)
	managedBody := mgManagedHeader + "\nHost kept-1\n  HostName 10.7.7.7\n"
	mgWrite(t, e.managed, managedBody, 0o600)
	if err := os.Chmod(filepath.Dir(e.managed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	res, fresh, err := e.a.InitFresh()
	mgRequireNoErr(t, err)
	if !fresh {
		t.Fatal("fresh = false, want true: the main file did not exist")
	}
	frRequireActions(t, res.Actions, []string{"create " + e.main + " (0600) with Include line"})
	frRequireSetUpState(t, e, managedBody)
	mgNeedSSH(t)
	if got := mgVal(mgSSHG(t, e.main, "kept-1"), "hostname"); got != "10.7.7.7" {
		t.Errorf("ssh -G kept-1: hostname %q, want 10.7.7.7 (the managed host is reachable)", got)
	}
}

// Clarification 8 + I3: a main file that exists is NOT fresh, whatever it holds:
// InitFresh changes nothing and says fresh=false without an error, and the
// following InitDefaultsReport is refused by the gate unless the config is set up.
func TestInitFresh_ExistingMainFileIsNotFresh(t *testing.T) {
	cases := []struct {
		name          string
		main, managed string
		notSetUp      bool
	}{
		{"zero-byte main file", "", mgAbsent, true},
		{"comment-only main file", "# nothing here yet\n", mgAbsent, true},
		{"main file with hosts, not set up", nsNotSetUpMain, mgAbsent, true},
		{"main file set up", nsSetUpMain, nsSetUpManaged, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := nsNew(t, c.main, c.managed)
			before := nsSnap(t, e.dir)
			res, fresh, err := e.a.InitFresh()
			mgRequireNoErr(t, err)
			if fresh {
				t.Error("fresh = true for an existing main file")
			}
			if len(res.Actions) != 0 {
				t.Errorf("Actions = %q, want none", res.Actions)
			}
			nsRequireSame(t, before, nsSnap(t, e.dir))

			_, _, err = e.a.InitDefaultsReport()
			if c.notSetUp {
				nsRequireGate(t, err)
				nsRequireSame(t, before, nsSnap(t, e.dir))
			} else if errors.Is(err, ErrNotSetUp) {
				t.Errorf("a set-up config was refused: %v", err)
			}
		})
	}
}

// I3 + I4: the second `init` of a fresh machine is the normal set-up init: it
// appends the default Host * block at the END of the main file, once, and the
// managed file stays as it is.
func TestInitFresh_SecondInitAddsHostStarAtEnd(t *testing.T) {
	e := frNew(t)
	_, fresh, err := e.a.InitFresh()
	mgRequireNoErr(t, err)
	if !fresh {
		t.Fatal("first init was not fresh")
	}
	if _, fresh, err = e.a.InitFresh(); err != nil || fresh {
		t.Fatalf("second InitFresh = fresh %v, err %v; want false, nil", fresh, err)
	}
	written, note, err := e.a.InitDefaultsReport()
	mgRequireNoErr(t, err)
	if !written {
		t.Fatalf("InitDefaultsReport wrote nothing (note %q)", note)
	}
	body := mgRead(t, e.main)
	lines := mgLines(body)
	if lines[0] != "Include "+e.managed {
		t.Errorf("line 1 = %q, want the Include line", lines[0])
	}
	i := strings.Index(body, "Host *\n")
	if i < 0 {
		t.Fatalf("main file has no Host * block:\n%s", body)
	}
	if i < len("Include "+e.managed) || strings.Count(body, "Host *") != 1 {
		t.Errorf("Host * block misplaced or repeated:\n%s", body)
	}
	for _, want := range []string{"ServerAliveInterval 60", "StrictHostKeyChecking accept-new"} {
		if !strings.Contains(body[i:], want) {
			t.Errorf("Host * block lacks %q:\n%s", want, body)
		}
	}
	if got := mgRead(t, e.managed); got != mgManagedHeader {
		t.Errorf("managed file changed: %q", got)
	}
	mgNeedSSH(t)
	if got := mgVal(mgSSHG(t, e.main, "anyhost"), "serveraliveinterval"); got != "60" {
		t.Errorf("ssh -G anyhost: serveraliveinterval %q, want 60", got)
	}

	// and a third time: Host * exists, nothing is written, the note says where.
	before := mgRead(t, e.main)
	written, note, err = e.a.InitDefaultsReport()
	mgRequireNoErr(t, err)
	if written || !strings.Contains(note, "Host * is already defined at ") {
		t.Errorf("third init: written=%v note=%q, want false and the 'already defined' note", written, note)
	}
	if mgRead(t, e.main) != before {
		t.Error("third init changed the main file")
	}
}

// I4: a failure inside the fresh setup leaves either the previous state (nothing
// at all) or a complete set-up state, never a part of it. The failure here is ssh
// refusing the new config at verification (a fake ssh that always fails).
func TestInitFresh_FailureLeavesPreviousOrCompleteState(t *testing.T) {
	e := frNew(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\necho 'fake ssh: refusing' >&2\nexit 255\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, _, err := e.a.InitFresh()
	if err == nil {
		t.Fatal("InitFresh returned no error although ssh rejects the result")
	}
	if errors.Is(err, ErrNotImplemented) {
		t.Fatalf("got the skeleton's ErrNotImplemented, want the failure of the verification: %v", err)
	}
	if mgExists(e.main) {
		// complete set-up state
		frRequireSetUpState(t, e, mgManagedHeader)
		return
	}
	// previous state: the machine looks as before, no stray directory either
	for _, p := range []string{e.managed, filepath.Dir(e.managed), e.sshDir} {
		if mgExists(p) {
			t.Errorf("partial state: %s exists although the main file does not", p)
		}
	}
}

// I4: a failure before anything is written (the parent directory cannot be
// written to) leaves the previous state.
func TestInitFresh_UnwritableParentLeavesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	e := frNew(t)
	if err := os.Chmod(e.base, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(e.base, 0o700) })

	_, fresh, err := e.a.InitFresh()
	if err == nil {
		t.Fatal("InitFresh returned no error for an unwritable parent directory")
	}
	if errors.Is(err, ErrNotImplemented) {
		t.Fatalf("got the skeleton's ErrNotImplemented: %v", err)
	}
	if fresh {
		t.Error("fresh = true although nothing could be created")
	}
	if mgExists(e.sshDir) {
		t.Errorf("%s was created", e.sshDir)
	}
}
