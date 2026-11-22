package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Tests for the P2c fix round (re-review findings R1-R3 and minors). Same
// rules as managed_test.go: temp dirs only, ssh always with -F <temp main
// file>, absolute Include paths; a "Match exec" command only ever touches a
// file inside the test's temp dir.

// ---- Item 1 (R1): a legacy save keeps odd Host lines ----

// ---- Item 2 (R2): token-derived options need an exact prediction ----

// richTokenFixture: a main file whose Host * uses tokens in every option
// that takes them (paths in the temp dir; ssh -G only prints them).
func richTokenFixture(t *testing.T) *managedFixture {
	t.Helper()
	f := newManagedFixture(t, fixtureManaged)
	d := f.dir
	f.writeMain(t, "Include "+f.managed+"\n"+fixtureMainTail+
		"  ControlPath "+d+"/cm-%C\n"+
		"  IdentityAgent "+d+"/agent-%r\n"+
		"  IdentityFile "+d+"/id_%r\n"+
		"  CertificateFile "+d+"/cert_%r\n"+
		"  UserKnownHostsFile "+d+"/kh_%k\n"+
		"  GlobalKnownHostsFile "+d+"/gkh_%k\n"+
		"  RevokedHostKeys "+d+"/revoked_%h\n"+
		// Socket paths have a short length limit; these are never created.
		"  LocalForward /nonexistent/p2c/l_%r.sock /nonexistent/p2c/lr_%h.sock\n"+
		"  RemoteForward /nonexistent/p2c/r_%r.sock /nonexistent/p2c/rr_%h.sock\n"+
		"  ProxyCommand /bin/echo %h %p %r\n"+
		"  KnownHostsCommand /bin/echo %H %h\n"+
		"  LocalCommand /bin/echo %h %r\n"+
		"  RemoteCommand /bin/echo %h %r %p\n")
	return f
}

var sourceEdits = []struct{ key, value string }{
	{"User", "bob"}, {"HostName", "10.0.0.77"}, {"Port", "2244"},
	{"HostKeyAlias", "alias-1"}, {"ProxyJump", "jump.example.com"},
}

// With "Host * ControlPath <tmp>/cm-%C" (and tokens in every other option
// that takes them) an edit of User, HostName, Port, HostKeyAlias or ProxyJump
// goes through: the derived options change to exactly what ssh predicted.
func TestSaveManaged_SourceEditsPassWithExactPrediction(t *testing.T) {
	requireSSH(t)
	f := richTokenFixture(t)
	for _, s := range sourceEdits {
		cpBefore := f.resolved(t, "web-1", "controlpath")
		d := f.doc(t)
		if err := d.SetOption("web-1", s.key, s.value); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", s.key, s.value)); err != nil {
			t.Fatalf("%s edit rolled back: %v", s.key, err)
		}
		if s.key != "HostKeyAlias" && f.resolved(t, "web-1", "controlpath") == cpBefore {
			t.Errorf("fixture: controlpath did not follow the %s edit", s.key)
		}
	}
	// All three at once, as an edit form would send them.
	d := f.doc(t)
	for _, kv := range [][2]string{{"User", "carol"}, {"HostName", "10.0.0.78"}, {"Port", "2245"}} {
		if err := d.SetOption("web-1", kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "User", "carol", "HostName", "10.0.0.78", "Port", "2245")); err != nil {
		t.Fatalf("combined edit rolled back: %v", err)
	}
	if got := f.resolved(t, "web-1", "identityagent"); got != f.dir+"/agent-carol" {
		t.Errorf("identityagent = %q", got)
	}
}

// The hole of review R2: next to a declared User / HostName / Port edit, an
// UNDECLARED change of an option that takes tokens used to pass, because any
// such option was allowed to change. Each of these must roll back.
func TestSaveManaged_UndeclaredChangeNextToASourceEditRollsBack(t *testing.T) {
	requireSSH(t)
	for _, c := range []struct {
		name    string
		mutate  func(t *testing.T, d *config.Doc)
		wantKey string
	}{
		{"IdentityFile added", func(t *testing.T, d *config.Doc) {
			if err := d.AddOptionValue("web-1", "IdentityFile", "/keys/sneaked_in"); err != nil {
				t.Fatal(err)
			}
		}, "identityfile"},
		{"LocalForward added", func(t *testing.T, d *config.Doc) {
			if err := d.AddOptionValue("web-1", "LocalForward", "8080 localhost:80"); err != nil {
				t.Fatal(err)
			}
		}, "localforward"},
		{"ProxyCommand changed", func(t *testing.T, d *config.Doc) {
			if err := d.SetOption("web-1", "ProxyCommand", "/bin/echo something else %h"); err != nil {
				t.Fatal(err)
			}
		}, "proxycommand"},
		{"IdentityFile reordered", func(t *testing.T, d *config.Doc) {
			var idx []int
			for i, l := range d.Lines {
				if strings.Contains(l, "IdentityFile /keys/web1_") {
					idx = append(idx, i)
				}
			}
			if len(idx) != 2 {
				t.Fatalf("fixture: %d IdentityFile lines", len(idx))
			}
			d.Lines[idx[0]], d.Lines[idx[1]] = d.Lines[idx[1]], d.Lines[idx[0]]
		}, "identityfile order changed"},
		{"ControlPath rewritten", func(t *testing.T, d *config.Doc) {
			if err := d.SetOption("web-1", "ControlPath", "/elsewhere/cm-%C"); err != nil {
				t.Fatal(err)
			}
		}, "controlpath"},
	} {
		for _, src := range sourceEdits[:3] {
			t.Run(c.name+" with "+src.key, func(t *testing.T) {
				f := richTokenFixture(t)
				orig := f.read(t)
				d := f.doc(t)
				if err := d.SetOption("web-1", src.key, src.value); err != nil {
					t.Fatal(err)
				}
				c.mutate(t, d)
				_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", src.key, src.value))
				if err == nil {
					t.Fatalf("the undeclared change passed next to a %s edit; file:\n%s", src.key, f.read(t))
				}
				for _, want := range []string{"rolled back", "changed beyond the edited options", c.wantKey} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error lacks %q: %v", want, err)
					}
				}
				if f.read(t) != orig {
					t.Error("file not restored")
				}
			})
		}
	}
}

// A plan without an expected value for the source option (an unset) gives ssh
// nothing to predict from: then no derived option may change at all. Without
// tokens in play the same unset passes.
func TestSaveManaged_UnsetOfASourceOptionHasNoPrediction(t *testing.T) {
	requireSSH(t)
	unset := func(f *managedFixture) error {
		d := f.doc(t)
		if err := d.UnsetOption("web-1", "Port"); err != nil {
			t.Fatal(err)
		}
		_, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "port"))
		return err
	}
	f := newManagedFixture(t, fixtureManaged)
	if err := unset(f); err != nil {
		t.Fatalf("plain unset refused: %v", err)
	}
	f = richTokenFixture(t)
	orig := f.read(t)
	err := unset(f)
	if err == nil || !strings.Contains(err.Error(), "controlpath") || !strings.Contains(err.Error(), "changed beyond the edited options") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != orig {
		t.Error("file not restored")
	}
}

// A value ssh does not accept is found by the prediction, before anything is
// written or backed up.
func TestSaveManaged_PredictionRejectsABadValueBeforeWriting(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := f.doc(t)
	if err := d.SetOption("web-1", "Port", "not-a-port"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "Port", "not-a-port"))
	if err == nil || !strings.Contains(err.Error(), "not writing") || !strings.Contains(err.Error(), "ssh does not accept the new values (port=not-a-port)") {
		t.Fatalf("err = %v", err)
	}
	f.mustUnchanged(t, fixtureManaged)
}

// The prediction is an ssh call of its own: `-o key=value` for exactly the
// expected source values, before the host, on the main file.
func TestPredictDerivedArguments(t *testing.T) {
	f := newManagedFixture(t, fixtureManaged)
	var got [][]string
	prev := sshRun
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		got = append(got, args)
		return []byte("user bob\ncontrolpath /x\n"), nil, nil
	}
	t.Cleanup(func() { sshRun = prev })

	v := setPlan("web-1", "User", "bob", "Port", "2244", "ForwardAgent", "yes")
	pred, err := f.a.predictDerived([]string{"db-1", probeSentinel, "web-1"}, v)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"-F", f.main, "-G", "-o", "port=2244", "-o", "user=bob", "--", "web-1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ssh calls = %q, want %q", got, want)
	}
	if len(pred) != 1 || !reflect.DeepEqual(pred["web-1"]["controlpath"], []string{"/x"}) {
		t.Errorf("pred = %v", pred)
	}
	// No expected source value: no ssh call, no prediction.
	got = nil
	pred, err = f.a.predictDerived([]string{"web-1"}, setPlan("web-1", "ForwardAgent", "yes"))
	if err != nil || len(got) != 0 || len(pred) != 0 {
		t.Errorf("calls=%q pred=%v err=%v", got, pred, err)
	}
}

// The tokenDerived table against the installed ssh: with tokens in every
// option that takes them, an edit of a source option changes only options of
// the table (plus the edited one), and for those the -o prediction is exactly
// what the edit produces. A gap in the table would show up here, not as a
// refused edit on somebody's machine.
func TestTokenDerivedTableCoversSSH(t *testing.T) {
	requireSSH(t)
	for _, s := range sourceEdits {
		f := richTokenFixture(t)
		key := strings.ToLower(s.key)
		before, err := f.a.sshG("web-1")
		if err != nil {
			t.Fatal(err)
		}
		predicted, err := f.a.sshG("web-1", key+"="+s.value)
		if err != nil {
			t.Fatal(err)
		}
		d := f.doc(t)
		if err := d.SetOption("web-1", s.key, s.value); err != nil {
			t.Fatal(err)
		}
		f.writeManaged(t, string(d.Bytes()))
		after, err := f.a.sshG("web-1")
		if err != nil {
			t.Fatal(err)
		}
		b, p, a := optionValues(before), optionValues(predicted), optionValues(after)
		moved := 0
		for k := range a {
			if reflect.DeepEqual(a[k], b[k]) {
				continue
			}
			moved++
			if k != key && !tokenDerived[k] {
				t.Errorf("%s edit: ssh -G changes %s, which is not in tokenDerived", s.key, k)
			}
			if !reflect.DeepEqual(a[k], p[k]) {
				t.Errorf("%s edit: %s is %v after the edit, the -o prediction said %v", s.key, k, a[k], p[k])
			}
		}
		if moved < 2 {
			t.Errorf("%s edit: only %d option(s) moved; the fixture should make derived options follow", s.key, moved)
		}
		if predicted != after {
			t.Errorf("%s edit: the whole -o prediction differs from the real result", s.key)
		}
	}
}

// ---- Item 3 (R3): "exec" in a host name is not a Match exec ----

// The three false positives of the review. Verification must really run: a
// good edit comes back without a "verification skipped" note, and a bad one
// is rolled back (with verification skipped it would be written and kept).
func TestSaveManaged_MatchWithExecInANameStillVerifies(t *testing.T) {
	requireSSH(t)
	for _, line := range []string{"Match host exec-box", "Match host build.exec", "Match host=exec", "Match user exec"} {
		t.Run(line, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			f.writeMain(t, "Include "+f.managed+"\n\n"+line+"\n  Compression no\n"+fixtureMainTail)
			calls := countSSH(t)

			note, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
			if err != nil || note != "" {
				t.Fatalf("good edit: note=%q err=%v", note, err)
			}
			if calls.Load() == 0 {
				t.Fatal("ssh was never run: verification was skipped")
			}

			good := f.read(t)
			d := f.doc(t)
			if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
				t.Fatal(err)
			}
			if _, err := f.a.saveManagedDoc(f.managed, d, badWritePlan("web-1", "KexAlgorithms")); err == nil || !strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("a bad edit was not rolled back: %v", err)
			}
			if f.read(t) != good {
				t.Error("file not restored")
			}
		})
	}
}

// Real exec criteria in every form still skip verification, and the command
// is never run.
func TestSaveManaged_EveryMatchExecFormSkipsVerification(t *testing.T) {
	requireSSH(t)
	for _, form := range []string{
		`Match exec "touch MARK"`,
		`Match host web-1 exec "touch MARK"`,
		`Match exec="touch MARK"`,
		`Match !exec "touch MARK"`,
		`match final EXEC "touch MARK"`,
	} {
		t.Run(form, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			marker := filepath.Join(f.dir, "exec-ran")
			f.writeMain(t, "Include "+f.managed+"\n\n"+strings.ReplaceAll(form, "MARK", marker)+"\n  Compression no\n"+fixtureMainTail)
			calls := countSSH(t)
			note, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
			if err != nil || !strings.Contains(note, "verification skipped") {
				t.Fatalf("note=%q err=%v", note, err)
			}
			if _, serr := os.Stat(marker); serr == nil || calls.Load() != 0 {
				t.Fatalf("ssh was run (%d calls) or the Match exec command ran", calls.Load())
			}
		})
	}
}

// ---- Item 4: the lost-update window ----

// onSSHCall wraps the sshRun seam: before every ssh call it runs hook with
// the call number (1-based).
func onSSHCall(t *testing.T, hook func(n int)) {
	t.Helper()
	n := 0
	prev := sshRun
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		n++
		hook(n)
		return prev(ctx, args...)
	}
	t.Cleanup(func() { sshRun = prev })
}

// An editor saves the file while sshm runs its BEFORE probes (the lock only
// keeps other sshm processes out). The base comparison at the start has
// already passed; the one right before the write must catch it.
func TestSaveManaged_EditorWriteDuringBeforePhaseIsAConflict(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := setUser(t, f, "bob")
	edited := fixtureManaged + "# a line the editor added meanwhile\n"
	onSSHCall(t, func(n int) {
		if n == 2 { // in the middle of the before-probes
			f.writeManaged(t, edited)
		}
	})
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "User", "bob"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("the editor's save was overwritten or ignored: err = %v", err)
	}
	if got := f.read(t); got != edited {
		t.Errorf("the editor's content is gone:\n%s", got)
	}
	if baks := f.backups(t); len(baks) != 0 {
		t.Errorf("a save that wrote nothing made backups: %v", baks)
	}
}

// The same for a managed file that did not exist when the Doc was made: it
// appears during the before-probes.
func TestSaveManaged_FileAppearingDuringBeforePhaseIsAConflict(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "")
	d := config.ParseDoc(nil)
	if err := d.AppendBlock(domain.Host{Name: "first", HostName: "10.0.0.7"}); err != nil {
		t.Fatal(err)
	}
	const other = "Host somebody-else\n  HostName 10.0.0.8\n"
	onSSHCall(t, func(n int) {
		if n == 1 {
			f.writeManaged(t, other)
		}
	})
	if _, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("first")); !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != other {
		t.Errorf("the other writer's file was replaced:\n%s", f.read(t))
	}
}

// An editor saves the file while sshm verifies its own write, and the
// verification then fails. The rollback must not put the old content over
// the editor's: the file stays as the editor left it and the error says so.
func TestSaveManaged_EditorWriteDuringVerificationIsNotRolledBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := setUser(t, f, "bob")
	written := string(d.Bytes())
	// The editor's version changes another host, which the plan does not
	// allow: verification fails and wants to roll back.
	edited := strings.Replace(written, "HostName 10.0.0.2", "HostName 10.0.0.99", 1) + "# the editor was here\n"
	if edited == written+"# the editor was here\n" {
		t.Fatal("fixture: nothing replaced")
	}
	injected := false
	onSSHCall(t, func(int) {
		if !injected && f.read(t) == written { // sshm's write is on disk: the after-phase
			injected = true
			f.writeManaged(t, edited)
		}
	})
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "User", "bob"))
	if !injected {
		t.Fatal("fixture: the editor never got its turn")
	}
	if !errors.Is(err, ErrNotRolledBack) {
		t.Fatalf("err = %v, want ErrNotRolledBack", err)
	}
	if strings.Contains(err.Error(), "file restored") {
		t.Errorf("the error claims a restore: %v", err)
	}
	if got := f.read(t); got != edited {
		t.Errorf("the rollback overwrote the editor's content:\n%s", got)
	}
	// What was there before the save is still available: in the backup.
	baks := f.backups(t)
	if len(baks) != 1 || !strings.Contains(err.Error(), baks[0]) {
		t.Fatalf("backups = %v, error = %v", baks, err)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != fixtureManaged {
		t.Errorf("backup content:\n%s", b)
	}
}

// The editor's save lands during verification and verification PASSES (its
// content is fine for ssh and for the plan). The save must not report
// success: the edit it was asked to make may not be in the file any more.
func TestSaveManaged_EditorWriteDuringVerificationIsNotASuccess(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := setUser(t, f, "bob")
	written := string(d.Bytes())
	edited := written + "# only a comment, added by the editor\n"
	injected := false
	onSSHCall(t, func(int) {
		if !injected && f.read(t) == written {
			injected = true
			f.writeManaged(t, edited)
		}
	})
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "User", "bob"))
	if !injected || !errors.Is(err, ErrConflict) || errors.Is(err, ErrNotRolledBack) {
		t.Fatalf("injected=%v err=%v, want ErrConflict", injected, err)
	}
	if f.read(t) != edited {
		t.Errorf("the editor's content was touched:\n%s", f.read(t))
	}
}

// A new file that somebody else rewrites during verification is not removed
// by the rollback either.
func TestSaveManaged_NewFileChangedDuringVerificationIsNotRemoved(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "")
	d := config.ParseDoc(nil)
	if err := d.AppendBlock(domain.Host{Name: "bad", KexAlgorithms: "no-such-kex-algorithm"}); err != nil {
		t.Fatal(err)
	}
	written := string(d.Bytes())
	const other = "Host somebody-else\n  HostName 10.0.0.8\n"
	injected := false
	onSSHCall(t, func(int) {
		if b, err := os.ReadFile(f.managed); !injected && err == nil && string(b) == written {
			injected = true
			// Still a config ssh refuses, so the save fails and wants to roll back.
			f.writeManaged(t, other+"  KexAlgorithms no-such-kex-algorithm\n")
		}
	})
	_, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("bad"))
	if !injected || !errors.Is(err, ErrNotRolledBack) {
		t.Fatalf("injected=%v err=%v", injected, err)
	}
	if !strings.HasPrefix(f.read(t), other) {
		t.Errorf("the other writer's file was removed or replaced")
	}
	if !strings.Contains(err.Error(), "there was no file before this save") {
		t.Errorf("error: %v", err)
	}
}

// Without interference the rollback still restores (the guard compares with
// what this save wrote, so it must not fire on sshm's own content).
func TestSaveManaged_RollbackStillRestoresItsOwnWrite(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := f.doc(t)
	if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, badWritePlan("web-1", "KexAlgorithms"))
	if err == nil || errors.Is(err, ErrNotRolledBack) || !strings.Contains(err.Error(), "file restored") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != fixtureManaged {
		t.Error("file not restored")
	}
}

// ---- Item 5: one lock for every path to the managed file ----

func TestManagedLockPathResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	realDir := filepath.Join(dir, "dotfiles", "ssh.d")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "sshm.conf")
	if err := os.WriteFile(realFile, []byte("Host a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// config.d is a symlink to the real directory...
	linkDir := filepath.Join(dir, "config.d")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	// ...and elsewhere a symlink points at the file itself.
	other := filepath.Join(dir, "elsewhere")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	linkFile := filepath.Join(other, "managed.conf")
	if err := os.Symlink(filepath.Join(linkDir, "sshm.conf"), linkFile); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(realDir, managedLockName)
	for _, p := range []string{realFile, filepath.Join(linkDir, "sshm.conf"), linkFile} {
		got, err := managedLockPath(p)
		if err != nil || got != want {
			t.Errorf("managedLockPath(%s) = %s, %v; want %s", p, got, err, want)
		}
	}
	// A file that does not exist yet locks in its (resolved) directory.
	if got, err := managedLockPath(filepath.Join(linkDir, "new.conf")); err != nil || got != want {
		t.Errorf("new file: %s, %v; want %s", got, err, want)
	}
}

// Two paths to one managed file exclude each other: a save through the
// symlinked config.d waits for (here: times out on) the lock a save through
// the real path holds.
func TestSaveManaged_SymlinkedConfigDirSharesTheLock(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "dotfiles", "ssh.d")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "sshm.conf")
	if err := os.WriteFile(realFile, []byte(fixtureManaged), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "config.d")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(linkDir, "sshm.conf")
	// A second way in: a symlink to the file itself, from another directory.
	// (This is the case that took a DIFFERENT lock file before P2c: the lock
	// was made next to the link. A symlinked directory alone always led to
	// the same lock file, through the directory link.)
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	viaFileLink := filepath.Join(elsewhere, "managed.conf")
	if err := os.Symlink(viaLink, viaFileLink); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "config")
	if err := os.WriteFile(main, []byte("Include "+viaLink+"\n"+fixtureMainTail), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewAppWithPath(main)

	// "Another sshm" works on the file through its real path.
	lock, err := managedLockPath(realFile)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := config.LockFile(lock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prev := managedLockTimeout
	managedLockTimeout = 150 * time.Millisecond
	t.Cleanup(func() { managedLockTimeout = prev })

	edit := func() (*config.Doc, verifyPlan) {
		raw, err := os.ReadFile(viaLink)
		if err != nil {
			t.Fatal(err)
		}
		d := config.ParseDoc(raw)
		if err := d.SetOption("web-1", "User", "bob"); err != nil {
			t.Fatal(err)
		}
		return d, setPlan("web-1", "User", "bob")
	}
	for _, p := range []string{viaLink, viaFileLink, realFile} {
		d, v := edit()
		if _, err := a.saveManagedDoc(p, d, v); !errors.Is(err, config.ErrLockTimeout) {
			t.Fatalf("a save through %s did not wait for the lock held through the real path: err = %v", p, err)
		}
		if b, _ := os.ReadFile(realFile); string(b) != fixtureManaged {
			t.Fatalf("the file was written through %s while the lock was held", p)
		}
	}
	if _, err := os.Stat(filepath.Join(elsewhere, managedLockName)); err == nil {
		t.Error("a second lock file was made next to the symlink")
	}
	unlock()

	requireSSH(t)
	d, v := edit()
	if _, err := a.saveManagedDoc(viaFileLink, d, v); err != nil {
		t.Fatalf("save after the lock was released: %v", err)
	}
	if fi, err := os.Lstat(viaFileLink); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the file symlink was replaced")
	}
	if b, _ := os.ReadFile(realFile); !strings.Contains(string(b), "User bob") {
		t.Error("the save did not reach the real file")
	}
	if fi, err := os.Lstat(linkDir); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("config.d is no longer a symlink")
	}
	// One lock file, next to the real file.
	if _, err := os.Stat(filepath.Join(realDir, managedLockName)); err != nil {
		t.Errorf("no lock file in the real directory: %v", err)
	}
}

// ---- Item 9: an Include below "Host *" or "Match all" ----

// ssh applies such an Include to every host (checked with the real ssh
// here), so a save into the managed file is accepted. What the block above
// sets first still wins: an edit it shadows is rolled back as "no effect".
func TestSaveManaged_IncludeBelowHostStarOrMatchAllIsAccepted(t *testing.T) {
	requireSSH(t)
	for name, mainBody := range map[string]string{
		"Host *":         "Host *\n  User fallback\n  Port 2200\n\nInclude %s\n",
		"Match all":      "Match all\n  User fallback\n  Port 2200\nInclude %s\n",
		"Host * later":   "Host first\n  User x\n\nHost *\n  User fallback\n  Port 2200\nInclude %s\n",
		"match ALL in =": "match=ALL # everything\n  User fallback\n  Port 2200\n  Include %s\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			f.writeMain(t, strings.Replace(mainBody, "%s", f.managed, 1))
			// ssh agrees: web-1 gets the managed block.
			if got := f.resolved(t, "web-1", "hostname"); got != "10.0.0.1" {
				t.Fatalf("fixture: ssh does not apply the Include (hostname %q)", got)
			}
			d := f.doc(t)
			if err := d.SetOption("web-1", "HostName", "10.0.0.42"); err != nil {
				t.Fatal(err)
			}
			if note, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "HostName", "10.0.0.42")); err != nil || note != "" {
				t.Fatalf("save refused: note=%q err=%v", note, err)
			}
			if got := f.resolved(t, "web-1", "hostname"); got != "10.0.0.42" {
				t.Errorf("hostname = %q", got)
			}
			// User is set by the block ABOVE the Include: first value wins.
			good := f.read(t)
			_, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
			if err == nil || !strings.Contains(err.Error(), "the change had no effect") {
				t.Fatalf("a shadowed edit passed: %v", err)
			}
			if f.read(t) != good {
				t.Error("file not restored")
			}
		})
	}
}

// ---- Item 8: host names that ssh would read as options ----

// captureExec replaces the process-replacing exec with a recorder.
func captureExec(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	prev := execReplace
	execReplace = func(binary string, argv []string, env []string) error {
		calls = append(calls, append([]string{filepath.Base(binary)}, argv...))
		return errors.New("exec captured by the test")
	}
	t.Cleanup(func() { execReplace = prev })
	return &calls
}

const optionNameFixture = `Host web-1
  HostName 10.0.0.1
  User alice

Host -oProxyCommand=evil
  HostName 10.0.0.2

Host -v
  HostName 10.0.0.3
`

// A name that starts with "-" never reaches the ssh command line, whether a
// Host block by that name exists (as in the fixture) or not, and whether it
// looks like user@host or not.
func TestConnectRefusesHostNamesThatLookLikeOptions(t *testing.T) {
	a := newTestApp(t, optionNameFixture)
	calls := captureExec(t)
	for _, name := range []string{"-oProxyCommand=evil", "-v", "-oProxyCommand=x", "-F/tmp/other", "-l@host", "--", "-"} {
		err := a.Connect(name, nil)
		if err == nil || !strings.Contains(err.Error(), "starts with '-'") {
			t.Errorf("Connect(%q) = %v, want a refusal", name, err)
		}
		err = a.Connect(name, []string{"-L", "8080:localhost:80"})
		if err == nil || !strings.Contains(err.Error(), "starts with '-'") {
			t.Errorf("Connect(%q, args) = %v, want a refusal", name, err)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("ssh was started: %q", *calls)
	}
}

func TestRunForwardRefusesHostNamesThatLookLikeOptions(t *testing.T) {
	a := newSetUpTestApp(t, optionNameFixture)
	before := configAfter(t, a)
	calls := captureExec(t)
	for _, save := range []bool{false, true} {
		for _, name := range []string{"-oProxyCommand=evil", "-v", "-oProxyCommand=x"} {
			err := a.RunForward(name, domain.ForwardLocal, []string{"8080:localhost:80"}, save)
			if err == nil || !strings.Contains(err.Error(), "starts with '-'") {
				t.Errorf("RunForward(%q, save=%v) = %v, want a refusal", name, save, err)
			}
		}
	}
	if len(*calls) != 0 {
		t.Errorf("ssh was started: %q", *calls)
	}
	if configAfter(t, a) != before {
		t.Error("a refused forward was saved")
	}
}

func TestCopyRefusesRemoteHostsThatLookLikeOptions(t *testing.T) {
	a := newTestApp(t, optionNameFixture)
	calls := captureExec(t)
	for _, c := range [][2]string{
		{"-oProxyCommand=evil:/tmp/x", "/tmp/y"},
		{"/tmp/y", "-v:/tmp/x"},
		{"/tmp/y", "-e@host:/tmp/x"},
	} {
		if err := a.Copy(c[0], c[1], "-a"); err == nil || !strings.Contains(err.Error(), "starts with '-'") {
			t.Errorf("Copy(%q, %q) = %v, want a refusal", c[0], c[1], err)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("rsync was started: %q", *calls)
	}
}

// The pass-through contract is untouched: `sshm <host> [ssh-args...]` puts
// the host first and the extra arguments after it, verbatim, with no "--"
// (which would stop ssh from reading them as options).
func TestConnectAndForwardPassArgumentsThrough(t *testing.T) {
	requireSSH(t)
	a := newTestApp(t, optionNameFixture)
	calls := captureExec(t)

	extra := []string{"-L", "10100:192.168.1.100:80", "-v", "--", "uptime"}
	if err := a.Connect("web-1", extra); err == nil || !strings.Contains(err.Error(), "exec captured") {
		t.Fatalf("Connect: %v", err)
	}
	if err := a.Connect("bob@adhoc.example.com", []string{"-p", "2222"}); err == nil || !strings.Contains(err.Error(), "exec captured") {
		t.Fatalf("ad-hoc Connect: %v", err)
	}
	if err := a.RunForward("web-1", domain.ForwardLocal, []string{"8080:localhost:80", "8081:localhost:81"}, false); err == nil || !strings.Contains(err.Error(), "exec captured") {
		t.Fatalf("RunForward: %v", err)
	}
	want := [][]string{
		{"ssh", "ssh", "web-1", "-L", "10100:192.168.1.100:80", "-v", "--", "uptime"},
		{"ssh", "ssh", "-i", domain.DefaultIdentityFile, "bob@adhoc.example.com", "-p", "2222"},
		{"ssh", "ssh", "-N", "-L", "8080:localhost:80", "-L", "8081:localhost:81", "web-1"},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Errorf("argv:\n got %q\nwant %q", *calls, want)
	}
}
