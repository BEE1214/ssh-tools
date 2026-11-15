package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// managedFixture is a main config that Includes (by absolute path) a managed
// file, all in a temp dir. Nothing here touches the real ~/.ssh: ssh is always
// called with -F <temp main file> and every Include path is absolute.
type managedFixture struct {
	dir, main, managed string
	a                  *App
}

const fixtureManaged = `# sshm managed
Host web-1
  HostName 10.0.0.1
  User alice
  Port 2222
  IdentityFile /keys/web1_a
  IdentityFile /keys/web1_b

Host web-*
  ServerAliveInterval 40

Host db-1
  HostName 10.0.0.2
`

const fixtureMainTail = `
Host main-1
  HostName 10.0.0.9
  User mainuser

Host *
  User fallback
  Port 2200
`

func requireSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}
}

func newManagedFixture(t *testing.T, managedBody string) *managedFixture {
	t.Helper()
	dir := t.TempDir()
	f := &managedFixture{
		dir:     dir,
		main:    filepath.Join(dir, "config"),
		managed: filepath.Join(dir, "config.d", "sshm.conf"),
	}
	if err := os.MkdirAll(filepath.Dir(f.managed), 0o700); err != nil {
		t.Fatal(err)
	}
	if managedBody != "" {
		f.writeManaged(t, managedBody)
	}
	f.writeMain(t, "Include "+f.managed+"\n"+fixtureMainTail)
	f.a = NewAppWithPath(f.main)
	return f
}

func (f *managedFixture) writeManaged(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(f.managed, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *managedFixture) writeMain(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(f.main, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *managedFixture) read(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.managed)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (f *managedFixture) mode(t *testing.T) os.FileMode {
	t.Helper()
	fi, err := os.Stat(f.managed)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func (f *managedFixture) backups(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(f.dir, "sshm-backups"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, filepath.Join(f.dir, "sshm-backups", e.Name()))
	}
	return out
}

// resolved returns one option line of `ssh -G host`.
func (f *managedFixture) resolved(t *testing.T, host, key string) string {
	t.Helper()
	out, err := f.a.sshG(host)
	if err != nil {
		t.Fatal(err)
	}
	var vals []string
	for _, l := range strings.Split(out, "\n") {
		if k, v, _ := strings.Cut(l, " "); k == key {
			vals = append(vals, v)
		}
	}
	return strings.Join(vals, ",")
}

func (f *managedFixture) doc(t *testing.T) *config.Doc {
	t.Helper()
	return config.ParseDoc([]byte(f.read(t)))
}

func TestSaveManaged_EditPassesSemanticCheck(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	orig := f.read(t)
	if got := f.resolved(t, "web-1", "user"); got != "alice" {
		t.Fatalf("fixture: user = %q", got)
	}

	d := f.doc(t)
	if err := d.SetOption("web-1", "User", "bob"); err != nil {
		t.Fatal(err)
	}
	note, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "User", "bob"))
	if err != nil || note != "" {
		t.Fatalf("save: note=%q err=%v", note, err)
	}
	if got := f.read(t); got != strings.Replace(orig, "User alice", "User bob", 1) {
		t.Errorf("file content:\n%s", got)
	}
	if got := f.resolved(t, "web-1", "user"); got != "bob" {
		t.Errorf("ssh -G user = %q, want bob", got)
	}
	if got := f.resolved(t, "web-1", "identityfile"); got != "/keys/web1_a,/keys/web1_b" {
		t.Errorf("repeated IdentityFile lost: %q", got)
	}
	if m := f.mode(t); m != 0o600 {
		t.Errorf("mode = %o, want 0600", m)
	}

	// The backup holds the previous content, mode 0600, in a 0700 dir.
	baks := f.backups(t)
	if len(baks) != 1 {
		t.Fatalf("backups = %v, want 1", baks)
	}
	if b, _ := os.ReadFile(baks[0]); string(b) != orig {
		t.Errorf("backup content differs from the original")
	}
	if fi, _ := os.Stat(baks[0]); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %o", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(baks[0])); fi.Mode().Perm() != 0o700 {
		t.Errorf("backup dir mode = %o", fi.Mode().Perm())
	}
	if !strings.HasPrefix(filepath.Base(baks[0]), "sshm.conf.") {
		t.Errorf("backup name = %s", filepath.Base(baks[0]))
	}
}

func TestSaveManaged_EachOperationVerifies(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)

	steps := []struct {
		name string
		do   func(d *config.Doc) error
		plan verifyPlan
		want func() bool
	}{
		{"add identity", func(d *config.Doc) error { return d.AddOptionValue("web-1", "IdentityFile", "/keys/web1_c") },
			addValuePlan("web-1", "IdentityFile", "/keys/web1_c"), func() bool { return f.resolved(t, "web-1", "identityfile") == "/keys/web1_a,/keys/web1_b,/keys/web1_c" }},
		{"unset port", func(d *config.Doc) error { return d.UnsetOption("web-1", "Port") },
			editPlan("web-1", "port"), func() bool { return f.resolved(t, "web-1", "port") == "2200" }}, // falls through to Host *
		{"append", func(d *config.Doc) error {
			return d.AppendBlock(domain.Host{Name: "new-1", HostName: "10.0.0.50", Port: "22"})
		},
			anyChangePlan("new-1"), func() bool { return f.resolved(t, "new-1", "port") == "22" }}, // explicit Port 22 beats Host * Port 2200
		{"duplicate", func(d *config.Doc) error { return d.DuplicateBlock("db-1", "db-2") },
			anyChangePlan("db-2"), func() bool { return f.resolved(t, "db-2", "hostname") == "10.0.0.2" }},
		{"disable", func(d *config.Doc) error { return d.DisableBlocks([]string{"db-1", "db-2"}, "db") },
			anyChangePlan("db-1", "db-2"), func() bool { return f.resolved(t, "db-1", "hostname") == "db-1" }},
		{"enable", func(d *config.Doc) error { return d.EnableGroup("db") },
			anyChangePlan("db-1", "db-2"), func() bool { return f.resolved(t, "db-1", "hostname") == "10.0.0.2" }},
		{"delete", func(d *config.Doc) error { return d.DeleteBlock("db-2") },
			anyChangePlan("db-2"), func() bool { return f.resolved(t, "db-2", "hostname") == "db-2" }},
	}
	for _, s := range steps {
		d := f.doc(t)
		if err := s.do(d); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if note, err := f.a.saveManagedDoc(f.managed, d, s.plan); err != nil || note != "" {
			t.Fatalf("%s: note=%q err=%v", s.name, note, err)
		}
		if !s.want() {
			t.Errorf("%s: unexpected resolution after save:\n%s", s.name, f.read(t))
		}
	}
}

func TestSaveManaged_InvalidOptionRollsBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	orig := f.read(t)

	d := f.doc(t)
	if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "kexalgorithms"))
	if err == nil {
		t.Fatal("an invalid KexAlgorithms was saved")
	}
	for _, want := range []string{"rolled back", "ssh -G", "KexAlgorithms"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if got := f.read(t); got != orig {
		t.Errorf("file not restored byte-for-byte:\n%s", got)
	}
	if m := f.mode(t); m != 0o600 {
		t.Errorf("mode after rollback = %o", m)
	}
	// ssh works again.
	if got := f.resolved(t, "web-1", "user"); got != "alice" {
		t.Errorf("config still broken after rollback: user = %q", got)
	}
}

// A change that is valid for ssh but alters a host the caller did not declare
// (here: a new "Host db-*" appended AFTER db-1 would still feed db-1 its
// ServerAliveInterval) is detected and rolled back.
func TestSaveManaged_UndeclaredHostChangeRollsBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	orig := f.read(t)

	d := f.doc(t)
	if err := d.AppendBlock(domain.Host{Name: "db-*", User: "wildcard-user"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("db-*"))
	if err == nil {
		t.Fatal("db-1 resolved differently but the save was accepted")
	}
	for _, want := range []string{"rolled back", "ssh -G db-1", "must not change", "- user fallback", "+ user wildcard-user"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
	if f.read(t) != orig {
		t.Error("file not restored")
	}
}

// An edit of a host may differ only in the declared keys.
func TestSaveManaged_ChangeOutsideDeclaredKeysRollsBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	orig := f.read(t)

	d := f.doc(t)
	if err := d.SetOption("web-1", "Port", "2230"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "user")) // claims only "user"
	if err == nil || !strings.Contains(err.Error(), "changed beyond the edited options") ||
		!strings.Contains(err.Error(), "+ port 2230") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != orig {
		t.Error("file not restored")
	}
}

// Precedence: a SetOption on the wildcard block reaches hosts that never
// mention it. Declaring only the wildcard as changed is caught.
func TestSaveManaged_PrecedenceChangeDetected(t *testing.T) {
	requireSSH(t)
	// web-2 has no User of its own: it inherits the one set on "Host web-*".
	f := newManagedFixture(t, fixtureManaged+"\nHost web-2\n  HostName 10.0.0.3\n")
	orig := f.read(t)

	d := f.doc(t)
	if err := d.SetOption("web-*", "User", "shared"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-*", "user"))
	if err == nil || !strings.Contains(err.Error(), "ssh -G web-2") || !strings.Contains(err.Error(), "+ user shared") {
		t.Fatalf("web-2 inherits the new User but the save was accepted: %v", err)
	}
	if f.read(t) != orig {
		t.Error("file not restored")
	}

	// Declaring the affected host makes the same edit acceptable.
	plan := editPlan("web-*", "user")
	plan.changed["web-2"] = true
	plan.keys["web-2"] = map[string]bool{"user": true}
	if _, err := f.a.saveManagedDoc(f.managed, d, plan); err != nil {
		t.Fatalf("declared change rejected: %v", err)
	}
	if got := f.resolved(t, "web-2", "user"); got != "shared" {
		t.Errorf("user = %q", got)
	}
}

func TestSaveManaged_PermissionsForcedTo0600(t *testing.T) {
	requireSSH(t)
	for name, mode := range map[string]os.FileMode{"group-writable": 0o664, "world-readable": 0o644} {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			if err := os.Chmod(f.managed, mode); err != nil {
				t.Fatal(err)
			}
			d := f.doc(t)
			if err := d.SetOption("web-1", "User", "bob"); err != nil {
				t.Fatal(err)
			}
			note, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "user"))
			if err != nil {
				t.Fatalf("save: %v", err)
			}
			if m := f.mode(t); m != 0o600 {
				t.Errorf("mode = %o, want 0600", m)
			}
			// ssh itself refuses a group-writable include; the save repairs
			// that first and says so.
			if mode&0o022 != 0 && !strings.Contains(note, "permissions") {
				t.Errorf("note = %q, want a permissions note", note)
			}
			if mode&0o022 == 0 && note != "" {
				t.Errorf("note = %q for an acceptable mode", note)
			}
			if got := f.resolved(t, "web-1", "user"); got != "bob" {
				t.Errorf("user = %q", got)
			}
		})
	}
}

func TestSaveManaged_SymlinkedManagedFileStaysSymlink(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "")
	real := filepath.Join(f.dir, "dotfiles", "sshm.conf")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte(fixtureManaged), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, f.managed); err != nil {
		t.Fatal(err)
	}

	d := f.doc(t)
	if err := d.SetOption("web-1", "User", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "user")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(f.managed); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced by a regular file: %v %v", fi, err)
	}
	if dest, _ := os.Readlink(f.managed); dest != real {
		t.Errorf("link now points to %q", dest)
	}
	if b, _ := os.ReadFile(real); !strings.Contains(string(b), "User bob") {
		t.Errorf("target not updated:\n%s", b)
	}

	// A rolled-back save restores the target and keeps the link as well.
	before, _ := os.ReadFile(real)
	d = f.doc(t)
	if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "kexalgorithms")); err == nil {
		t.Fatal("invalid option accepted")
	}
	if after, _ := os.ReadFile(real); string(after) != string(before) {
		t.Error("target not restored")
	}
	if fi, _ := os.Lstat(f.managed); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("rollback replaced the symlink")
	}
}

func TestSaveManaged_NewFile(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "")

	// Success: created 0600, no backup (nothing existed).
	d := config.ParseDoc(nil)
	if err := d.AppendBlock(domain.Host{Name: "first", HostName: "10.0.0.7", User: "u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("first")); err != nil {
		t.Fatal(err)
	}
	if f.mode(t) != 0o600 || len(f.backups(t)) != 0 {
		t.Errorf("mode=%o backups=%v", f.mode(t), f.backups(t))
	}
	if got := f.resolved(t, "first", "hostname"); got != "10.0.0.7" {
		t.Errorf("hostname = %q", got)
	}

	// Rollback: the brand-new file is removed again.
	if err := os.Remove(f.managed); err != nil {
		t.Fatal(err)
	}
	d = config.ParseDoc(nil)
	if err := d.AppendBlock(domain.Host{Name: "bad", KexAlgorithms: "no-such-kex-algorithm"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("bad"))
	if err == nil || !strings.Contains(err.Error(), "KexAlgorithms") || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(f.managed); !os.IsNotExist(serr) {
		t.Errorf("new file left behind after rollback: %v", serr)
	}
	// No stray temp files either: only the lock file stays.
	ents, _ := os.ReadDir(filepath.Dir(f.managed))
	for _, e := range ents {
		if e.Name() != managedLockName {
			t.Errorf("leftover in config.d: %s", e.Name())
		}
	}
}

func TestSaveManaged_AlreadyBrokenConfigIsNotWritten(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	f.writeMain(t, "Include "+f.managed+"\n\nHost *\n  KexAlgorithms no-such-kex-algorithm\n")
	orig := f.read(t)

	d := f.doc(t)
	if err := d.SetOption("web-1", "User", "bob"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "user"))
	if err == nil || !strings.Contains(err.Error(), "already broken") || !strings.Contains(err.Error(), "KexAlgorithms") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != orig || len(f.backups(t)) != 0 {
		t.Error("a broken configuration must not be written to")
	}
}

func TestSaveManaged_MatchExecSkipsVerification(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	marker := filepath.Join(f.dir, "exec-ran")
	// A Match exec in the MAIN file: ssh -G would run `touch marker`.
	f.writeMain(t, "Include "+f.managed+"\n\nMatch exec \"touch "+marker+"\"\n  Compression no\n"+fixtureMainTail)

	d := f.doc(t)
	if err := d.SetOption("web-1", "User", "bob"); err != nil {
		t.Fatal(err)
	}
	note, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "user"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "verification skipped") || !strings.Contains(note, "exec") || !strings.Contains(note, f.main) {
		t.Errorf("note = %q", note)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("the Match exec command was run")
	}
	if !strings.Contains(f.read(t), "User bob") {
		t.Error("file was not written")
	}

	// Same when the Match exec is in the new managed content itself.
	f.writeMain(t, "Include "+f.managed+"\n"+fixtureMainTail)
	d = f.doc(t)
	d.Lines = append(d.Lines, "", "Match exec \"touch "+marker+"\"", "  Compression no")
	note, err = f.a.saveManagedDoc(f.managed, d, anyChangePlan())
	if err != nil || !strings.Contains(note, "verification skipped") {
		t.Fatalf("note=%q err=%v", note, err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("the Match exec command was run")
	}
}

func TestSaveManaged_MissingSSHSkipsVerification(t *testing.T) {
	f := newManagedFixture(t, fixtureManaged)
	t.Setenv("PATH", t.TempDir()) // an empty dir: no ssh

	d := f.doc(t)
	if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil { // would be rolled back with ssh
		t.Fatal(err)
	}
	note, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "kexalgorithms"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "verification skipped") || !strings.Contains(note, "ssh not found") {
		t.Errorf("note = %q", note)
	}
	if !strings.Contains(f.read(t), "no-such-kex-algorithm") || f.mode(t) != 0o600 {
		t.Error("file not written with mode 0600")
	}
}

func TestSaveManaged_BackupsDoNotOverwriteEachOther(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	for _, u := range []string{"u1", "u2", "u3"} {
		d := f.doc(t)
		if err := d.SetOption("web-1", "User", u); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.saveManagedDoc(f.managed, d, editPlan("web-1", "user")); err != nil {
			t.Fatal(err)
		}
	}
	if baks := f.backups(t); len(baks) != 3 {
		t.Errorf("backups = %v, want 3", baks)
	}
}
