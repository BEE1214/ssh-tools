package app

// P7 clause R2 (PLAN-p7.md): the refusal "the current ssh configuration is
// already broken" names the newest backup of the file. R1 (signals) needs the
// built binary and is tested in internal/cli/interrupt_test.go.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// irBrokenManaged is a managed file ssh rejects (unknown option).
const irBrokenManaged = mgManagedHeader + "\nHost web-1\n  HostName 10.0.0.1\n  NoSuchOptionX yes\n"

// irBackup writes a backup file named like config.BackupTo names them
// (<base>.<stamp>[-n]) into dir/sshm-backups, with an mtime that agrees with
// the stamp (a tie for the "-n" form).
func irBackup(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, "sshm-backups", name)
	mgWrite(t, p, "backup "+name+"\n", 0o600)
	m := regexp.MustCompile(`\.(\d{8}-\d{6}\.\d{6})(?:-\d+)?$`).FindStringSubmatch(name)
	if m == nil {
		t.Fatalf("fixture: %q is not named like a backup", name)
	}
	ts, err := time.Parse("20060102-150405.000000", m[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, ts, ts); err != nil {
		t.Fatal(err)
	}
	return p
}

// irRequireBroken checks that the fixture really is broken for ssh, so a
// "refused" result cannot come from anything else.
func irRequireBroken(t *testing.T, main string) {
	t.Helper()
	mgNeedSSH(t)
	if out, err := exec.Command(mgRealSSH, "-F", main, "-G", "some-host").CombinedOutput(); err == nil {
		t.Fatalf("fixture: ssh accepts the config:\n%s", out)
	}
}

var irHint = regexp.MustCompile(`\(newest backup of (.+?): (.+?)\)$`)

// R2: AddHost on a managed file ssh rejects: the refusal ends with the hint that
// names the managed file and its NEWEST backup.
func TestBrokenConfigRefusal_NamesNewestBackupOfManagedFile(t *testing.T) {
	e := nsNew(t, nsSetUpMain, irBrokenManaged)
	irRequireBroken(t, e.main)
	irBackup(t, e.dir, "sshm.conf.20240101-120000.000000")
	newest := irBackup(t, e.dir, "sshm.conf.20240303-090000.000000-1")
	irBackup(t, e.dir, "sshm.conf.20240303-090000.000000")
	irBackup(t, e.dir, "sshm.conf.20230505-000000.000000")
	irBackup(t, e.dir, "config.20991231-235959.000000") // a newer backup of ANOTHER file
	before := nsSnap(t, e.dir)

	err := e.a.AddHost(domain.Host{Name: "new-1", HostName: "10.9.9.9"})
	if err == nil {
		t.Fatal("AddHost succeeded on a broken config")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not writing "+e.managed+": the current ssh configuration is already broken: ") {
		t.Fatalf("the refusal changed: %q", msg)
	}
	wantSuffix := "(newest backup of " + e.managed + ": " + newest + ")"
	if !strings.HasSuffix(msg, wantSuffix) {
		t.Errorf("the refusal does not end with %q:\n%s", wantSuffix, msg)
	}
	if n := strings.Count(msg, "newest backup"); n != 1 {
		t.Errorf("the hint appears %d times, want once", n)
	}
	nsRequireSameExceptLock(t, before, nsSnap(t, e.dir))
}

// R2: without a backup of that file the text is unchanged: it is exactly the
// refusal of a fixture without any backup, plus nothing. Compared on two
// fixtures (paths normalized): one without backups, one whose backup dir only
// holds backups of another file. Both must read alike; a third, with a backup,
// must be the same text plus the hint.
func TestBrokenConfigRefusal_TextUnchangedWithoutBackupOfThatFile(t *testing.T) {
	refusal := func(prep func(e *mgEnv)) (string, *mgEnv) {
		e := nsNew(t, nsSetUpMain, irBrokenManaged)
		irRequireBroken(t, e.main)
		prep(e)
		err := e.a.AddHost(domain.Host{Name: "new-1", HostName: "10.9.9.9"})
		if err == nil {
			t.Fatal("AddHost succeeded on a broken config")
		}
		if errors.Is(err, ErrNotImplemented) {
			t.Fatal("ErrNotImplemented")
		}
		return strings.ReplaceAll(err.Error(), e.dir, "<D>"), e
	}
	plain, _ := refusal(func(e *mgEnv) {})
	if !strings.Contains(plain, "<D>/config.d/sshm.conf: the current ssh configuration is already broken: ") {
		t.Fatalf("unexpected refusal: %q", plain)
	}
	if strings.Contains(plain, "newest backup") {
		t.Errorf("a hint although there is no backup: %q", plain)
	}
	other, _ := refusal(func(e *mgEnv) { irBackup(t, e.dir, "config.20240101-120000.000000") })
	if other != plain {
		t.Errorf("backups of another file changed the text:\n%q\nvs\n%q", other, plain)
	}
	with, _ := refusal(func(e *mgEnv) { irBackup(t, e.dir, "sshm.conf.20240101-120000.000000") })
	rest, ok := strings.CutPrefix(with, plain)
	if !ok {
		t.Fatalf("with a backup the refusal is not the old text plus a hint:\n%q\nvs\n%q", with, plain)
	}
	want := "(newest backup of <D>/config.d/sshm.conf: <D>/sshm-backups/sshm.conf.20240101-120000.000000)"
	if strings.TrimSpace(rest) != want {
		t.Errorf("appended text = %q, want %q", strings.TrimSpace(rest), want)
	}
}

// R2, other operations of the managed save: the hint is on every refusal of a
// save, not only AddHost.
func TestBrokenConfigRefusal_OtherManagedWrites(t *testing.T) {
	calls := map[string]func(a *App) error{
		"EditHost":      func(a *App) error { return a.EditHost("web-1", map[string]string{"user": "x"}) },
		"DeleteHost":    func(a *App) error { return a.DeleteHost("web-1") },
		"DuplicateHost": func(a *App) error { return a.DuplicateHost("web-1", "web-2") },
		"AddForward": func(a *App) error {
			return a.AddForward("web-1", domain.ForwardLocal, []string{"8080:localhost:80"})
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			e := nsNew(t, nsSetUpMain, irBrokenManaged)
			irRequireBroken(t, e.main)
			newest := irBackup(t, e.dir, "sshm.conf.20240303-090000.000000")
			irBackup(t, e.dir, "sshm.conf.20240101-090000.000000")
			err := call(e.a)
			if err == nil || !strings.Contains(err.Error(), "already broken") {
				t.Fatalf("got %v, want the 'already broken' refusal", err)
			}
			want := "(newest backup of " + e.managed + ": " + newest + ")"
			if !strings.HasSuffix(err.Error(), want) {
				t.Errorf("does not end with %q:\n%s", want, err)
			}
		})
	}
}

// R2, setup form: the main file is what setup rewrites, so it is the file whose
// newest backup is named.
func TestBrokenConfigRefusal_SetupForm(t *testing.T) {
	e := nsNew(t, "Host web-1\n  HostName 10.0.0.1\n  NoSuchOptionX yes\n", mgAbsent)
	irRequireBroken(t, e.main)
	irBackup(t, e.dir, "config.20240101-120000.000000")
	newest := irBackup(t, e.dir, "config.20240404-120000.000000")
	before := nsSnap(t, e.dir)

	_, err := e.a.Setup(SetupOptions{})
	if err == nil || !strings.Contains(err.Error(), "the current ssh configuration is already broken: ") {
		t.Fatalf("Setup = %v, want the 'already broken' refusal", err)
	}
	want := "(newest backup of " + e.main + ": " + newest + ")"
	if !strings.HasSuffix(err.Error(), want) {
		t.Errorf("does not end with %q:\n%s", want, err)
	}
	nsRequireSameExceptLock(t, before, nsSnap(t, e.dir))
}

func TestBrokenConfigRefusal_SetupFormWithoutBackupIsUnchanged(t *testing.T) {
	e := nsNew(t, "Host web-1\n  HostName 10.0.0.1\n  NoSuchOptionX yes\n", mgAbsent)
	irRequireBroken(t, e.main)
	_, err := e.a.Setup(SetupOptions{})
	if err == nil || !strings.Contains(err.Error(), "not setting up: the current ssh configuration is already broken: ") {
		t.Fatalf("Setup = %v, want the 'already broken' refusal", err)
	}
	if strings.Contains(err.Error(), "newest backup") {
		t.Errorf("a hint although there is no backup: %v", err)
	}
}

// R2, import form: the import writes the main and the managed file; the hint
// names one of them with ITS newest backup (the spec does not say which).
func TestBrokenConfigRefusal_ImportForm(t *testing.T) {
	e := nsNew(t, "Include @M@\n\nHost imp-1\n  HostName 10.0.0.5\n  NoSuchOptionX yes\n", mgManagedHeader)
	irRequireBroken(t, e.main)
	irBackup(t, e.dir, "config.20240101-120000.000000")
	mainNewest := irBackup(t, e.dir, "config.20240202-120000.000000")
	irBackup(t, e.dir, "sshm.conf.20240101-120000.000000")
	managedNewest := irBackup(t, e.dir, "sshm.conf.20240303-120000.000000")
	before := nsSnap(t, e.dir)

	_, err := e.a.Import(ImportOptions{Apply: true})
	if err == nil || !strings.Contains(err.Error(), "the current ssh configuration is already broken: ") {
		t.Fatalf("Import = %v, want the 'already broken' refusal", err)
	}
	m := irHint.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("the refusal does not end with a '(newest backup of <file>: <path>)' hint:\n%s", err)
	}
	switch m[1] {
	case e.main:
		if m[2] != mainNewest {
			t.Errorf("newest backup of the main file = %q, want %q", m[2], mainNewest)
		}
	case e.managed:
		if m[2] != managedNewest {
			t.Errorf("newest backup of the managed file = %q, want %q", m[2], managedNewest)
		}
	default:
		t.Errorf("the hint names %q, want the main or the managed file", m[1])
	}
	nsRequireSameExceptLock(t, before, nsSnap(t, e.dir))
}
