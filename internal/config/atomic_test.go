package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readStr(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func noLeftovers(t *testing.T, dir string, want ...string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s contains %v, want %v (temp file left behind?)", dir, got, want)
	}
}

func TestAtomicWrite_PreservesModeAndCreates0600(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	if err := AtomicWrite(p, []byte("a\n")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("new file mode = %o, want 0600", fi.Mode().Perm())
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(p, []byte("b\n")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 || readStr(t, p) != "b\n" {
		t.Errorf("mode = %o content = %q; AtomicWrite must preserve the existing mode", fi.Mode().Perm(), readStr(t, p))
	}
	noLeftovers(t, dir, "config")
}

func TestAtomicWriteMode_ForcesMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "managed.conf")
	if err := os.WriteFile(p, []byte("old\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o664); err != nil { // beat the umask
		t.Fatal(err)
	}
	if err := AtomicWriteMode(p, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 || readStr(t, p) != "new\n" {
		t.Errorf("mode = %o, content = %q", fi.Mode().Perm(), readStr(t, p))
	}
	noLeftovers(t, dir, "managed.conf")
}

// A dotfiles-managed ~/.ssh/config is a symlink: both writers must update the
// file it points to and leave the link alone.
func TestAtomicWrite_WritesThroughSymlinks(t *testing.T) {
	for name, write := range map[string]func(string, []byte) error{
		"AtomicWrite":     AtomicWrite,
		"AtomicWriteMode": func(p string, b []byte) error { return AtomicWriteMode(p, b, 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			real := filepath.Join(dir, "dotfiles", "config")
			if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(real, []byte("old\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			mid := filepath.Join(dir, "mid")
			link := filepath.Join(dir, "ssh", "config")
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			// link -> ../mid (relative) -> real: a chain with a relative hop.
			if err := os.Symlink(real, mid); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join("..", "mid"), link); err != nil {
				t.Fatal(err)
			}

			if err := write(link, []byte("new\n")); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{link, mid} {
				if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Errorf("%s is no longer a symlink: %v %v", p, fi, err)
				}
			}
			if readStr(t, real) != "new\n" {
				t.Errorf("target = %q", readStr(t, real))
			}
			noLeftovers(t, filepath.Dir(real), "config")
			noLeftovers(t, filepath.Dir(link), "config")
		})
	}
}

func TestAtomicWrite_DanglingSymlinkCreatesTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "dotfiles", "config")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "config")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteMode(link, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 || readStr(t, real) != "x\n" {
		t.Error("dangling link not written through")
	}
}

func TestAtomicWrite_FailureLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	// The target is a non-empty directory: the final rename must fail.
	p := filepath.Join(dir, "config")
	if err := os.MkdirAll(filepath.Join(p, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(p, []byte("x")); err == nil {
		t.Fatal("expected an error")
	}
	noLeftovers(t, dir, "config")
}

func TestBackupTo(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "config.d", "sshm.conf")
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bdir := filepath.Join(dir, "sshm-backups")

	seen := map[string]bool{}
	for i := 0; i < 5; i++ { // same instant is possible: names must not collide
		bak, err := BackupTo(src, bdir)
		if err != nil {
			t.Fatal(err)
		}
		if seen[bak] {
			t.Fatalf("backup %s overwritten", bak)
		}
		seen[bak] = true
		if filepath.Dir(bak) != bdir || !strings.HasPrefix(filepath.Base(bak), "sshm.conf.") {
			t.Errorf("backup path %s", bak)
		}
		if readStr(t, bak) != "content\n" {
			t.Errorf("backup content")
		}
		if fi, _ := os.Stat(bak); fi.Mode().Perm() != 0o600 {
			t.Errorf("backup mode %o", fi.Mode().Perm())
		}
	}
	if fi, _ := os.Stat(bdir); fi.Mode().Perm() != 0o700 {
		t.Errorf("backup dir mode %o", fi.Mode().Perm())
	}
	if _, err := BackupTo(filepath.Join(dir, "missing"), bdir); err == nil {
		t.Error("backup of a missing file must fail")
	}
}
