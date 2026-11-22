package tui

// Fixtures for the pre-P6 TUI tests after the move to managed mode
// (PLAN-p6.md T7). Temp dirs only; placeholders only; ssh never sees the real
// ~/.ssh.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

// newManagedTestModel writes cfg as the managed file (0600 in a 0700 config.d)
// and a main file whose only line is the absolute Include of it. It returns a
// Model over that config (editing on, since the snapshot is managed), the App
// and the path of the MANAGED file, which is where every edit lands.
func newManagedTestModel(t *testing.T, cfg string) (Model, *app.App, string) {
	t.Helper()
	dir := t.TempDir()
	managed := filepath.Join(dir, "config.d", "sshm.conf")
	if err := os.MkdirAll(filepath.Dir(managed), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, managed, cfg)
	writeFile(t, filepath.Join(dir, "config"), "Include "+managed+"\n")
	a := app.NewAppWithPath(filepath.Join(dir, "config"))
	return New(a), a, managed
}

// newLegacyTestModel is a Model over a legacy config: cfg is the main file and
// nothing includes a managed file, so editing is off.
func newLegacyTestModel(t *testing.T, cfg string) (Model, *app.App, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	writeFile(t, path, cfg)
	a := app.NewAppWithPath(path)
	return New(a), a, path
}
