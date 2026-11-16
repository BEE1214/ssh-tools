package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

// includeModel builds a model over a main config that Includes a second file
// (absolute temp paths only). Hosts: web-1 (main), inc-1 and inc-2 (included).
func includeModel(t *testing.T) (Model, string, string) {
	t.Helper()
	dir := t.TempDir()
	incPath := filepath.Join(dir, "extra.conf")
	writeFile(t, incPath, "Host inc-1\n  HostName 10.0.1.1\n  User ia\n\nHost inc-2\n  HostName 10.0.1.2\n")
	mainPath := filepath.Join(dir, "config")
	writeFile(t, mainPath, "Include "+incPath+"\n\nHost web-1\n  HostName 10.0.0.1\n  User admin\n")
	m := New(app.NewAppWithPath(mainPath))
	return m, mainPath, incPath
}

func TestIncludedHostsAreTagged(t *testing.T) {
	m, _, _ := includeModel(t)
	m, _ = press(m, "/")
	m = typeText(m, "inc-")
	m, _ = press(m, "enter")
	v := plain(m)
	for _, name := range []string{"inc-1", "inc-2"} {
		line := lineWith(v, name)
		if !strings.Contains(line, "[included]") {
			t.Errorf("%s line lacks [included]: %q", name, line)
		}
	}

	m, _ = press(m, "esc")
	m, _ = press(m, "/")
	m = typeText(m, "web-1")
	m, _ = press(m, "enter")
	if line := lineWith(plain(m), "web-1"); strings.Contains(line, "[included]") {
		t.Errorf("main-file host tagged [included]: %q", line)
	}
}

func lineWith(view, needle string) string {
	for _, l := range strings.Split(view, "\n") {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// Connect stays allowed for an included host (it is not gated).
func TestIncludedHostCanBeConnected(t *testing.T) {
	m, _, _ := includeModel(t)
	m = onHost(m, "inc-1")
	m, cmd := press(m, "enter")
	if m.Selected() != "inc-1" || !isQuit(cmd) {
		t.Fatalf("selected=%q quit=%v", m.Selected(), isQuit(cmd))
	}
}

// managedIncludeModel is includeModel in managed mode: the main file Includes
// the managed file (host web-1) and extra.conf (inc-1, inc-2).
func managedIncludeModel(t *testing.T) (Model, string, string) {
	t.Helper()
	dir := t.TempDir()
	incPath := filepath.Join(dir, "extra.conf")
	writeFile(t, incPath, "Host inc-1\n  HostName 10.0.1.1\n  User ia\n\nHost inc-2\n  HostName 10.0.1.2\n")
	managed := filepath.Join(dir, "config.d", "sshm.conf")
	if err := os.MkdirAll(filepath.Dir(managed), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, managed, "Host web-1\n  HostName 10.0.0.1\n  User admin\n")
	mainPath := filepath.Join(dir, "config")
	writeFile(t, mainPath, "Include "+managed+"\nInclude "+incPath+"\n")
	return New(app.NewAppWithPath(mainPath)), mainPath, incPath
}

// Legacy mode (T8, was: "with the editor off as in Run"): the edit keys do
// nothing, also on included hosts, show the setup toast, and no file is touched.
func TestIncludedHostEditKeysStayDisabled(t *testing.T) {
	m, mainPath, incPath := includeModel(t)
	mainBefore, incBefore := readFile(t, mainPath), readFile(t, incPath)
	want := "editing needs setup: run 'sshm setup' to create " + filepath.Join(filepath.Dir(mainPath), "config.d", "sshm.conf")
	m = onHost(m, "inc-1")
	for _, key := range []string{"e", "n", "d", "D"} {
		m, _ = press(m, key)
		if m.mode != modeList || !m.toastErr || m.toast != want {
			t.Fatalf("key %q: mode=%v toast=%q, want %q", key, m.mode, m.toast, want)
		}
	}
	if readFile(t, mainPath) != mainBefore || readFile(t, incPath) != incBefore {
		t.Fatal("a file changed although editing is disabled")
	}
}

// In managed mode e/d/D on an included host are refused with the app layer's
// message (naming the included file) and never reach the writer.
func TestIncludedHostGatedForEditDeleteDuplicate(t *testing.T) {
	m, mainPath, incPath := managedIncludeModel(t)
	mainBefore, incBefore := readFile(t, mainPath), readFile(t, incPath)
	entries, _ := os.ReadDir(filepath.Dir(mainPath))

	m = onHost(m, "inc-1")
	for _, key := range []string{"e", "d", "D"} {
		m, _ = press(m, key)
		if m.mode != modeList {
			t.Fatalf("key %q opened mode %v on an included host", key, m.mode)
		}
		if !m.toastErr || !strings.Contains(m.toast, "(included)") || !strings.Contains(m.toast, incPath) {
			t.Fatalf("key %q: toast %q", key, m.toast)
		}
	}
	if readFile(t, mainPath) != mainBefore || readFile(t, incPath) != incBefore {
		t.Fatal("a file changed")
	}
	if after, _ := os.ReadDir(filepath.Dir(mainPath)); len(after) != len(entries) {
		t.Fatalf("directory entries changed: %d -> %d", len(entries), len(after))
	}

	// A host of the managed file is still editable in the same model.
	m = onHost(m, "web-1")
	m, _ = press(m, "e")
	if m.mode != modeEditor {
		t.Fatalf("e on a main-file host: mode=%v toast=%q", m.mode, m.toast)
	}
}

func TestIncludeWarningsCountInStatusBar(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "config")
	writeFile(t, mainPath, "Include /example/%h.conf\n\nHost web-1\n  HostName 10.0.0.1\n  IdentityFile /example/id\n")
	m := New(app.NewAppWithPath(mainPath))
	if got := plain(m); !strings.Contains(got, "1 warning") {
		t.Fatalf("status bar lacks the include warning:\n%s", got)
	}
}
