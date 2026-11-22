package tui

// W1 (PR #8 review): hosts whose `Host` line has an inline comment
// (`Host web-9 # prod box`) must work in the TUI exactly like plain hosts:
// edit, duplicate, delete, the read-only toast and Enter-to-connect all use the
// name a user types (web-9), never the raw line text.
//
// Fixtures: temp dirs only (tmNewEnv of managed_helpers_test.go); ssh is only
// called with -F <temp main>. Hosts and addresses are placeholders.

import (
	"strings"
	"testing"
)

const hkMainBody = `Include @M@

Host main-9 # legacy note
  HostName 10.0.0.19
  User mainuser
  IdentityFile /keys/main9
`

const hkManagedBody = `# Managed by sshm. Hosts in this file are edited by sshm.

# the commented one
Host web-9 # prod box
  # the web node
  HostName 10.0.0.91
  User alice
  Port 2222
  IdentityFile /keys/web9

Host plain-9
  HostName 10.0.0.92
  User bob
  IdentityFile /keys/plain9
`

func hkModel(t *testing.T) (Model, *tmEnv) {
	t.Helper()
	e := tmNewEnv(t, hkMainBody, hkManagedBody)
	return tmModel(e), e
}

// hkExpand expands every group and puts the cursor on name, failing when the
// host has no row under that name (a raw name would not).
func hkOn(t *testing.T, m Model, name string) Model {
	t.Helper()
	m = tmExpandAll(m)
	m = onHost(m, name)
	if got := curKey(m); got != "h:"+name {
		var names []string
		for _, h := range m.hosts {
			names = append(names, h.Name)
		}
		t.Fatalf("cursor on %q, want h:%s; host names: %q", got, name, names)
	}
	return m
}

func TestHkW1_EditCommentedManagedHostSavesOnlyItsLine(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := hkModel(t)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)
	treeBefore := tmTree(t, e.dir)

	m = hkOn(t, m, "web-9")
	m, _ = press(m, "e")
	if m.mode != modeEditor || m.editor == nil {
		t.Fatalf("e on web-9: mode=%v toast=%q", m.mode, m.toast)
	}
	if got := m.editor.name; got != "web-9" {
		t.Errorf("editor name = %q, want web-9", got)
	}
	if view := plain(m); !strings.Contains(view, "Edit: web-9") || strings.Contains(view, "prod box") {
		t.Errorf("form title should be the clean name:\n%s", view)
	}

	m, _ = press(m, "tab") // HostName -> User
	m = set(m, "root")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList || m.toastErr || m.toast != "saved web-9" {
		t.Fatalf("save: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}

	want := strings.Replace(origManaged, "  User alice\n", "  User root\n", 1)
	if got := readFile(t, e.managed); got != want {
		t.Errorf("managed file after the edit:\n%s\nwant only the User line changed:\n%s", got, want)
	}
	if !strings.Contains(readFile(t, e.managed), "Host web-9 # prod box\n") {
		t.Error("the Host line lost its comment")
	}
	if got := readFile(t, e.main); got != origMain {
		t.Errorf("main file changed:\n%s", got)
	}
	tmOnlyChanged(t, treeBefore, tmTree(t, e.dir), e.managed)
	if got := tmSSHG(t, e.main, "web-9")["user"]; len(got) != 1 || got[0] != "root" {
		t.Errorf("ssh -G web-9 user = %v, want [root]", got)
	}
}

func TestHkW1_EditCommentedMainHostShowsTheReadOnlyToast(t *testing.T) {
	t.Parallel()
	m, e := hkModel(t)
	before := tmTree(t, e.dir)

	m = hkOn(t, m, "main-9")
	m, _ = press(m, "e")
	if m.mode == modeEditor || m.editor != nil {
		t.Fatalf("e on main-9 opened the editor (mode=%v)", m.mode)
	}
	if !m.toastErr {
		t.Errorf("toast %q is not an error toast", m.toast)
	}
	want := smgRefusal("main-9", e.main)
	if m.toast != want {
		t.Errorf("toast = %q, want %q", m.toast, want)
	}
	if strings.Contains(m.toast, "legacy note") || strings.Contains(m.toast, "#") {
		t.Errorf("toast %q mentions the comment", m.toast)
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
}

// smgRefusal is the import refusal for a host defined in the main file.
func smgRefusal(host, file string) string {
	return "host \"" + host + "\" is defined in " + file + ", which sshm does not manage; run 'sshm import'"
}

func TestHkW1_EnterOnACommentedHostSelectsTheCleanName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"web-9", "main-9"} {
		m, _ := hkModel(t)
		m = hkOn(t, m, name)
		m, cmd := press(m, "enter")
		if !isQuit(cmd) {
			t.Errorf("%s: enter did not quit (toast=%q)", name, m.toast)
		}
		if got := m.Selected(); got != name {
			t.Errorf("Selected() = %q, want %q", got, name)
		}
	}
}

func TestHkW1_DuplicateCommentedManagedHost(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := hkModel(t)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)
	treeBefore := tmTree(t, e.dir)

	m = hkOn(t, m, "web-9")
	m, _ = press(m, "d")
	if m.mode != modeDuplicate {
		t.Fatalf("d on web-9: mode=%v toast=%q", m.mode, m.toast)
	}
	if m.target != "web-9" {
		t.Errorf("duplicate target = %q, want web-9", m.target)
	}
	m = typeText(m, "web-10")
	m, _ = press(m, "enter")
	if m.mode != modeList || m.toastErr || !strings.Contains(m.toast, "web-10") {
		t.Fatalf("duplicate: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}

	got := readFile(t, e.managed)
	for _, l := range tmLines(origManaged) { // nothing of the original is lost
		if strings.TrimSpace(l) != "" && strings.Count(got, l) < strings.Count(origManaged, l) {
			t.Errorf("line %q of the original managed file was lost:\n%s", l, got)
		}
	}
	if !strings.Contains(got, "Host web-9 # prod box\n") {
		t.Errorf("the source Host line changed:\n%s", got)
	}
	if strings.Count(got, "Host web-10") != 1 {
		t.Errorf("Host web-10 appears %d times:\n%s", strings.Count(got, "Host web-10"), got)
	}
	if readFile(t, e.main) != origMain {
		t.Error("main file changed")
	}
	tmOnlyChanged(t, treeBefore, tmTree(t, e.dir), e.managed)
	src, dup := tmSSHG(t, e.main, "web-9"), tmSSHG(t, e.main, "web-10")
	for _, k := range []string{"hostname", "user", "port", "identityfile"} {
		if strings.Join(src[k], ",") != strings.Join(dup[k], ",") {
			t.Errorf("ssh -G: %s of the copy = %v, want the source's %v", k, dup[k], src[k])
		}
	}
}

func TestHkW1_DeleteCommentedManagedHost(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := hkModel(t)
	origMain := readFile(t, e.main)
	treeBefore := tmTree(t, e.dir)

	m = hkOn(t, m, "web-9")
	m, _ = press(m, "D")
	if m.mode != modeDelete {
		t.Fatalf("D on web-9: mode=%v toast=%q", m.mode, m.toast)
	}
	if m.target != "web-9" {
		t.Errorf("delete target = %q, want web-9", m.target)
	}
	m, _ = press(m, "y")
	if m.mode != modeList || m.toastErr || m.toast != "deleted web-9" {
		t.Fatalf("delete: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}

	got := readFile(t, e.managed)
	for _, gone := range []string{"web-9", "prod box", "10.0.0.91", "/keys/web9"} {
		if strings.Contains(got, gone) {
			t.Errorf("managed file still has %q:\n%s", gone, got)
		}
	}
	if !tmSubLines(got, "Host plain-9\n  HostName 10.0.0.92\n  User bob\n  IdentityFile /keys/plain9\n") {
		t.Errorf("the neighbouring block was damaged:\n%s", got)
	}
	if readFile(t, e.main) != origMain {
		t.Error("main file changed")
	}
	tmOnlyChanged(t, treeBefore, tmTree(t, e.dir), e.managed)
}
