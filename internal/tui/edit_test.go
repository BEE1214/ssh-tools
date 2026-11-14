package tui

import (
	"os"
	"strings"
	"testing"
)

// set replaces the focused editor field's content.
func set(m Model, text string) Model {
	m, _ = press(m, "ctrl+u")
	return typeText(m, text)
}

func TestEditHostSavesThroughApp(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	m = onHost(m, "web-1")

	m, _ = press(m, "e")
	if m.mode != modeEditor || m.editor == nil || m.editor.name != "web-1" {
		t.Fatalf("editor not open: mode=%v", m.mode)
	}
	if m.editor.focus != fHostName {
		t.Errorf("edit should start on HostName (Host is read-only), focus=%d", m.editor.focus)
	}
	// HostName -> User (tab), replace User.
	m, _ = press(m, "tab")
	m = set(m, "root")
	m, _ = press(m, "ctrl+s")

	if m.mode != modeList || m.editor != nil {
		t.Fatalf("editor should close after save: mode=%v toast=%q", m.mode, m.toast)
	}
	if m.toastErr || !strings.Contains(m.toast, "saved web-1") {
		t.Errorf("toast = %q", m.toast)
	}
	if curKey(m) != "h:web-1" {
		t.Errorf("cursor should stay on edited host, on %q", curKey(m))
	}
	want := strings.Replace(fixture,
		"Host web-1\n  HostName 10.0.0.1\n  User admin\n",
		"Host web-1\n  HostName 10.0.0.1\n  User root\n", 1)
	if got := readFile(t, path); got != want {
		t.Errorf("file after edit:\n%s\nwant:\n%s", got, want)
	}
}

func TestEditorEnterAdvancesAndSavesOnLastField(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	m = onHost(m, "web-1")
	m, _ = press(m, "e")
	m, _ = press(m, "enter", "enter", "enter", "enter") // HostName..ProxyJump
	if m.editor.focus != fProxyJump || m.mode != modeEditor {
		t.Fatalf("focus=%d mode=%v", m.editor.focus, m.mode)
	}
	m = typeText(m, "bastion-1")
	m, _ = press(m, "enter")
	if m.mode != modeList || !strings.Contains(readFile(t, path), "ProxyJump bastion-1") {
		t.Errorf("enter on last field should save; mode=%v\n%s", m.mode, readFile(t, path))
	}
}

func TestEditorTabCyclesAndSkipsReadOnlyName(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	m = onHost(m, "web-1")
	m, _ = press(m, "e")
	m, _ = press(m, "shift+tab") // wraps to the last field, never fName
	if m.editor.focus != fProxyJump {
		t.Errorf("shift+tab from first = %d, want ProxyJump", m.editor.focus)
	}
	m, _ = press(m, "tab") // wraps to first editable
	if m.editor.focus != fHostName {
		t.Errorf("tab from last = %d, want HostName", m.editor.focus)
	}
	// The read-only name must not take typed text.
	m = typeText(m, "x")
	if m.editor.inputs[fName].Value() != "web-1" {
		t.Errorf("name field changed to %q", m.editor.inputs[fName].Value())
	}
}

func TestEditorNoChangesDoesNotWrite(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	before := readFile(t, path)
	infoBefore, _ := os.Stat(path)
	m = onHost(m, "web-1")
	m, _ = press(m, "e", "ctrl+s")
	if m.mode != modeList || m.toast != "no changes" {
		t.Errorf("mode=%v toast=%q", m.mode, m.toast)
	}
	infoAfter, _ := os.Stat(path)
	if readFile(t, path) != before || !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Error("file must not be rewritten when nothing changed")
	}
}

func TestEditorEscCancels(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	before := readFile(t, path)
	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab")
	m = set(m, "changed")
	m, cmd := press(m, "esc")
	if m.mode != modeList || m.editor != nil || isQuit(cmd) {
		t.Errorf("esc should cancel only: mode=%v quit=%v", m.mode, isQuit(cmd))
	}
	if readFile(t, path) != before {
		t.Error("cancel must not write")
	}
}

func TestEditorWarningsShownButDoNotBlock(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	m = onHost(m, "web-2") // no IdentityFile -> missing-identity warning
	m, _ = press(m, "e")
	if !strings.Contains(plain(m), "no IdentityFile set") {
		t.Fatalf("warning not displayed:\n%s", plain(m))
	}
	m, _ = press(m, "tab")
	m = set(m, "ops")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList || !strings.Contains(m.toast, "1 warning") {
		t.Errorf("warnings must not block: mode=%v toast=%q", m.mode, m.toast)
	}
	if !strings.Contains(readFile(t, path), "User ops") {
		t.Error("edit not written")
	}
}

func TestEditorValidationErrorBlocksSave(t *testing.T) {
	cases := []struct {
		name, typed, want string
	}{
		{"duplicate name", "web-1", "already exists"},
		{"empty name", "", "must not be empty"},
		{"whitespace in name", "two words", "whitespace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, _, path := newTestModel(t, fixture)
			before := readFile(t, path)
			m, _ = press(m, "n")
			if m.mode != modeEditor || !m.editor.isNew || m.editor.focus != fName {
				t.Fatalf("new editor: mode=%v", m.mode)
			}
			m = typeText(m, c.typed)
			m, _ = press(m, "ctrl+s")

			if m.mode != modeEditor {
				t.Fatalf("save with an error must stay in the editor")
			}
			if !strings.Contains(plain(m), c.want) {
				t.Errorf("inline error %q not shown:\n%s", c.want, plain(m))
			}
			if readFile(t, path) != before {
				t.Error("blocked save must not write")
			}
		})
	}
}

func TestNewHost(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	m, _ = press(m, "n")
	if got := m.editor.inputs[fIdentity].Value(); got != "~/.ssh/id_ed25519" {
		t.Errorf("identity default = %q", got)
	}
	m = typeText(m, "lab-1")
	m, _ = press(m, "tab")
	m = typeText(m, "192.0.2.5")
	m, _ = press(m, "tab")
	m = typeText(m, "tester")
	m, _ = press(m, "ctrl+s")

	if m.mode != modeList || curKey(m) != "h:lab-1" {
		t.Fatalf("mode=%v cursor=%q toast=%q", m.mode, curKey(m), m.toast)
	}
	got := readFile(t, path)
	want := fixture + "\nHost lab-1\n  HostName 192.0.2.5\n  User tester\n  IdentityFile ~/.ssh/id_ed25519\n"
	if got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
}

func TestDuplicate(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	m = onHost(m, "web-1")
	m, _ = press(m, "d")
	if m.mode != modeDuplicate {
		t.Fatalf("mode=%v", m.mode)
	}
	if !strings.Contains(plain(m), "Duplicate web-1 as:") {
		t.Errorf("prompt not shown:\n%s", plain(m))
	}
	m = typeText(m, "web-3")
	m, _ = press(m, "enter")
	if m.mode != modeList || curKey(m) != "h:web-3" || !strings.Contains(m.toast, "duplicated web-1 as web-3") {
		t.Fatalf("mode=%v cursor=%q toast=%q", m.mode, curKey(m), m.toast)
	}
	want := fixture + "\nHost web-3\n  HostName 10.0.0.1\n  User admin\n  IdentityFile ~/.ssh/id_example\n"
	if got := readFile(t, path); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
}

func TestDuplicateRejectsBadNames(t *testing.T) {
	for name, typed := range map[string]string{"existing": "web-2", "empty": "", "space": "a b"} {
		t.Run(name, func(t *testing.T) {
			m, _, path := newTestModel(t, fixture)
			before := readFile(t, path)
			m = onHost(m, "web-1")
			m, _ = press(m, "d")
			m = typeText(m, typed)
			m, _ = press(m, "enter")
			if m.mode != modeDuplicate || !m.toastErr {
				t.Errorf("should stay in prompt with an error: mode=%v toast=%q", m.mode, m.toast)
			}
			if readFile(t, path) != before {
				t.Error("rejected duplicate must not write")
			}
			// Esc leaves the prompt.
			if m, _ = press(m, "esc"); m.mode != modeList {
				t.Error("esc should cancel the prompt")
			}
		})
	}
}

func TestDeleteWithConfirm(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	before := readFile(t, path)
	m = onHost(m, "web-2")

	// Declining (n, esc, or any other key) deletes nothing.
	for _, k := range []string{"n", "esc"} {
		m, _ = press(m, "D")
		if m.mode != modeDelete || !strings.Contains(plain(m), "Delete web-2? (y/n)") {
			t.Fatalf("confirm not shown:\n%s", plain(m))
		}
		m, _ = press(m, "x") // ignored
		if m.mode != modeDelete {
			t.Fatal("unrelated keys must not dismiss the confirmation")
		}
		m, _ = press(m, k)
		if m.mode != modeList || readFile(t, path) != before {
			t.Fatalf("%s should cancel without writing", k)
		}
	}

	m, _ = press(m, "D", "y")
	if m.mode != modeList || !strings.Contains(m.toast, "deleted web-2") {
		t.Fatalf("mode=%v toast=%q", m.mode, m.toast)
	}
	want := strings.Replace(fixture, "Host web-2\n  HostName 10.0.0.2\n  User admin\n\n", "", 1)
	if got := readFile(t, path); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
	// Cursor lands on a neighbouring row, not off the end.
	if _, ok := m.current(); !ok {
		t.Error("cursor lost after delete")
	}
	for _, k := range rowKeys(onHost(m, "web-1")) {
		if k == "h:web-2" {
			t.Error("deleted host still listed")
		}
	}
}

func TestWriteErrorIsShownNotFatal(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab")
	m = set(m, "root")
	// The host disappears externally while the editor is open.
	writeFile(t, path, "Host other-1\n  HostName 10.0.0.5\n")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeEditor || !strings.Contains(plain(m), "not found") {
		t.Errorf("save error should be shown inline:\n%s", plain(m))
	}
	if got := readFile(t, path); got != "Host other-1\n  HostName 10.0.0.5\n" {
		t.Errorf("failed save modified the file:\n%s", got)
	}
}

// TestStaleModelDoesNotClobberExternalEdit: the TUI holds an old copy of the
// config; another process edits a *different* host before the TUI saves.
// The app layer re-reads before writing, so that edit must survive exactly.
func TestStaleModelDoesNotClobberExternalEdit(t *testing.T) {
	m, _, path := newTestModel(t, fixture)

	// External edit to web-2 (and an appended host) after the TUI loaded.
	external := strings.Replace(fixture,
		"Host web-2\n  HostName 10.0.0.2\n  User admin\n",
		"Host web-2\n  HostName 10.0.0.222\n  User external\n", 1) +
		"\nHost added-externally\n  HostName 10.0.0.99\n"
	writeFile(t, path, external)

	// The TUI still shows the old data...
	if strings.Contains(plain(onHost(m, "web-2")), "10.0.0.222") {
		t.Fatal("test setup: model should still be stale")
	}
	// ...and edits web-1.
	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab")
	m = set(m, "root")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList {
		t.Fatalf("save failed: %q", m.toast)
	}

	want := strings.Replace(external,
		"Host web-1\n  HostName 10.0.0.1\n  User admin\n",
		"Host web-1\n  HostName 10.0.0.1\n  User root\n", 1)
	if got := readFile(t, path); got != want {
		t.Errorf("external edit not preserved byte-for-byte:\n%s\nwant:\n%s", got, want)
	}
	// After the save the view is fresh again.
	if !strings.Contains(plain(onHost(m, "added-externally")), "10.0.0.99") {
		t.Error("reload after save should show externally added host")
	}
}

// TestEditChangesOnlyTargetBytes: opening the TUI on a config with comments,
// a Host * block, a DevPod block and a disabled group, then editing one
// host, changes nothing but that host's lines.
func TestEditChangesOnlyTargetBytes(t *testing.T) {
	m, a, path := withDisabledDeploy(t)
	before := readFile(t, path)
	if !strings.Contains(before, "# sshm disabled group=deploy start") {
		t.Fatalf("setup: group not disabled:\n%s", before)
	}
	stateBefore := readFile(t, a.ConfigPath()+".sshm-groups")

	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab")
	m = set(m, "root")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList {
		t.Fatalf("save failed: %q", m.toast)
	}

	want := strings.Replace(before,
		"Host web-1\n  HostName 10.0.0.1\n  User admin\n",
		"Host web-1\n  HostName 10.0.0.1\n  User root\n", 1)
	if want == before {
		t.Fatal("test bug: replacement did not apply")
	}
	if got := readFile(t, path); got != want {
		t.Errorf("bytes outside web-1 changed:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	// Group state sidecar untouched; DevPod and disabled blocks intact.
	if readFile(t, path+".sshm-groups") != stateBefore {
		t.Error("group state file changed")
	}
	got := readFile(t, path)
	for _, must := range []string{
		"# DevPod Start demo.devpod\nHost demo.devpod\n", "# DevPod End demo.devpod\n",
		"# sshm disabled group=deploy start\n", "# sshm disabled group=deploy end\n",
		"# Hand-written notes live up here.\n",
	} {
		if !strings.Contains(got, must) {
			t.Errorf("lost %q", must)
		}
	}
}
