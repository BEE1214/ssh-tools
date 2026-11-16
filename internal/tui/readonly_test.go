package tui

import (
	"os"
	"strings"
	"testing"
)

// Legacy mode (T8 characterization, was TestEditingDisabledByDefault): New over
// a config that does not include the managed file leaves editing off: e/n/d/D
// only toast, never open the editor or touch the config file.
func TestEditingDisabledByDefault(t *testing.T) {
	m, a, path := newLegacyTestModel(t, fixture)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "editing needs setup: run 'sshm setup' to create " + a.ManagedPath()

	m, _ = press(m, "right", "j") // expand first group, land on a host
	for _, key := range []string{"e", "n", "d", "D"} {
		m, _ = press(m, key)
		if m.mode != modeList {
			t.Fatalf("key %q left list mode (mode=%v)", key, m.mode)
		}
		if !m.toastErr || m.toast != want {
			t.Fatalf("key %q: want the error toast %q, got %q", key, want, m.toast)
		}
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("config changed although editing is disabled")
	}
}

func TestReadOnlyHintsAndHelpOmitEditKeys(t *testing.T) {
	m, _, _ := newLegacyTestModel(t, fixture)
	if h := m.hintsLine(); strings.Contains(h, "e edit") || strings.Contains(h, "D del") {
		t.Fatalf("hints advertise editing: %q", h)
	}
	m, _ = press(m, "?")
	if v := m.View().Content; strings.Contains(v, "delete host") {
		t.Fatalf("help advertises editing:\n%s", v)
	}
}
