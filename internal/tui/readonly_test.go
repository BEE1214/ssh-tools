package tui

import (
	"os"
	"strings"
	"testing"
)

// New (the constructor Run uses) must leave editing off: e/n/d/D only toast,
// never open the editor or touch the config file.
func TestEditingDisabledByDefault(t *testing.T) {
	m, a, path := newTestModel(t, fixture)
	m = New(a) // fresh model: editable is false, as in Run
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	m, _ = press(m, "right", "j") // expand first group, land on a host
	for _, key := range []string{"e", "n", "d", "D"} {
		m, _ = press(m, key)
		if m.mode != modeList {
			t.Fatalf("key %q left list mode (mode=%v)", key, m.mode)
		}
		if !m.toastErr || !strings.Contains(m.toast, "disabled") {
			t.Fatalf("key %q: want a 'disabled' error toast, got %q", key, m.toast)
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
	_, a, _ := newTestModel(t, fixture)
	m := New(a)
	if h := m.hintsLine(); strings.Contains(h, "e edit") || strings.Contains(h, "D del") {
		t.Fatalf("hints advertise editing: %q", h)
	}
	m, _ = press(m, "?")
	if v := m.View().Content; strings.Contains(v, "delete host") {
		t.Fatalf("help advertises editing:\n%s", v)
	}
}
