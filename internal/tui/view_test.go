package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// assertFits checks the rendered view never exceeds the window.
func assertFits(t *testing.T, label string, m Model) {
	t.Helper()
	out := plain(m)
	if strings.TrimSpace(out) == "" {
		t.Errorf("%s: empty view", label)
	}
	lines := strings.Split(out, "\n")
	if m.height >= 2 && len(lines) > m.height {
		t.Errorf("%s: %d lines in a %d-line window", label, len(lines), m.height)
	}
	for i, l := range lines {
		if w := lipgloss.Width(l); w > m.width {
			t.Errorf("%s: line %d is %d wide in a %d-wide window: %q", label, i, w, m.width, l)
		}
	}
}

// states returns a model in every mode, at the given size.
func states(t *testing.T, w, h int) map[string]Model {
	t.Helper()
	base, _, _ := withDisabledDeploy(t)
	base, _ = send(base, tea.WindowSizeMsg{Width: w, Height: h})
	for _, g := range []string{"web", "deploy", "ungrouped"} {
		base.expanded[g] = true
	}
	base.rebuild()

	out := map[string]Model{"list": base}
	out["filter-typing"], _ = press(base, "/", "w", "e")
	out["filter-applied"], _ = press(base, "/", "w", "e", "enter")
	out["help"], _ = press(base, "?")
	out["new"], _ = press(base, "n")
	out["edit"], _ = press(onHost(base, "web-1"), "e")
	out["duplicate"], _ = press(onHost(base, "web-1"), "d")
	out["delete"], _ = press(onHost(base, "web-1"), "D")
	out["toast"], _ = press(onHost(base, "deploy-acq"), "enter")
	return out
}

func TestViewSmoke(t *testing.T) {
	for _, size := range [][2]int{{20, 5}, {120, 40}, {80, 24}, {40, 14}, {1, 1}, {10, 2}, {3, 30}} {
		for name, m := range states(t, size[0], size[1]) {
			assertFits(t, fmt.Sprintf("%s %dx%d", name, size[0], size[1]), m)
		}
	}
}

func TestViewDefaultSizeBeforeWindowMsg(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	if m.width != 80 || m.height != 24 {
		t.Errorf("default size = %dx%d", m.width, m.height)
	}
	assertFits(t, "default", m)
}

func TestViewRequestsAltScreen(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	if !m.View().AltScreen {
		t.Error("TUI should use the alternate screen so the terminal is restored on exit")
	}
}

func TestViewEmptyConfig(t *testing.T) {
	m, _, _ := newTestModel(t, "")
	if !strings.Contains(plain(m), "no hosts") || !strings.Contains(plain(m), "[0 hosts]") {
		t.Errorf("empty config view:\n%s", plain(m))
	}
	// Keys on an empty list must not panic.
	press(m, "j", "k", "enter", "e", "d", "D", "left", "right", "/", "esc")
}

func manyHosts(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "Host big-%03d\n  HostName 10.0.%d.%d\n  IdentityFile ~/.ssh/id_example\n\n", i, i/250, i%250)
	}
	return b.String()
}

func TestLongListScrolls(t *testing.T) {
	m, _, _ := newTestModel(t, manyHosts(60))
	m, _ = send(m, tea.WindowSizeMsg{Width: 80, Height: 10})
	m, _ = press(m, "right") // expand "big"; 61 rows

	if got := len(m.rows); got != 61 {
		t.Fatalf("rows = %d", got)
	}
	if strings.Contains(plain(m), "big-040") {
		t.Fatal("rows below the viewport must not be rendered")
	}

	// Walk to a row far below the first screen.
	for i := 0; i < 40; i++ {
		m, _ = press(m, "j")
	}
	if m.offset == 0 {
		t.Fatal("viewport did not scroll")
	}
	out := plain(m)
	if !strings.Contains(out, "big-040") {
		t.Errorf("selected row not visible:\n%s", out)
	}
	if strings.Contains(out, "big-001") {
		t.Errorf("scrolled-off row still rendered:\n%s", out)
	}
	assertFits(t, "scrolled", m)

	// Back to the top scrolls back.
	for i := 0; i < 60; i++ {
		m, _ = press(m, "k")
	}
	if m.offset != 0 || !strings.Contains(plain(m), "big (60 hosts)") {
		t.Errorf("offset=%d\n%s", m.offset, plain(m))
	}

	// Shrinking the window keeps the cursor visible.
	for i := 0; i < 30; i++ {
		m, _ = press(m, "j")
	}
	m, _ = send(m, tea.WindowSizeMsg{Width: 30, Height: 6})
	if r, _ := m.current(); !strings.Contains(plain(m), r.host.Name) {
		t.Errorf("cursor row %q not visible after resize:\n%s", r.host.Name, plain(m))
	}
	assertFits(t, "resized", m)
}
