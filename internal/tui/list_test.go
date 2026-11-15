package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestKeyMsgStrings(t *testing.T) {
	for in, want := range map[string]string{
		"j": "j", "D": "D", "?": "?", "/": "/", "enter": "enter", "esc": "esc",
		"shift+tab": "shift+tab", "ctrl+s": "ctrl+s", "ctrl+c": "ctrl+c", "right": "right",
	} {
		if got := keyMsg(in).String(); got != want {
			t.Errorf("keyMsg(%q).String() = %q, want %q", in, got, want)
		}
	}
}

func rowKeys(m Model) []string {
	var keys []string
	for _, r := range m.rows {
		keys = append(keys, r.key())
	}
	return keys
}

func TestNavigationAndExpandCollapse(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)

	// Collapsed by default; "ungrouped" sorts last; wildcard "Host *" is
	// not listed.
	want := []string{"g:deploy", "g:web", "g:ungrouped"}
	if got := rowKeys(m); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("initial rows = %v, want %v", got, want)
	}
	if curKey(m) != "g:deploy" {
		t.Fatalf("cursor on %q", curKey(m))
	}

	// j/down move; k/up move back; clamped at both ends.
	m, _ = press(m, "j", "down", "down", "down")
	if curKey(m) != "g:ungrouped" {
		t.Errorf("after 4 downs cursor on %q, want g:ungrouped (clamped)", curKey(m))
	}
	m, _ = press(m, "k", "up", "up", "up")
	if curKey(m) != "g:deploy" {
		t.Errorf("after ups cursor on %q, want g:deploy", curKey(m))
	}

	// Expand web with right, step into it, collapse from a host row.
	m, _ = press(m, "j", "right")
	if curKey(m) != "g:web" {
		t.Fatalf("cursor on %q, want g:web", curKey(m))
	}
	if got := rowKeys(m); len(got) != 5 || got[2] != "h:web-1" || got[3] != "h:web-2" {
		t.Fatalf("rows after expand = %v", got)
	}
	m, _ = press(m, "j", "j")
	if curKey(m) != "h:web-2" {
		t.Fatalf("cursor on %q, want h:web-2", curKey(m))
	}
	m, _ = press(m, "left")
	if curKey(m) != "g:web" || len(m.rows) != 3 {
		t.Errorf("collapse from host: cursor %q, %d rows", curKey(m), len(m.rows))
	}

	// l / h work too, and Enter toggles a group header.
	m, _ = press(m, "l")
	if len(m.rows) != 5 {
		t.Errorf("l should expand, rows=%d", len(m.rows))
	}
	m, _ = press(m, "h")
	if len(m.rows) != 3 {
		t.Errorf("h should collapse, rows=%d", len(m.rows))
	}
	m, cmd := press(m, "enter")
	if len(m.rows) != 5 || cmd != nil || m.Selected() != "" {
		t.Errorf("enter on header should toggle only: rows=%d cmd=%v sel=%q", len(m.rows), cmd != nil, m.Selected())
	}
}

func TestHeaderShowsHostCounts(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	out := plain(m)
	for _, want := range []string{"SSH Manager", "[6 hosts]", "web (2 hosts)", "deploy (2 hosts)", "ungrouped (2 hosts)"} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q:\n%s", want, out)
		}
	}
}

func TestHostRowContent(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	m = onHost(m, "web-1")
	m = onHost(m, "web-2")
	m = onHost(m, "solo")
	out := plain(m)
	for _, want := range []string{
		"web-1", "admin @ 10.0.0.1:22", "id_example",
		"web-2", "no key",
		"solo", "(default) @ 10.0.0.9:2222",
		"demo.devpod", "[read-only]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q:\n%s", want, out)
		}
	}
}

func TestFilterEnterApplyAndClear(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)

	m, _ = press(m, "/")
	if m.mode != modeFilter {
		t.Fatalf("mode = %v, want filter", m.mode)
	}
	m = typeText(m, "web")
	// Flat matches, groups auto-expanded (no headers).
	if got := rowKeys(m); strings.Join(got, ",") != "h:web-1,h:web-2" {
		t.Fatalf("filtered rows = %v", got)
	}
	if !strings.Contains(plain(m), "[2 hosts]") {
		t.Errorf("count should reflect matches:\n%s", plain(m))
	}

	// 'q' while typing is text, not quit.
	m, cmd := press(m, "q")
	if isQuit(cmd) || m.filter.Value() != "webq" {
		t.Fatalf("q in filter mode must be typed: quit=%v value=%q", isQuit(cmd), m.filter.Value())
	}
	m, _ = press(m, "esc")
	if m.mode != modeList || m.filter.Value() != "" {
		t.Fatalf("esc should clear filter: mode=%v value=%q", m.mode, m.filter.Value())
	}
	// "webq" matched nothing, so there was no host to keep the cursor on.
	if len(m.rows) != 3 {
		t.Errorf("after clear: rows=%v", rowKeys(m))
	}

	// Apply with Enter: filter stays, navigation keys work again.
	m, _ = press(m, "/")
	m = typeText(m, "web")
	m, _ = press(m, "down", "enter")
	if m.mode != modeList || m.filter.Value() != "web" || curKey(m) != "h:web-2" {
		t.Fatalf("after apply: mode=%v value=%q cursor=%q", m.mode, m.filter.Value(), curKey(m))
	}
	// First Esc clears the filter (cursor stays on web-2 with group expanded)...
	m, cmd = press(m, "esc")
	if isQuit(cmd) || m.filter.Value() != "" || curKey(m) != "h:web-2" {
		t.Fatalf("esc with applied filter: quit=%v value=%q cursor=%q", isQuit(cmd), m.filter.Value(), curKey(m))
	}
	// ...the second one quits.
	if _, cmd = press(m, "esc"); !isQuit(cmd) {
		t.Error("second esc should quit")
	}
}

func TestFilterNoMatches(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	m, _ = press(m, "/")
	m = typeText(m, "zzzz")
	if len(m.rows) != 0 {
		t.Fatalf("rows = %v", rowKeys(m))
	}
	if !strings.Contains(plain(m), "[0 hosts]") {
		t.Errorf("view:\n%s", plain(m))
	}
	// Enter with no rows must not select or crash.
	m, cmd := press(m, "enter", "enter")
	if isQuit(cmd) || m.Selected() != "" {
		t.Error("enter with no matches must not select")
	}
}

func TestEnterSelectsHostAndQuits(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	m = onHost(m, "web-2")
	m, cmd := press(m, "enter")
	if m.Selected() != "web-2" || !isQuit(cmd) {
		t.Errorf("selected=%q quit=%v", m.Selected(), isQuit(cmd))
	}
}

func TestEnterFromFilterSelectsMatch(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	m, _ = press(m, "/")
	m = typeText(m, "solo")
	m, _ = press(m, "enter")
	m, cmd := press(m, "enter")
	if m.Selected() != "solo" || !isQuit(cmd) {
		t.Errorf("selected=%q quit=%v", m.Selected(), isQuit(cmd))
	}
}

func TestQuitKeysSelectNothing(t *testing.T) {
	for _, k := range []string{"q", "esc", "ctrl+c"} {
		m, _, _ := newTestModel(t, fixture)
		m, cmd := press(m, k)
		if !isQuit(cmd) || m.Selected() != "" {
			t.Errorf("%s: quit=%v selected=%q", k, isQuit(cmd), m.Selected())
		}
	}
}

func TestDisabledHostsShownButBlocked(t *testing.T) {
	m, _, path := withDisabledDeploy(t)
	before := readFile(t, path)

	m = onHost(m, "deploy-acq")
	out := plain(m)
	if !strings.Contains(out, "deploy-acq") || !strings.Contains(out, "[disabled]") {
		t.Fatalf("disabled host should be listed with a tag:\n%s", out)
	}

	// Connect is refused: no selection, no quit.
	m, cmd := press(m, "enter")
	if m.Selected() != "" || isQuit(cmd) || !m.toastErr || !strings.Contains(m.toast, "disabled") {
		t.Errorf("enter: selected=%q quit=%v toast=%q", m.Selected(), isQuit(cmd), m.toast)
	}
	// Edit / duplicate / delete are refused.
	for _, k := range []string{"e", "d", "D"} {
		m, _ = press(m, k)
		if m.mode != modeList || !m.toastErr || !strings.Contains(m.toast, "disabled") {
			t.Errorf("%s on disabled host: mode=%v toast=%q", k, m.mode, m.toast)
		}
	}
	if readFile(t, path) != before {
		t.Error("blocked actions must not touch the file")
	}
}

func TestDevPodHostIsReadOnly(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	before := readFile(t, path)
	m = onHost(m, "demo.devpod")

	for _, k := range []string{"e", "d", "D"} {
		m, _ = press(m, k)
		if m.mode != modeList || !m.toastErr || !strings.Contains(m.toast, "read-only") {
			t.Errorf("%s on DevPod host: mode=%v toast=%q", k, m.mode, m.toast)
		}
	}
	if readFile(t, path) != before {
		t.Error("blocked actions must not touch the file")
	}
	// Connecting is still fine: it is an ordinary ssh host.
	m, cmd := press(m, "enter")
	if m.Selected() != "demo.devpod" || !isQuit(cmd) {
		t.Errorf("connect to DevPod host: selected=%q quit=%v", m.Selected(), isQuit(cmd))
	}
}

func TestHelpOverlay(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	m, _ = press(m, "?")
	if m.mode != modeHelp || !strings.Contains(plain(m), "duplicate host") {
		t.Fatalf("help not shown:\n%s", plain(m))
	}
	m, cmd := press(m, "x")
	if m.mode != modeList || isQuit(cmd) {
		t.Error("any key closes help without quitting")
	}
}

func TestReloadPicksUpExternalChange(t *testing.T) {
	m, _, path := newTestModel(t, fixture)
	writeFile(t, path, fixture+"\nHost extra-1\n  HostName 10.0.0.77\n")
	m, _ = press(m, "r")
	if m.toast != "reloaded" {
		t.Errorf("toast = %q", m.toast)
	}
	if !strings.Contains(plain(onHost(m, "extra-1")), "10.0.0.77") {
		t.Error("reloaded host not shown")
	}
}

func TestLoadErrorIsNonFatalAndRecoverable(t *testing.T) {
	m, _, path := newTestModel(t, "Host a-1\n  HostName 10.0.0.1\n")
	// Unterminated disabled marker = parse error on the next read.
	writeFile(t, path, "# sshm disabled group=x start\n# Host x-1\n")
	m, _ = press(m, "r")
	if m.loadErr == nil || !strings.Contains(plain(m), "config error") {
		t.Fatalf("expected visible config error, got:\n%s", plain(m))
	}
	// Previous data stays on screen.
	if !strings.Contains(plain(m), "a (1 host)") {
		t.Errorf("stale data should remain:\n%s", plain(m))
	}
	writeFile(t, path, "Host b-1\n  HostName 10.0.0.2\n")
	m, _ = press(m, "r")
	if m.loadErr != nil || !strings.Contains(plain(m), "b (1 host)") {
		t.Errorf("did not recover:\n%s", plain(m))
	}
}

func TestStatusBarShowsIssueCount(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	// web-2, deploy-eu, solo (and demo.devpod? has no identity) lack keys.
	if out := plain(m); !strings.Contains(out, "warning") {
		t.Errorf("status bar should show issue count:\n%s", out)
	}
	clean, _, _ := newTestModel(t, "Host ok-1\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/id_example\n")
	if out := plain(clean); !strings.Contains(out, "no issues") {
		t.Errorf("expected 'no issues':\n%s", out)
	}
}

func TestWindowSizeMsgUpdatesLayout(t *testing.T) {
	m, _, _ := newTestModel(t, fixture)
	m, _ = send(m, tea.WindowSizeMsg{Width: 50, Height: 12})
	if m.width != 50 || m.height != 12 {
		t.Errorf("size = %dx%d", m.width, m.height)
	}
}
