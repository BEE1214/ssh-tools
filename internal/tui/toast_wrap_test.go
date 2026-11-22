package tui

// T17 (PLAN-p6.md 4.2): a toast longer than the terminal width wraps onto at
// most 3 lines (each at most the width) instead of being clipped; the whole
// text stays visible and the view never has more than `height` lines.
//
// The toast is set directly (setToast) so the text and its length are exact.
// Fixtures: the managed fixture of managed_helpers_test.go (temp dirs).

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

const twTail = "run 'sshm import'"

// twLong builds an n-character toast of short words that starts with "HEAD"
// and ends with the tail of an ownership refusal.
func twLong(n int) string {
	s := "HEAD"
	for len(s)+1+len(twTail) < n {
		s += " word"
	}
	s = s[:n-1-len(twTail)] // exact length; the cut may shorten the last word
	return s + " " + twTail
}

// twFlat removes all whitespace, so a toast that was wrapped (the break
// replaces a space) compares equal to the original text.
func twFlat(s string) string { return strings.Join(strings.Fields(s), "") }

func twSized(t *testing.T, w, h int) Model {
	t.Helper()
	m, _ := tmManaged(t, false)
	m, _ = send(m, tea.WindowSizeMsg{Width: w, Height: h})
	return m
}

// twRequireFits fails when the view has more than h lines or a line wider than w.
func twRequireFits(t *testing.T, label, view string, w, h int) []string {
	t.Helper()
	lines := strings.Split(view, "\n")
	if len(lines) > h {
		t.Errorf("%s: view has %d lines, want at most %d", label, len(lines), h)
	}
	for i, l := range lines {
		if got := ansi.StringWidth(l); got > w {
			t.Errorf("%s: line %d is %d cells wide, want at most %d: %q", label, i, got, w, l)
		}
	}
	return lines
}

// twSpan is the number of lines from the one holding "HEAD" to the one that
// holds the end of the toast ("import'").
func twSpan(lines []string) int {
	first, last := -1, -1
	for i, l := range lines {
		if first < 0 && strings.Contains(l, "HEAD") {
			first = i
		}
		if strings.Contains(l, "import'") {
			last = i
		}
	}
	if first < 0 || last < first {
		return -1
	}
	return last - first + 1
}

func TestTwT17_LongToastWrapsAndStaysVisible(t *testing.T) {
	t.Parallel()
	for _, w := range []int{80, 100} {
		toast := twLong(95)
		if len(toast) != 95 {
			t.Fatalf("fixture: toast has %d characters, want 95", len(toast))
		}
		m := twSized(t, 80, 24)
		m, _ = send(m, tea.WindowSizeMsg{Width: w, Height: 24})
		m.setToast(toast, true)

		view := plain(m)
		lines := twRequireFits(t, fmt.Sprintf("width %d", w), view, w, 24)
		flat := twFlat(view)
		for _, part := range []string{"HEAD", twFlat(twTail)} {
			if !strings.Contains(flat, part) {
				t.Errorf("width %d: view lost %q of the toast:\n%s", w, part, view)
			}
		}
		if !strings.Contains(flat, twFlat(toast)) {
			t.Errorf("width %d: the whole toast is not in the view (text clipped):\n%s", w, view)
		}
		wantLines := 1
		if len(toast) > w {
			wantLines = 2
		}
		if got := twSpan(lines); got != wantLines {
			t.Errorf("width %d: the %d-char toast spans %d lines, want %d:\n%s", w, len(toast), got, wantLines, view)
		}
	}
}

func TestTwT17_AtMostThreeLinesEvenForAHugeToast(t *testing.T) {
	t.Parallel()
	m := twSized(t, 80, 24)
	m.setToast(twLong(400), true)
	view := plain(m)
	lines := twRequireFits(t, "400-char toast", view, 80, 24)
	last := len(lines) - 1
	if !strings.Contains(lines[last], "↑↓ move") {
		t.Fatalf("the hints line is not the last line: %q", lines[last])
	}
	// The status area is everything from the line that starts the toast down to
	// the hints line. A toast too long for the cap is cut, not dropped: exactly 3
	// lines, the last one ending in an ellipsis. (The end of the text, "import'",
	// is deliberately gone, so twSpan cannot measure this case.)
	first := -1
	for i, l := range lines {
		if strings.Contains(l, "HEAD") {
			first = i
			break
		}
	}
	if first < 0 {
		t.Fatalf("the start of the toast is missing:\n%s", view)
	}
	status := lines[first:last]
	if len(status) != 3 {
		t.Errorf("status area has %d lines, want exactly 3:\n%s", len(status), strings.Join(status, "\n"))
	}
	if n := len(status); n > 0 {
		if end := strings.TrimRight(status[n-1], " "); !strings.HasSuffix(end, "…") {
			t.Errorf("last status line %q does not end in …", end)
		}
	}
	for i, l := range status[:min(2, len(status))] {
		if strings.HasSuffix(strings.TrimRight(l, " "), "…") {
			t.Errorf("status line %d ends in … but is not the last one: %q", i, l)
		}
	}
	if strings.Contains(twFlat(view), twFlat(twTail)) {
		t.Errorf("the tail of a 400-char toast is still shown, so nothing was cut:\n%s", view)
	}
}

func TestTwT17_LineCountWithinHeightInEveryMode(t *testing.T) {
	t.Parallel()
	for _, size := range [][2]int{{80, 24}, {100, 24}, {80, 10}, {100, 8}} {
		w, h := size[0], size[1]
		for _, toast := range []string{twLong(95), twLong(400), "deleted web-1"} {
			for name, want := range map[string]mode{"list": modeList, "help": modeHelp, "editor": modeEditor} {
				m := twSized(t, w, h)
				switch name {
				case "help":
					m, _ = press(m, "?")
				case "editor":
					m = onHost(m, "web-1")
					m, _ = press(m, "e")
				}
				if m.mode != want {
					t.Fatalf("fixture: %s mode not reached (mode=%v, toast %q)", name, m.mode, m.toast)
				}
				m.setToast(toast, true) // after the key: a key press clears the toast
				twRequireFits(t, fmt.Sprintf("%dx%d %s mode, %d-char toast", w, h, name, len(toast)), plain(m), w, h)
			}
		}
	}
}

func TestTwT17_ShortToastStaysOnOneLine(t *testing.T) {
	t.Parallel()
	m := twSized(t, 80, 24)
	m.setToast("deleted web-1", false)
	view := plain(m)
	lines := twRequireFits(t, "short toast", view, 80, 24)
	if len(lines) != 24 {
		t.Errorf("view has %d lines, want exactly 24 (as before)", len(lines))
	}
	n := 0
	for _, l := range lines {
		if strings.Contains(l, "deleted web-1") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("short toast occupies %d lines, want 1", n)
	}
	if got := strings.TrimRight(lines[len(lines)-2], " "); got != "deleted web-1" {
		t.Errorf("status line = %q, want the toast on the line above the hints", got)
	}
	if !strings.Contains(lines[len(lines)-1], "↑↓ move") {
		t.Errorf("last line =%q, want the hints", lines[len(lines)-1])
	}
}

// With a managed path of 80+ characters the "editing disabled" toast must still
// show the reason (it comes first) and the whole managed path (wrapped) within
// the 3-line cap.
func TestTwT18_LongPath(t *testing.T) {
	t.Parallel()
	for _, w := range []int{80, 100} {
		base := t.TempDir()
		// Pad with a long directory name up to a managed path of about 90 chars.
		pad := max(10, 90-len(filepath.Join(base, "config.d", "sshm.conf"))-1)
		dir := filepath.Join(base, strings.Repeat("d", pad))
		e := &tmEnv{
			dir:     dir,
			main:    filepath.Join(dir, "config"),
			managed: filepath.Join(dir, "config.d", "sshm.conf"),
			extra:   filepath.Join(dir, "extra.conf"),
		}
		if len(e.managed) < 80 {
			t.Fatalf("fixture: managed path has %d characters, want at least 80", len(e.managed))
		}
		tmWrite(t, e.managed, e.sub(tmpBrokenManaged), 0o600)
		tmWrite(t, e.extra, tmExtraBody, 0o600)
		tmWrite(t, e.main, e.sub(tmMainBody), 0o600)
		e.a = app.NewAppWithPath(e.main)

		m := tmModel(e)
		m, _ = send(m, tea.WindowSizeMsg{Width: w, Height: 24})
		m, _ = press(m, "e")
		if !strings.HasPrefix(m.toast, "editing disabled: managed file cannot be loaded (") {
			t.Fatalf("width %d: toast = %q", w, m.toast)
		}
		view := plain(m)
		twRequireFits(t, fmt.Sprintf("width %d", w), view, w, 24)
		flat := twFlat(view)
		for _, part := range []string{`unterminated disabled group block "zzz"`, e.managed} {
			if !strings.Contains(flat, twFlat(part)) {
				t.Errorf("width %d: view lacks %q:\n%s", w, part, view)
			}
		}
	}
}

// A refusal produced by a real key press wraps too (path lengths vary, so only
// the invariants are checked): the 'sshm import' tail is visible at width 80.
func TestTwT17_RealRefusalTailVisibleAtWidth80(t *testing.T) {
	t.Parallel()
	m := twSized(t, 80, 24)
	m = onHost(m, "main-1")
	m, _ = press(m, "e")
	if !strings.Contains(m.toast, twTail) {
		t.Fatalf("toast = %q, want the import refusal", m.toast)
	}
	view := plain(m)
	twRequireFits(t, "real refusal", view, 80, 24)
	if !strings.Contains(twFlat(view), twFlat(m.toast)) {
		t.Errorf("the refusal is clipped in the view:\n%s", view)
	}
}
