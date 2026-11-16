package tui

// Mutation-audit tests for P6 (PLAN-p6.md): clauses the original TUI tests let
// a mutant slip through. Same helpers/fixtures as managed_helpers_test.go.
// Temp dirs and placeholders only.

import (
	"os"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// T7 + T8: a FAILED reload keeps the last snapshot, also in legacy mode: the
// setup toast still names the managed path (it must not be blanked).
func TestTauT7_FailedReloadInLegacyModeKeepsTheSetupToast(t *testing.T) {
	t.Parallel()
	m, e := tmLegacy(t)
	if err := os.Remove(e.main); err != nil {
		t.Fatal(err)
	}
	m, _ = press(m, "r")
	if m.loadErr == nil {
		t.Fatal("fixture: reload of a missing main file did not fail")
	}
	for _, key := range []string{"e", "n", "d", "D"} {
		got, _ := press(m, key)
		if got.mode != modeList || !got.toastErr || got.toast != tmSetupToast(e) {
			t.Errorf("%s after a failed reload: mode=%v toast=%q err=%v, want the setup toast %q", key, got.mode, got.toast, got.toastErr, tmSetupToast(e))
		}
	}
}

// T7 + T18: a failed reload also keeps the managed-file problem, so the edit
// keys keep showing "editing disabled: ..." instead of "needs setup".
func TestTauT18_FailedReloadKeepsTheManagedProblem(t *testing.T) {
	t.Parallel()
	m, e, problem := tmpBrokenEnv(t)
	if err := os.Remove(e.main); err != nil {
		t.Fatal(err)
	}
	m, _ = press(m, "r")
	if m.loadErr == nil {
		t.Fatal("fixture: reload of a missing main file did not fail")
	}
	got, _ := press(m, "n")
	if want := "editing disabled: " + problem; got.mode != modeList || got.toast != want {
		t.Errorf("n after a failed reload: mode=%v toast=%q, want %q", got.mode, got.toast, want)
	}
}

// T8: when even the FIRST load fails, the setup toast must still name the
// managed path (New seeds it from the App before any snapshot exists).
func TestTauT8_FirstLoadFailureStillNamesTheManagedPath(t *testing.T) {
	t.Parallel()
	e := tmNewEnv(t, tmLegacyMainBody, tmAbsent)
	if err := os.Remove(e.main); err != nil {
		t.Fatal(err)
	}
	m := tmModel(e)
	if m.loadErr == nil {
		t.Fatal("fixture: loading a missing main file did not fail")
	}
	for _, key := range []string{"e", "n", "d", "D"} {
		got, _ := press(m, key)
		if got.mode != modeList || !got.toastErr || got.toast != tmSetupToast(e) {
			t.Errorf("%s with no snapshot: mode=%v toast=%q err=%v, want %q", key, got.mode, got.toast, got.toastErr, tmSetupToast(e))
		}
	}
}

// T17: a toast that does not fit on three lines occupies EXACTLY three lines
// (the cap), each at most the width, the last one ends in an ellipsis, and the
// hints stay the last line. Q is not part of any other text on screen.
func TestTauT17_HugeToastIsCappedAtThreeLinesWithAnEllipsis(t *testing.T) {
	t.Parallel()
	words := strings.TrimSpace(strings.Repeat("QQQQ ", 80))
	for name, toast := range map[string]string{
		"unbroken": strings.Repeat("Q", 400),
		"words":    words,
	} {
		for _, w := range []int{80, 100} {
			m := twSized(t, w, 24)
			m, _ = send(m, tea.WindowSizeMsg{Width: w, Height: 24})
			m.setToast(toast, true)
			lines := twRequireFits(t, name, plain(m), w, 24)

			var q []int
			for i, l := range lines {
				if strings.Contains(l, "QQ") {
					q = append(q, i)
				}
			}
			if len(q) != 3 {
				t.Fatalf("%s toast, width %d: occupies %d lines, want exactly 3 (the cap)\n%s", name, w, len(q), strings.Join(lines, "\n"))
			}
			if q[2] != q[0]+2 || q[2] != len(lines)-2 {
				t.Errorf("%s toast, width %d: lines %v, want three consecutive lines right above the hints", name, w, q)
			}
			if last := strings.TrimRight(lines[q[2]], " "); !strings.HasSuffix(last, "…") {
				t.Errorf("%s toast, width %d: last toast line %q does not end in an ellipsis", name, w, last)
			}
			for _, i := range q[:2] {
				if strings.Contains(lines[i], "…") {
					t.Errorf("%s toast, width %d: line %d has an ellipsis before the last toast line: %q", name, w, i, lines[i])
				}
			}
		}
	}
}

// T17: a toast that fits in three lines gets no ellipsis.
func TestTauT17_ToastThatFitsInThreeLinesHasNoEllipsis(t *testing.T) {
	t.Parallel()
	m := twSized(t, 80, 24)
	m.setToast(strings.Repeat("Q", 200), true) // 80 + 80 + 40
	view := plain(m)
	if strings.Contains(view, "…") {
		t.Errorf("a 200-char toast at width 80 fits in 3 lines but was ellipsized:\n%s", view)
	}
	if n := strings.Count(view, "Q"); n != 200 {
		t.Errorf("view shows %d of the 200 toast characters:\n%s", n, view)
	}
}

// T13/T15: a duplicate name that exists in another file (main file, other
// included file) is refused by the PROMPT: it stays open with the error toast
// so the user can fix the name, and nothing is written.
func TestTauT13_DuplicateNameClashKeepsThePromptOpen(t *testing.T) {
	t.Parallel()
	for _, clash := range []string{"main-1", "inc-1", "web-1"} {
		m, e := tmManaged(t, false)
		before := tmTree(t, e.dir)
		m = onHost(m, "db-1")
		m, _ = press(m, "d")
		m = typeText(m, clash)
		m, _ = press(m, "enter")
		if m.mode != modeDuplicate || !m.toastErr || !strings.Contains(m.toast, "already exists") {
			t.Errorf("duplicate as %s: mode=%v toast=%q err=%v, want the prompt still open with an 'already exists' error", clash, m.mode, m.toast, m.toastErr)
		}
		tmRequireSame(t, before, tmTree(t, e.dir))
		m, _ = press(m, "esc")
		if m.mode != modeList {
			t.Errorf("esc did not close the prompt: mode=%v", m.mode)
		}
	}
}

// T13: after D + y the list shows the new state (the host is gone from the
// snapshot the TUI displays), not the pre-delete one.
func TestTauT13_DeleteRefreshesTheList(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	m = onHost(m, "db-1")
	m, _ = press(m, "D", "y")
	if m.mode != modeList || m.toastErr || m.toast != "deleted db-1" {
		t.Fatalf("D y: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}
	if strings.Contains(readFile(t, e.managed), "Host db-1") {
		t.Fatalf("fixture: db-1 is still in the managed file")
	}
	for _, h := range m.hosts {
		if h.Name == "db-1" {
			t.Errorf("the model still lists db-1 after the delete (no reload)")
		}
	}
	m = tmExpandAll(m)
	if row := tmRow(plain(m), "db-1"); row != "" {
		t.Errorf("the view still shows db-1: %q", row)
	}
}

// T5/T15: the editor's live validation is a preview. Typing into the form,
// moving between fields (which validates) and cancelling must leave every file
// untouched (bytes, modes, mtimes).
func TestTauT15_LiveValidationWritesNothing(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	before := tmTree(t, e.dir)
	m = onHost(m, "web-1")
	m, _ = press(m, "e") // HostName field has focus
	m = set(m, "10.9.9.9")
	m, _ = press(m, "tab") // validates with the typed value
	m = set(m, "root")
	m, _ = press(m, "tab")
	if m.mode != modeEditor {
		t.Fatalf("fixture: mode=%v toast=%q", m.mode, m.toast)
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
	m, _ = press(m, "esc")
	if m.mode != modeList {
		t.Fatalf("esc: mode=%v", m.mode)
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
}
