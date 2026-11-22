package tui

// T18 (PLAN-p6.md 4.2) in the TUI: a managed file that an unconditional
// Include reaches but that cannot be loaded disables the edit keys with the
// toast `editing disabled: <Snapshot.ManagedProblem>`. A missing managed file
// and a missing Include keep the T8 "needs setup" toast; a healthy file edits.
//
// Fixtures: the helpers of managed_helpers_test.go (temp dirs, placeholders).

import (
	"os"
	"strings"
	"testing"
)

// tmpBrokenManaged is the managed fixture plus a disabled-group start marker
// without an end marker, which config.Parse refuses.
const tmpBrokenManaged = tmManagedBody + `
# sshm disabled group=zzz start
#Host zzz-1
#  HostName 10.0.0.50
`

func tmpBrokenEnv(t *testing.T) (Model, *tmEnv, string) {
	t.Helper()
	e := tmNewEnv(t, tmMainBody, tmpBrokenManaged)
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("fixture: Snapshot: %v", err)
	}
	if snap.ManagedProblem == "" {
		t.Fatalf("fixture: ManagedProblem is empty for an unparsable managed file")
	}
	return tmModel(e), e, snap.ManagedProblem
}

func TestTmpT18_EditKeysShowEditingDisabled(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"e", "n", "d", "D"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			m, e, problem := tmpBrokenEnv(t)
			if m.managed {
				t.Fatalf("model is managed with an unloadable managed file")
			}
			if !strings.Contains(problem, e.managed) {
				t.Errorf("ManagedProblem = %q, want it to name %s", problem, e.managed)
			}
			before := tmTree(t, e.dir)

			m, cmd := press(m, key)
			want := "editing disabled: " + problem
			if m.toast != want || !m.toastErr {
				t.Errorf("toast after %q = %q (err=%v), want error toast %q", key, m.toast, m.toastErr, want)
			}
			if strings.Contains(m.toast, "needs setup") {
				t.Errorf("toast %q is the T8 text, want the editing-disabled text", m.toast)
			}
			if m.mode != modeList || m.editor != nil {
				t.Errorf("mode after %q = %v, want the list (editing is disabled)", key, m.mode)
			}
			if isQuit(cmd) {
				t.Errorf("key %q quit the program", key)
			}
			if !strings.Contains(plain(m), "editing disabled") {
				t.Errorf("the view does not show the toast:\n%s", plain(m))
			}
			tmRequireSame(t, before, tmTree(t, e.dir))
		})
	}
}

// With a host under the cursor (a host of the main file, still listed) the
// edit keys give the same toast and still write nothing.
func TestTmpT18_OnAHostRowStillDisabled(t *testing.T) {
	t.Parallel()
	m, e, problem := tmpBrokenEnv(t)
	m = onHost(m, "main-1")
	before := tmTree(t, e.dir)
	for _, key := range []string{"e", "d", "D", "n"} {
		m, _ = press(m, key)
		if want := "editing disabled: " + problem; m.toast != want {
			t.Errorf("toast after %q = %q, want %q", key, m.toast, want)
		}
		if m.mode != modeList {
			t.Fatalf("mode after %q = %v, want the list", key, m.mode)
		}
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
}

func TestTmpT18_MissingManagedFileKeepsTheSetupToast(t *testing.T) {
	t.Parallel()
	e := tmNewEnv(t, tmMainBody, tmAbsent)
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.ManagedProblem != "" {
		t.Fatalf("ManagedProblem = %q for a missing managed file, want empty", snap.ManagedProblem)
	}
	m := tmModel(e)
	before := tmTree(t, e.dir)
	for _, key := range []string{"e", "n", "d", "D"} {
		m, _ = press(m, key)
		if m.toast != tmSetupToast(e) || !m.toastErr {
			t.Errorf("toast after %q = %q, want the T8 toast %q", key, m.toast, tmSetupToast(e))
		}
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
}

func TestTmpT18_NoIncludeKeepsTheSetupToast(t *testing.T) {
	t.Parallel()
	for name, managedBody := range map[string]string{"absent": tmAbsent, "broken": tmpBrokenManaged} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := tmNewEnv(t, tmLegacyMainBody, managedBody)
			snap, err := e.a.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if snap.ManagedProblem != "" {
				t.Fatalf("ManagedProblem = %q without an Include, want empty", snap.ManagedProblem)
			}
			m := tmModel(e)
			before := tmTree(t, e.dir)
			for _, key := range []string{"e", "n", "d", "D"} {
				m, _ = press(m, key)
				if m.toast != tmSetupToast(e) || !m.toastErr {
					t.Errorf("toast after %q = %q, want the T8 toast %q", key, m.toast, tmSetupToast(e))
				}
			}
			tmRequireSame(t, before, tmTree(t, e.dir))
		})
	}
}

func TestTmpT18_HealthyManagedFileEdits(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.ManagedProblem != "" {
		t.Fatalf("ManagedProblem = %q for a healthy managed file, want empty", snap.ManagedProblem)
	}
	m = onHost(m, "web-1")
	m, _ = press(m, "e")
	if m.mode != modeEditor {
		t.Errorf("mode after e = %v (toast %q), want the editor", m.mode, m.toast)
	}
	if strings.Contains(m.toast, "editing disabled") {
		t.Errorf("toast %q on a healthy managed file", m.toast)
	}
}

// The problem follows reloads: fixing the file and pressing r re-enables
// editing; a failed reload keeps the previous problem like the other fields.
func TestTmpT18_ReloadFollowsTheFile(t *testing.T) {
	t.Parallel()
	m, e, problem := tmpBrokenEnv(t)

	// A failed reload (main file gone) keeps the old state.
	mainBytes, err := os.ReadFile(e.main)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.main); err != nil {
		t.Fatal(err)
	}
	m, _ = press(m, "r")
	if m.loadErr == nil {
		t.Fatalf("reload with a missing main file did not fail")
	}
	m, _ = press(m, "e")
	if want := "editing disabled: " + problem; m.toast != want {
		t.Errorf("after a failed reload the toast = %q, want the old problem %q", m.toast, want)
	}
	tmWrite(t, e.main, string(mainBytes), 0o600)

	// Still broken: the same toast after a successful reload.
	m, _ = press(m, "r")
	if m.loadErr != nil {
		t.Fatalf("reload: %v", m.loadErr)
	}
	m, _ = press(m, "e")
	if want := "editing disabled: " + problem; m.toast != want {
		t.Errorf("after reload the toast = %q, want %q", m.toast, want)
	}

	// Fixed: r re-enables editing.
	tmWrite(t, e.managed, e.sub(tmManagedBody), 0o600)
	m, _ = press(m, "r")
	if !m.managed {
		t.Fatalf("model is not managed after the file was fixed and reloaded")
	}
	m = onHost(m, "web-1")
	m, _ = press(m, "e")
	if m.mode != modeEditor {
		t.Errorf("mode after e = %v (toast %q), want the editor", m.mode, m.toast)
	}
}
