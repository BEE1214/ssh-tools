package tui

// Black-box tests for P6 (PLAN-p6.md): the TUI editor on the managed file,
// clauses T7-T16. They use New(a) over temp configs only (see
// managed_helpers_test.go); nothing flips an internal switch, and none of
// them refers to the removed `editable` field.
//
// Tests marked "characterization" already pass against the skeleton.

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

// tmReason returns the snapshot's ReadOnlyReason of the (single) host.
func tmReason(t *testing.T, e *tmEnv, name string) string {
	t.Helper()
	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range s.Hosts {
		if h.Name == name {
			return h.ReadOnlyReason
		}
	}
	t.Fatalf("fixture: snapshot has no host %q", name)
	return ""
}

func tmImportMsg(host, file string) string {
	return fmt.Sprintf("host %q is defined in %s, which sshm does not manage; run 'sshm import'", host, file)
}

func tmIncludedMsg(host, file string) string {
	return (&app.UnmanagedHostError{Host: host, File: file}).Error()
}

// tmEditKeysRefused presses each key (from the same model) with the cursor on
// host and requires the error toast want, list mode and untouched files.
func tmEditKeysRefused(t *testing.T, m Model, e *tmEnv, host string, keys []string, want string) {
	t.Helper()
	m = onHost(m, host)
	for _, key := range keys {
		before := tmTree(t, e.dir)
		got, _ := press(m, key)
		if got.mode != modeList {
			t.Errorf("%s on %s: mode = %v, want list", key, host, got.mode)
		}
		if !got.toastErr || got.toast != want {
			t.Errorf("%s on %s: toast = %q (err=%v), want error toast %q", key, host, got.toast, got.toastErr, want)
		}
		tmRequireSame(t, before, tmTree(t, e.dir))
	}
}

// ---- T7 ------------------------------------------------------------------

// T7: the `editable` field is gone.
func TestTmT7_EditableFieldIsRemoved(t *testing.T) {
	t.Parallel()
	if _, ok := reflect.TypeOf(Model{}).FieldByName("editable"); ok {
		t.Error("Model still has the field `editable`; editing must depend on the snapshot only")
	}
}

// T7: a model built by New over a managed config can edit, with nothing
// flipped by hand.
func TestTmT7_ManagedModelEditsWithoutAnySwitch(t *testing.T) {
	t.Parallel()
	m, _ := tmManaged(t, false)
	m = onHost(m, "web-1")
	m, _ = press(m, "n")
	if m.mode != modeEditor || m.editor == nil || !m.editor.isNew {
		t.Fatalf("n in managed mode: mode=%v toast=%q", m.mode, m.toast)
	}
	m, _ = press(m, "esc")
	m, _ = press(m, "e")
	if m.mode != modeEditor || m.editor == nil || m.editor.name != "web-1" {
		t.Fatalf("e on a managed host: mode=%v toast=%q", m.mode, m.toast)
	}
}

// T7: running `sshm setup` elsewhere and pressing r turns editing on; before r
// the old snapshot still rules.
func TestTmT7_ReloadEnablesEditingAfterSetup(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmLegacy(t)
	m = onHost(m, "web-1")
	if m, _ = press(m, "n"); m.mode != modeList || m.toast != tmSetupToast(e) {
		t.Fatalf("legacy: mode=%v toast=%q", m.mode, m.toast)
	}
	if _, err := e.a.Setup(app.SetupOptions{}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Not reloaded yet: still the last loaded snapshot (legacy).
	if m, _ = press(m, "n"); m.mode != modeList || m.toast != tmSetupToast(e) {
		t.Errorf("before r: mode=%v toast=%q, want editing still off", m.mode, m.toast)
	}
	m, _ = press(m, "r")
	if m.toastErr || m.toast != "reloaded" {
		t.Fatalf("r: toast=%q err=%v", m.toast, m.toastErr)
	}
	for _, want := range []string{"e edit", "n new", "d dup", "D del"} {
		if h := tmHints(m); !strings.Contains(h, want) {
			t.Errorf("hints after r lack %q: %q", want, h)
		}
	}
	m, _ = press(m, "n")
	if m.mode != modeEditor || m.editor == nil || !m.editor.isNew {
		t.Errorf("after r: n gives mode=%v toast=%q, want the new-host form", m.mode, m.toast)
	}
}

// T7: the opposite way: the Include disappears, r turns editing off again.
func TestTmT7_ReloadDisablesEditingWhenTheIncludeDisappears(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	if m, _ = press(m, "n"); m.mode != modeEditor {
		t.Fatalf("fixture: n in managed mode: mode=%v toast=%q", m.mode, m.toast)
	}
	m, _ = press(m, "esc")
	tmWrite(t, e.main, "Host main-1\n  HostName 10.0.0.9\n", 0o600)
	m, _ = press(m, "r")
	m, _ = press(m, "n")
	if m.mode != modeList || m.toast != tmSetupToast(e) || !m.toastErr {
		t.Errorf("after the Include vanished: mode=%v toast=%q, want the setup toast", m.mode, m.toast)
	}
	if h := tmHints(m); strings.Contains(h, "e edit") || strings.Contains(h, "n new") {
		t.Errorf("hints still list edit keys in legacy mode: %q", h)
	}
}

// T7: a failed reload keeps the last loaded snapshot, so editing stays on.
// (Reading T7 literally: "iff the LAST LOADED snapshot has Managed".)
func TestTmT7_FailedReloadKeepsTheLastSnapshot(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	if err := os.Remove(e.main); err != nil {
		t.Fatal(err)
	}
	m, _ = press(m, "r")
	if m.loadErr == nil {
		t.Fatal("fixture: reload of a missing main file did not fail")
	}
	m, _ = press(m, "n")
	if m.mode != modeEditor {
		t.Errorf("after a failed reload: mode=%v toast=%q, want the new-host form (last snapshot was managed)", m.mode, m.toast)
	}
}

// T7: the config is replaced by one that is not set up while the form is open:
// the save is refused by the gate (P7 G1), shown in the form, and writes
// nothing. After the form is closed and the config reloaded, the next n is
// refused with the setup toast.
func TestTmT7_SaveAfterTheIncludeVanishedIsRefused(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab")
	m = set(m, "root")
	tmWrite(t, e.main, e.sub(tmLegacyMainBody), 0o600) // web-1 now lives in the main file, no Include
	before := readFile(t, e.main)
	m, _ = press(m, "ctrl+s")
	if m.mode != modeEditor || m.editor == nil || !strings.Contains(m.editor.err, "sshm is not set up") {
		t.Fatalf("save: mode=%v toast=%q, want the form to stay open with the gate error", m.mode, m.toast)
	}
	if got := readFile(t, e.main); got != before {
		t.Fatalf("the refused save wrote to the config:\n%s", got)
	}
	m, _ = press(m, "esc")
	m, _ = press(m, "r")
	if h := tmHints(m); strings.Contains(h, "e edit") {
		t.Errorf("hints after the reload still list edit keys: %q", h)
	}
	m, _ = press(m, "n")
	if m.mode != modeList || m.toast != tmSetupToast(e) {
		t.Errorf("n after the reload: mode=%v toast=%q, want the setup toast", m.mode, m.toast)
	}
}

// ---- T8 ------------------------------------------------------------------

// T8: in legacy mode e/n/d/D stay in list mode, write nothing and show the
// setup toast, wherever the cursor is.
func TestTmT8_LegacyKeysShowTheSetupToast(t *testing.T) {
	t.Parallel()
	m, e := tmLegacy(t)
	want := tmSetupToast(e)
	keys := []string{"e", "n", "d", "D"}
	for _, host := range []string{"web-1", "inc-1"} { // main-file host, included host
		tmEditKeysRefused(t, m, e, host, keys, want)
	}
	// On a group header.
	if len(m.rows) == 0 || !m.rows[0].header {
		t.Fatal("fixture: first row is not a group header")
	}
	m.cursor = 0
	for _, key := range keys {
		before := tmTree(t, e.dir)
		got, _ := press(m, key)
		if got.mode != modeList || !got.toastErr || got.toast != want {
			t.Errorf("%s on a group header: mode=%v toast=%q err=%v", key, got.mode, got.toast, got.toastErr)
		}
		tmRequireSame(t, before, tmTree(t, e.dir))
	}
}

// T8: legacy hints omit the edit keys, the help overlay omits the edit key
// lines and carries the sentence.
func TestTmT8_LegacyHintsAndHelp(t *testing.T) {
	t.Parallel()
	m, _ := tmLegacy(t)
	h := tmHints(m)
	for _, bad := range []string{"e edit", "n new", "d dup", "D del"} {
		if strings.Contains(h, bad) {
			t.Errorf("legacy hints contain %q: %q", bad, h)
		}
	}
	for _, keep := range []string{"enter connect", "/ filter", "? help", "q quit"} {
		if !strings.Contains(h, keep) { // characterization
			t.Errorf("legacy hints lack %q: %q", keep, h)
		}
	}
	_, help := tmHelp(t, m)
	if !strings.Contains(help, "Editing is available after 'sshm setup'.") {
		t.Errorf("legacy help lacks the sentence:\n%s", help)
	}
	for _, bad := range []string{"edit host", "new host", "duplicate host", "delete host"} {
		if strings.Contains(help, bad) {
			t.Errorf("legacy help lists %q:\n%s", bad, help)
		}
	}
	if !strings.Contains(help, "move cursor") { // characterization
		t.Errorf("legacy help lost the navigation keys:\n%s", help)
	}
}

// ---- T9 ------------------------------------------------------------------

func TestTmT9_ManagedHintsAndHelpListTheEditKeys(t *testing.T) {
	t.Parallel()
	m, _ := tmManaged(t, false)
	h := tmHints(m)
	for _, want := range []string{"e edit", "n new", "d dup", "D del"} {
		if !strings.Contains(h, want) {
			t.Errorf("managed hints lack %q: %q", want, h)
		}
	}
	_, help := tmHelp(t, m)
	for _, want := range []string{"edit host", "new host", "duplicate host", "delete host"} {
		if !strings.Contains(help, want) {
			t.Errorf("managed help lacks %q:\n%s", want, help)
		}
	}
	if strings.Contains(help, "Editing is available after 'sshm setup'") {
		t.Errorf("managed help carries the legacy sentence:\n%s", help)
	}
}

// ---- T10 -----------------------------------------------------------------

// T10: e/d/D on a host outside the managed file: the reason as an error toast.
func TestTmT10_ReadOnlyHostsShowTheirReasonVerbatim(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	keys := []string{"e", "d", "D"}
	for host, want := range map[string]string{
		"main-1": tmImportMsg("main-1", e.main),   // main file: with the import hint
		"inc-1":  tmIncludedMsg("inc-1", e.extra), // other included file: without it
		"inc-2":  tmIncludedMsg("inc-2", e.extra),
	} {
		if got := tmReason(t, e, host); got != want {
			t.Errorf("snapshot reason of %s = %q, want %q", host, got, want)
		}
		tmEditKeysRefused(t, m, e, host, keys, want)
	}
}

// T10 non-firing: managed-file hosts are not refused.
func TestTmT10_ManagedHostsAreNotRefused(t *testing.T) {
	t.Parallel()
	m, _ := tmManaged(t, false)
	m = onHost(m, "web-1")
	for key, want := range map[string]mode{"e": modeEditor, "d": modeDuplicate, "D": modeDelete} {
		got, _ := press(m, key)
		if got.mode != want || got.toastErr {
			t.Errorf("%s on a managed host: mode=%v toast=%q, want mode %v", key, got.mode, got.toast, want)
		}
	}
}

// T10: n opens the new-host form even with the cursor on a read-only host.
func TestTmT10_NewStillOpensOnAReadOnlyHost(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	for _, host := range []string{"main-1", "inc-1"} {
		before := tmTree(t, e.dir)
		got, _ := press(onHost(m, host), "n")
		if got.mode != modeEditor || got.editor == nil || !got.editor.isNew || got.toastErr {
			t.Errorf("n on %s: mode=%v toast=%q", host, got.mode, got.toast)
		}
		tmRequireSame(t, before, tmTree(t, e.dir))
	}
}

// T10: gated and DevPod hosts keep their own toasts, which come first, even
// when the host is also outside the managed file.
func TestTmT10_GatedAndDevPodToastsTakePrecedence(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmManaged(t, true) // group "old" disabled (old-1, old-2 in the managed file)
	// Gate main-1's group too: a gated host that is ALSO outside the managed file.
	sidecar := e.managed + ".sshm-groups"
	writeFile(t, sidecar, readFile(t, sidecar)+"main\n")
	tmBackdate(t, e.dir)
	m = tmModel(e)

	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	gated := map[string]bool{}
	for _, h := range snap.Hosts {
		gated[h.Name] = h.Gated
	}
	if !gated["main-1"] || !gated["old-1"] || gated["web-1"] {
		t.Fatalf("fixture: gate state = %v", gated)
	}

	keys := []string{"e", "d", "D"}
	for _, host := range []string{"main-1", "old-1"} {
		m2 := onHost(m, host)
		for _, key := range keys {
			before := tmTree(t, e.dir)
			got, _ := press(m2, key)
			if got.mode != modeList || !got.toastErr || !strings.Contains(got.toast, "is in disabled group") || strings.Contains(got.toast, "does not manage") {
				t.Errorf("%s on gated %s: mode=%v toast=%q, want the disabled-group toast", key, host, got.mode, got.toast)
			}
			tmRequireSame(t, before, tmTree(t, e.dir))
		}
	}
	for _, host := range []string{"other.devpod", "demo.devpod"} { // DevPod: outside / inside the managed file
		tmEditKeysRefused(t, m, e, host, keys, host+" is read-only (managed by DevPod)")
	}
}

// ---- T11 -----------------------------------------------------------------

func TestTmT11_ManagedModeTags(t *testing.T) {
	t.Parallel()
	m, _ := tmManaged(t, true)
	m = tmExpandAll(m)
	v := plain(m)
	cases := []struct {
		host      string
		want, not []string
	}{
		{"web-1", nil, []string{"[main]", "[included]", "[read-only]"}},
		{"db-1", nil, []string{"[main]", "[included]"}},
		{"nouser-1", nil, []string{"[main]", "[included]"}},
		{"bare-1", nil, []string{"[main]", "[included]"}},
		{"main-1", []string{"[main]"}, []string{"[included]"}},
		{"inc-1", []string{"[included]"}, []string{"[main]"}},
		{"inc-2", []string{"[included]"}, []string{"[main]"}},
		{"other.devpod", []string{"[main]", "[read-only]"}, []string{"[included]"}},
		{"demo.devpod", []string{"[read-only]"}, []string{"[main]", "[included]"}},
		{"old-1", []string{"[disabled]"}, []string{"[main]", "[included]"}},
	}
	for _, c := range cases {
		line := tmRow(v, c.host)
		if line == "" {
			t.Errorf("no row for %s in:\n%s", c.host, v)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(line, w) {
				t.Errorf("%s row lacks %s: %q", c.host, w, line)
			}
		}
		for _, n := range c.not {
			if strings.Contains(line, n) {
				t.Errorf("%s row has %s: %q", c.host, n, line)
			}
		}
	}
}

// T11: the tags also show in the flat list while filtering.
func TestTmT11_TagsInTheFilteredList(t *testing.T) {
	t.Parallel()
	m, _ := tmManaged(t, false)
	m, _ = press(m, "/")
	m = typeText(m, "-1")
	m, _ = press(m, "enter")
	v := plain(m)
	if l := tmRow(v, "main-1"); !strings.Contains(l, "[main]") {
		t.Errorf("filtered main-1 row lacks [main]: %q", l)
	}
	if l := tmRow(v, "inc-1"); !strings.Contains(l, "[included]") {
		t.Errorf("filtered inc-1 row lacks [included]: %q", l)
	}
	if l := tmRow(v, "web-1"); l == "" || strings.Contains(l, "[main]") || strings.Contains(l, "[included]") {
		t.Errorf("filtered web-1 row: %q", l)
	}
}

// T11: legacy keeps today's [included] and never shows [main].
func TestTmT11_LegacyTags(t *testing.T) {
	t.Parallel()
	m, _ := tmLegacy(t)
	m = tmExpandAll(m)
	v := plain(m)
	if strings.Contains(v, "[main]") {
		t.Errorf("legacy view shows [main]:\n%s", v)
	}
	if l := tmRow(v, "inc-1"); !strings.Contains(l, "[included]") { // characterization
		t.Errorf("legacy inc-1 row lacks [included]: %q", l)
	}
	for _, host := range []string{"web-1", "db-1", "main-1"} {
		if l := tmRow(v, host); l == "" || strings.Contains(l, "[included]") {
			t.Errorf("legacy %s row: %q", host, l)
		}
	}
	m, _ = press(m, "/")
	m = typeText(m, "main-")
	m, _ = press(m, "enter")
	if v := plain(m); strings.Contains(v, "[main]") {
		t.Errorf("legacy filtered view shows [main]:\n%s", v)
	}
}

// T11: the help overlay explains both tags in managed mode, and does not
// mention [main] in legacy mode.
func TestTmT11_HelpExplainsTheTags(t *testing.T) {
	t.Parallel()
	m, _ := tmManaged(t, false)
	_, help := tmHelp(t, m)
	for _, want := range []string{"[main]", "[included]"} {
		if !strings.Contains(help, want) {
			t.Errorf("managed help does not explain %s:\n%s", want, help)
		}
	}
	lm, _ := tmLegacy(t)
	if _, lhelp := tmHelp(t, lm); strings.Contains(lhelp, "[main]") {
		t.Errorf("legacy help mentions [main]:\n%s", lhelp)
	}
}

// ---- T12 -----------------------------------------------------------------

// T12: an edit changes only the managed file, surgically.
func TestTmT12_EditSavesOnlyIntoTheManagedFile(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmManaged(t, false)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)
	treeBefore := tmTree(t, e.dir)
	sshBefore := tmResolveAll(t, e)

	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab") // HostName -> User
	m = set(m, "root")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList || m.toastErr || !strings.Contains(m.toast, "saved web-1") {
		t.Fatalf("save: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}

	if got := readFile(t, e.main); got != origMain {
		t.Errorf("main file changed:\n%s", got)
	}
	want := strings.Replace(origManaged, "  User alice\n", "  User root\n", 1)
	if got := readFile(t, e.managed); got != want {
		t.Errorf("managed file after the edit:\n%s\nwant (comments and other lines kept):\n%s", got, want)
	}
	for _, keep := range []string{"# primary web host", "# the web node", "# keepalive for web-1", "ServerAliveInterval 40", "Port 2222"} {
		if !strings.Contains(readFile(t, e.managed), keep) {
			t.Errorf("managed file lost %q", keep)
		}
	}
	tmOnlyChanged(t, treeBefore, tmTree(t, e.dir), e.managed)
	if fi, err := os.Stat(e.managed); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("managed file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	after := tmResolveAll(t, e)
	if got := after["web-1"]["user"]; len(got) != 1 || got[0] != "root" {
		t.Errorf("ssh -G web-1 user = %v, want [root]", got)
	}
	tmRequireOnlyChangedOptions(t, sshBefore, after, "web-1", "user")
}

func TestTmT12_EditSeveralFields(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmManaged(t, false)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)
	sshBefore := tmResolveAll(t, e)

	m = onHost(m, "web-1")
	m, _ = press(m, "e")
	m = set(m, "10.0.0.11") // HostName
	m, _ = press(m, "tab", "tab")
	m = set(m, "2223") // Port
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList || !strings.Contains(m.toast, "saved web-1") {
		t.Fatalf("save: mode=%v toast=%q", m.mode, m.toast)
	}
	want := strings.Replace(strings.Replace(origManaged, "HostName 10.0.0.1\n", "HostName 10.0.0.11\n", 1), "Port 2222\n", "Port 2223\n", 1)
	if got := readFile(t, e.managed); got != want {
		t.Errorf("managed file:\n%s\nwant:\n%s", got, want)
	}
	if readFile(t, e.main) != origMain {
		t.Error("main file changed")
	}
	tmRequireOnlyChangedOptions(t, sshBefore, tmResolveAll(t, e), "web-1", "hostname", "port")
}

// T12 non-firing: cancelling and saving without changes write nothing.
func TestTmT12_CancelAndNoChangeWriteNothing(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	before := tmTree(t, e.dir)
	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab")
	m = set(m, "root")
	m, cmd := press(m, "esc")
	if m.mode != modeList || m.editor != nil || isQuit(cmd) {
		t.Errorf("esc: mode=%v", m.mode)
	}
	tmRequireSame(t, before, tmTree(t, e.dir))

	m, _ = press(m, "e", "ctrl+s")
	if m.mode != modeList || m.toast != "no changes" {
		t.Errorf("save without changes: mode=%v toast=%q", m.mode, m.toast)
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
}

// ---- T13 -----------------------------------------------------------------

func TestTmT13_NewHostIsAppendedToTheManagedFile(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmManaged(t, false)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)
	treeBefore := tmTree(t, e.dir)
	sshBefore := tmResolveAll(t, e)

	m = onHost(m, "web-1")
	m, _ = press(m, "n")
	if m.mode != modeEditor {
		t.Fatalf("n: mode=%v toast=%q", m.mode, m.toast)
	}
	m = tmFillNew(m, "new-1", "10.0.0.50", "dave", "", "/keys/new1")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList || m.toastErr || m.toast != "saved new-1" {
		t.Fatalf("save: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}
	if curKey(m) != "h:new-1" {
		t.Errorf("cursor on %q, want h:new-1", curKey(m))
	}

	got := readFile(t, e.managed)
	if !strings.HasPrefix(got, origManaged) {
		t.Errorf("the new host must be appended, existing text untouched:\n%s", got)
	}
	tail := strings.TrimPrefix(got, origManaged)
	for _, want := range []string{"Host new-1\n", "HostName 10.0.0.50\n", "User dave\n", "IdentityFile /keys/new1\n"} {
		if !strings.Contains(tail, want) {
			t.Errorf("appended text lacks %q:\n%s", want, tail)
		}
	}
	if strings.Count(got, "Host new-1") != 1 {
		t.Errorf("Host new-1 appears %d times", strings.Count(got, "Host new-1"))
	}
	if readFile(t, e.main) != origMain {
		t.Error("main file changed")
	}
	tmOnlyChanged(t, treeBefore, tmTree(t, e.dir), e.managed)
	tmRequireOnlyChangedOptions(t, sshBefore, tmResolveAll(t, e), "")
	nh := tmSSHG(t, e.main, "new-1")
	if nh["hostname"][0] != "10.0.0.50" || nh["user"][0] != "dave" || nh["identityfile"][0] != "/keys/new1" {
		t.Errorf("ssh -G new-1: hostname=%v user=%v identityfile=%v", nh["hostname"], nh["user"], nh["identityfile"])
	}
}

func TestTmT13_DuplicateCreatesTheCopyInTheManagedFile(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmManaged(t, false)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)
	treeBefore := tmTree(t, e.dir)
	sshBefore := tmResolveAll(t, e)

	m = onHost(m, "web-1")
	m, _ = press(m, "d")
	if m.mode != modeDuplicate {
		t.Fatalf("d: mode=%v toast=%q", m.mode, m.toast)
	}
	m = typeText(m, "web-9")
	m, _ = press(m, "enter")
	if m.mode != modeList || m.toastErr || !strings.Contains(m.toast, "web-9") {
		t.Fatalf("duplicate: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}
	if curKey(m) != "h:web-9" {
		t.Errorf("cursor on %q, want h:web-9", curKey(m))
	}

	got := readFile(t, e.managed)
	if strings.Count(got, "Host web-9") != 1 {
		t.Errorf("Host web-9 appears %d times:\n%s", strings.Count(got, "Host web-9"), got)
	}
	for _, l := range tmLines(origManaged) { // nothing of the original is lost
		if strings.TrimSpace(l) != "" && strings.Count(got, l) < strings.Count(origManaged, l) {
			t.Errorf("line %q of the original managed file was lost", l)
		}
	}
	if readFile(t, e.main) != origMain {
		t.Error("main file changed")
	}
	tmOnlyChanged(t, treeBefore, tmTree(t, e.dir), e.managed)
	tmRequireOnlyChangedOptions(t, sshBefore, tmResolveAll(t, e), "")
	src, dup := tmSSHG(t, e.main, "web-1"), tmSSHG(t, e.main, "web-9")
	for _, k := range []string{"hostname", "user", "port", "identityfile", "serveraliveinterval"} {
		if !reflect.DeepEqual(src[k], dup[k]) {
			t.Errorf("ssh -G: %s of the copy = %v, want the source's %v", k, dup[k], src[k])
		}
	}
}

func TestTmT13_DuplicateNameThatExistsInTheMainFileIsRefused(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	before := tmTree(t, e.dir)
	m = onHost(m, "web-1")
	m, _ = press(m, "d")
	m = typeText(m, "main-1")
	m, _ = press(m, "enter")
	if !m.toastErr || !strings.Contains(m.toast, "already exists") {
		t.Errorf("toast=%q err=%v, want an 'already exists' error", m.toast, m.toastErr)
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
}

func TestTmT13_DeleteRemovesTheBlockFromTheManagedFile(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmManaged(t, false)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)
	treeBefore := tmTree(t, e.dir)
	sshBefore := tmResolveAll(t, e)

	m = onHost(m, "db-1")
	m, _ = press(m, "D")
	if m.mode != modeDelete {
		t.Fatalf("D: mode=%v toast=%q", m.mode, m.toast)
	}
	m, _ = press(m, "y")
	if m.mode != modeList || m.toastErr || !strings.Contains(m.toast, "deleted db-1") {
		t.Fatalf("delete: mode=%v toast=%q err=%v", m.mode, m.toast, m.toastErr)
	}

	got := readFile(t, e.managed)
	for _, gone := range []string{"Host db-1", "10.0.0.2", "bob", "/keys/db1"} {
		if strings.Contains(got, gone) {
			t.Errorf("managed file still has %q:\n%s", gone, got)
		}
	}
	for _, block := range []string{
		"Host web-1\n  # the web node\n  HostName 10.0.0.1\n  User alice\n  Port 2222\n  IdentityFile /keys/web1\n  # keepalive for web-1\n  ServerAliveInterval 40\n",
		"Host nouser-1\n  HostName 10.0.0.3\n  IdentityFile /keys/n1\n",
		"Host bare-1\n  HostName 10.0.0.4\n  User carol\n",
		"Host old-2\n  HostName 10.0.0.32\n  IdentityFile /keys/old2\n",
	} {
		if !tmSubLines(got, block) {
			t.Errorf("a neighbouring block was damaged, missing:\n%s\nin:\n%s", block, got)
		}
	}
	if !strings.HasPrefix(got, "# Managed by sshm. Hosts in this file are edited by sshm.\n\n# primary web host\n") {
		t.Errorf("header / leading comment changed:\n%s", got)
	}
	if len(got) >= len(origManaged) {
		t.Error("managed file did not shrink")
	}
	if readFile(t, e.main) != origMain {
		t.Error("main file changed")
	}
	tmOnlyChanged(t, treeBefore, tmTree(t, e.dir), e.managed)
	after := tmResolveAll(t, e)
	if got := after["db-1"]["hostname"]; len(got) != 1 || got[0] != "db-1" {
		t.Errorf("ssh -G db-1 hostname = %v, want the unresolved name db-1", got)
	}
	tmRequireOnlyChangedOptions(t, sshBefore, after, "db-1", "hostname", "user", "identityfile")
}

// T13 non-firing: answering n (or esc) to the confirmation deletes nothing.
func TestTmT13_DeleteCancelledWritesNothing(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	before := tmTree(t, e.dir)
	m = onHost(m, "db-1")
	for _, key := range []string{"n", "esc"} {
		m, _ = press(m, "D")
		if m.mode != modeDelete {
			t.Fatalf("D: mode=%v toast=%q", m.mode, m.toast)
		}
		m, _ = press(m, key)
		if m.mode != modeList {
			t.Errorf("%s: mode=%v", key, m.mode)
		}
	}
	tmRequireSame(t, before, tmTree(t, e.dir))
}

// ---- T14 -----------------------------------------------------------------

// T14: a value the form lets through but ssh rejects: the writer rolls back,
// the form stays open with the error, the file is unchanged; fixing the value
// then saves.
func TestTmT14_SSHRejectedValueKeepsTheFormOpen(t *testing.T) {
	t.Parallel()
	tmNeedSSH(t)
	m, e := tmManaged(t, false)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)

	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab", "tab") // HostName -> User -> Port
	m = set(m, "notaport")             // the form has no port validation (out of scope in PLAN-p6.md)
	m, _ = press(m, "ctrl+s")
	if m.mode != modeEditor || m.editor == nil {
		t.Fatalf("after a failed save: mode=%v toast=%q, want the form still open", m.mode, m.toast)
	}
	if m.editor.err == "" {
		t.Fatal("the failed save left no error text in the form")
	}
	if head := m.editor.err; !strings.Contains(plain(m), firstChars(head, 30)) {
		t.Errorf("the form does not show the error %q:\n%s", head, plain(m))
	}
	if readFile(t, e.managed) != origManaged || readFile(t, e.main) != origMain {
		t.Error("a file changed although the save failed")
	}

	m = set(m, "2223")
	m, _ = press(m, "ctrl+s")
	if m.mode != modeList || !strings.Contains(m.toast, "saved web-1") {
		t.Fatalf("after fixing the value: mode=%v toast=%q", m.mode, m.toast)
	}
	if want := strings.Replace(origManaged, "Port 2222\n", "Port 2223\n", 1); readFile(t, e.managed) != want {
		t.Errorf("managed file:\n%s", readFile(t, e.managed))
	}
}

// T14: an app-level failure of another kind: the managed directory becomes
// read-only after the form opened.
func TestTmT14_UnwritableManagedDirectoryKeepsTheFormOpen(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	m, e := tmManaged(t, false)
	origManaged, origMain := readFile(t, e.managed), readFile(t, e.main)

	m = onHost(m, "web-1")
	m, _ = press(m, "e", "tab")
	m = set(m, "root")
	dir := filepath.Dir(e.managed)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	m, _ = press(m, "ctrl+s")
	if m.mode != modeEditor || m.editor == nil || m.editor.err == "" {
		t.Fatalf("after a failed save: mode=%v toast=%q, want the form open with an error", m.mode, m.toast)
	}
	if !strings.Contains(plain(m), firstChars(m.editor.err, 30)) {
		t.Errorf("the form does not show the error %q", m.editor.err)
	}
	os.Chmod(dir, 0o700)
	if readFile(t, e.managed) != origManaged || readFile(t, e.main) != origMain {
		t.Error("a file changed although the save failed")
	}
	if strings.Contains(m.toast, "saved") {
		t.Errorf("toast claims a save: %q", m.toast)
	}
}

func firstChars(s string, n int) string {
	r := []rune(strings.SplitN(s, "\n", 2)[0])
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// ---- T15 -----------------------------------------------------------------

// T15: the live validation of an edit works for managed-file hosts: a
// warning appears and disappears, and no ownership error shows up.
func TestTmT15_LiveValidationForManagedHosts(t *testing.T) {
	t.Parallel()
	m, _ := tmManaged(t, false)
	const warn = "no IdentityFile set"

	m1, _ := press(onHost(m, "bare-1"), "e")
	if m1.mode != modeEditor || m1.editor == nil {
		t.Fatalf("e on bare-1: mode=%v toast=%q", m1.mode, m1.toast)
	}
	if m1.editor.err != "" || !strings.Contains(plain(m1), warn) {
		t.Errorf("bare-1 (no key): err=%q, want the missing-identity warning:\n%s", m1.editor.err, plain(m1))
	}

	m2, _ := press(onHost(m, "db-1"), "e")
	if m2.mode != modeEditor || m2.editor == nil {
		t.Fatalf("e on db-1: mode=%v toast=%q", m2.mode, m2.toast)
	}
	if m2.editor.err != "" || strings.Contains(plain(m2), warn) {
		t.Fatalf("db-1: err=%q view:\n%s", m2.editor.err, plain(m2))
	}
	m2, _ = press(m2, "tab", "tab", "tab") // IdentityFile
	m2 = set(m2, "")
	m2, _ = press(m2, "tab") // moving on re-validates
	if !strings.Contains(plain(m2), warn) {
		t.Errorf("clearing the key shows no warning:\n%s", plain(m2))
	}
}

// T15: a new name that exists only in the main file, only in another included
// file or in the managed file gives the duplicate error and cannot be saved.
func TestTmT15_NewHostNamesThatExistElsewhere(t *testing.T) {
	t.Parallel()
	m, e := tmManaged(t, false)
	for _, name := range []string{"main-1", "inc-1", "web-1"} {
		before := tmTree(t, e.dir)
		got, _ := press(m, "n")
		if got.mode != modeEditor {
			t.Fatalf("n: mode=%v toast=%q", got.mode, got.toast)
		}
		got = typeText(got, name)
		got, _ = press(got, "tab")
		if v := plain(got); !strings.Contains(v, "already exists") {
			t.Errorf("name %q: no duplicate error in:\n%s", name, v)
		}
		got, _ = press(got, "ctrl+s")
		if got.mode != modeEditor {
			t.Errorf("name %q: ctrl+s left the form (mode=%v)", name, got.mode)
		}
		tmRequireSame(t, before, tmTree(t, e.dir))
	}
	// Non-firing: a fresh name validates without that error.
	got, _ := press(m, "n")
	got = typeText(got, "brand-new")
	got, _ = press(got, "tab")
	if v := plain(got); strings.Contains(v, "already exists") {
		t.Errorf("fresh name reports a duplicate:\n%s", v)
	}
}

// ---- T16 -----------------------------------------------------------------

// tmImportViolations lists the imports of src that point into this module
// but are neither internal/app nor internal/domain.
func tmImportViolations(t *testing.T, module, filename, src string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var bad []string
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if path == module || strings.HasPrefix(path, module+"/") {
			if path != module+"/internal/app" && path != module+"/internal/domain" {
				bad = append(bad, path)
			}
		}
	}
	return bad
}

func tmModulePath(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatal("no module line in go.mod")
	return ""
}

// T16 (characterization): the package imports only app and domain from this
// module.
func TestTmT16_TUIImportsOnlyAppAndDomain(t *testing.T) {
	t.Parallel()
	module := tmModulePath(t)
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v %v", files, err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		if bad := tmImportViolations(t, module, f, string(src)); len(bad) > 0 {
			t.Errorf("%s imports %v; internal/tui may import only internal/app and internal/domain", f, bad)
		}
	}
	if checked < 5 {
		t.Errorf("only %d production files checked: the guard looks vacuous", checked)
	}
}

// T16: the checker itself fires on a layering violation and not on a clean file.
func TestTmT16_CheckerFiresOnViolations(t *testing.T) {
	t.Parallel()
	const module = "example.test/mod"
	clean := `package tui
import (
	"fmt"
	"example.test/mod/internal/app"
	"example.test/mod/internal/domain"
	"charm.land/bubbletea/v2"
)
`
	if bad := tmImportViolations(t, module, "clean.go", clean); len(bad) != 0 {
		t.Errorf("clean file flagged: %v", bad)
	}
	dirty := `package tui
import (
	"example.test/mod/internal/app"
	"example.test/mod/internal/config"
	"example.test/mod/internal/cli"
)
`
	if bad := tmImportViolations(t, module, "dirty.go", dirty); len(bad) != 2 {
		t.Errorf("dirty file flagged %v, want config and cli", bad)
	}
}
