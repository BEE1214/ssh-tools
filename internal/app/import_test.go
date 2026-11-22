package app

// Black-box tests for `sshm import` (PLAN-p3-p4.md section 5, clauses I1-I12,
// result semantics 5.1). Equivalence is judged by real `ssh -F <main> -G`.
//
// I12 (lost updates between planning and the write) cannot be reached from the
// outside without a test seam; it has no test here.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

const imMain = `Include @M@
Include @D@/extra.conf

# global note about this file

# web servers
Host web-1
  HostName 10.0.0.1
  User alice
  # inner comment
  Port 2222

Host *-staging
  User stage

# group: infra
# database primary
Host db-1
    HostName 10.0.0.3

Host a b
  User multi

# DevPod Start demo
Host demo
  HostName localhost
# DevPod End demo

Match host matched.example.com
  User matchuser

Host solo
	HostName 10.0.0.4
	user tabby

Host *
  ServerAliveInterval 30
`

const imExtra = "Host inc-1\n  HostName 10.0.0.70\n"

var imHosts = []string{"web-1", "db-1", "solo", "demo", "a", "b", "matched.example.com", "prod-staging", "inc-1"}

func newImEnv(t *testing.T) *mgEnv { return newImEnvWith(t, imMain, mgManagedHeader) }

func newImEnvWith(t *testing.T, mainBody, managedBody string) *mgEnv {
	t.Helper()
	e := newMgEnv(t, mainBody, managedBody)
	mgWrite(t, e.extra(), imExtra, 0o600)
	return e
}

// imSpans returns the 1-based [from,to] ranges of the three movable blocks of
// imMain, in file order, computed from the fixture text.
func imSpans(t *testing.T, orig string) [][2]int {
	t.Helper()
	return [][2]int{
		{mgLineOf(t, orig, "# web servers"), mgLineOf(t, orig, "  Port 2222")},
		{mgLineOf(t, orig, "# group: infra"), mgLineOf(t, orig, "    HostName 10.0.0.3")},
		{mgLineOf(t, orig, "Host solo"), mgLineOf(t, orig, "\tuser tabby")},
	}
}

func imStayAt(res ImportResult, file string, line int) (ImportStay, bool) {
	for _, s := range res.Stay {
		if s.File == file && s.Line == line {
			return s, true
		}
	}
	return ImportStay{}, false
}

func imNames(res ImportResult) []string {
	var out []string
	for _, b := range res.Move {
		out = append(out, b.Name)
	}
	return out
}

// ---- I1 ------------------------------------------------------------------------------

func TestImport_RequiresManagedMode(t *testing.T) {
	t.Parallel()
	// Legacy mode: movable hosts exist, but sshm is not set up.
	e := newMgEnv(t, strings.TrimPrefix(imMain, "Include @M@\nInclude @D@/extra.conf\n"), mgAbsent)
	before := e.snap(t)
	for _, opts := range []ImportOptions{{}, {Apply: true}, {Apply: true, Force: true}} {
		_, err := e.a.Import(opts)
		if !errors.Is(err, ErrNotSetUp) {
			t.Fatalf("Import(%+v) err = %v, want ErrNotSetUp", opts, err)
		}
		if err.Error() != "sshm is not set up: run 'sshm setup' first" {
			t.Errorf("message = %q", err)
		}
		mgRequireUnchanged(t, before, e.snap(t))
	}
}

func TestImport_RefusesWhenAnIncludeCannotBeFollowed(t *testing.T) {
	t.Parallel()
	for name, inc := range map[string]string{"% token": "Include @D@/%h.conf\n", "~user path": "Include ~nobody/x.conf\n"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newImEnvWith(t, strings.Replace(imMain, "Include @D@/extra.conf\n", "Include @D@/extra.conf\n"+inc, 1), mgManagedHeader)
			before := e.snap(t)
			for _, opts := range []ImportOptions{{}, {Apply: true}, {Apply: true, Force: true}} {
				_, err := e.a.Import(opts)
				mgRequireErr(t, err)
				mgRequireUnchanged(t, before, e.snap(t))
			}
		})
	}
}

// ---- I2, I3, 5.1: the plan ----------------------------------------------------------------

func TestImport_PlanListsMovableBlocksAndStayReasons(t *testing.T) {
	t.Parallel()
	e := newImEnv(t)
	orig := e.readMain(t)
	res, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)

	spans := imSpans(t, orig)
	want := []ImportBlock{
		{Name: "web-1", Group: "web", FromLine: spans[0][0], ToLine: spans[0][1]},  // first line = attached comment
		{Name: "db-1", Group: "infra", FromLine: spans[1][0], ToLine: spans[1][1]}, // explicit "# group:" comment
		{Name: "solo", Group: "", FromLine: spans[2][0], ToLine: spans[2][1]},      // no comment, no group
	}
	if !reflect.DeepEqual(res.Move, want) {
		t.Errorf("Move =\n%+v\nwant\n%+v", res.Move, want)
	}

	stays := []struct {
		file   string
		line   int
		name   string // "" = not asserted
		reason string
	}{
		{e.main, mgLineOf(t, orig, "Host *-staging"), "", StayWildcard},
		{e.main, mgLineOf(t, orig, "Host a b"), "", StayMultiPattern},
		{e.main, mgLineOf(t, orig, "Host demo"), "demo", StayDevPod},
		{e.main, mgLineOf(t, orig, "Match host matched.example.com"), "", StayMatch},
		{e.main, mgLineOf(t, orig, "Host *"), "*", StayWildcard},
		{e.extra(), 1, "inc-1", StayIncluded},
	}
	for _, s := range stays {
		got, ok := imStayAt(res, s.file, s.line)
		if !ok {
			t.Errorf("no Stay entry for %s line %d (%s); Stay = %+v", s.file, s.line, s.reason, res.Stay)
			continue
		}
		if got.Reason != s.reason {
			t.Errorf("%s:%d reason = %q, want %q", s.file, s.line, got.Reason, s.reason)
		}
		if s.name != "" && got.Name != s.name {
			t.Errorf("%s:%d name = %q, want %q", s.file, s.line, got.Name, s.name)
		}
	}
	if len(res.Stay) != len(stays) {
		t.Errorf("Stay has %d entries, want %d: %+v", len(res.Stay), len(stays), res.Stay)
	}
}

func TestImport_PatternClassification(t *testing.T) {
	t.Parallel()
	const body = `Include @M@

Host a *
  User m1

Host q?
  User m2

Host !neg
  User m3

Host web-*
  User m4

Host x y
  User m5

Host plain-1
  HostName 10.0.0.5
`
	e := newMgEnv(t, body, mgManagedHeader)
	orig := e.readMain(t)
	res, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)
	if got := imNames(res); !reflect.DeepEqual(got, []string{"plain-1"}) {
		t.Errorf("Move = %v, want [plain-1]", got)
	}
	for header, reason := range map[string]string{
		"Host a *":   StayMultiPattern, // one pattern is a wildcard, still 'multiple patterns'
		"Host x y":   StayMultiPattern,
		"Host q?":    StayWildcard,
		"Host !neg":  StayWildcard,
		"Host web-*": StayWildcard,
	} {
		s, ok := imStayAt(res, e.main, mgLineOf(t, orig, header))
		if !ok || s.Reason != reason {
			t.Errorf("%q: Stay = %+v (found %v), want reason %q", header, s, ok, reason)
		}
	}
}

func TestImport_DryRunChangesNothing(t *testing.T) {
	t.Parallel()
	e := newImEnv(t)
	before := e.snap(t)
	res, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)
	if res.Applied || res.Checked || res.Equivalent {
		t.Errorf("dry run: Applied=%v Checked=%v Equivalent=%v, want all false", res.Applied, res.Checked, res.Equivalent)
	}
	if !mgNoteHas(res.Notes, "equivalence is checked when --apply runs") {
		t.Errorf("Notes = %q, want the note 'equivalence is checked when --apply runs'", res.Notes)
	}
	if len(res.Move) != 3 {
		t.Errorf("Move = %v, want 3 blocks", imNames(res))
	}
	mgRequireUnchanged(t, before, e.snap(t)) // bytes, mtimes, and no backup of any kind
}

// ---- I4, I5 (equivalent case), I10 -----------------------------------------------------------

func TestImport_ApplyMovesBlocksVerbatim(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newImEnv(t)
	if err := os.Chmod(e.main, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.managed, 0o644); err != nil { // fine for ssh; sshm must tighten it
		t.Fatal(err)
	}
	origMain, origManaged := e.readMain(t), e.readManaged(t)
	spans := imSpans(t, origMain)
	resolved := mgSSHAll(t, e.main, imHosts)

	res, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	if !res.Applied || !res.Checked || !res.Equivalent || len(res.Diff) != 0 {
		t.Errorf("result: Applied=%v Checked=%v Equivalent=%v Diff=%v, want applied and verified equivalent", res.Applied, res.Checked, res.Equivalent, res.Diff)
	}
	if got := imNames(res); !reflect.DeepEqual(got, []string{"web-1", "db-1", "solo"}) {
		t.Errorf("Move = %v", got)
	}

	// I4: managed file = old content + the three blocks verbatim (comments, inner comments,
	// trailing blanks, tabs), in order, one blank line apart.
	var texts []string
	for _, s := range spans {
		texts = append(texts, mgSpan(origMain, s[0], s[1]))
	}
	joined := strings.Join(texts, "\n\n")
	gotManaged := e.readManaged(t)
	if !strings.HasPrefix(gotManaged, origManaged) {
		t.Errorf("the previous managed content was changed:\n%s", gotManaged)
	}
	if !strings.HasSuffix(gotManaged, joined+"\n") {
		t.Errorf("managed file does not end with the moved blocks verbatim:\n%s\nwant suffix:\n%s", gotManaged, joined)
	}
	// ...and the main file lost exactly those spans plus one adjacent blank line each.
	mgCheckMainAfterMove(t, origMain, spans, e.readMain(t))
	for _, keep := range []string{"Include " + e.managed, "Include " + e.extra(), "# global note about this file", "# DevPod Start demo", "Match host matched.example.com", "Host *-staging", "Host a b"} {
		if !strings.Contains(e.readMain(t), keep) {
			t.Errorf("main file lost %q", keep)
		}
	}

	// I5: ssh resolves every host as before.
	mgRequireSameResolution(t, e.main, resolved)

	// I10: both files backed up first; modes.
	if len(mgBackupWith(t, e.dir, origMain)) != 1 {
		t.Errorf("no backup of the original main file in sshm-backups: %v", mgBackupFiles(t, e.dir))
	}
	if len(mgBackupWith(t, e.dir, origManaged)) != 1 {
		t.Errorf("no backup of the original managed file in sshm-backups")
	}
	if m := mgMode(t, e.managed); m != 0o600 {
		t.Errorf("managed mode = %o, want 0600", m)
	}
	if m := mgMode(t, e.main); m != 0o640 {
		t.Errorf("main mode = %o, want 0640 (unchanged)", m)
	}
	if m := mgMode(t, e.backupDir()); m != 0o700 {
		t.Errorf("sshm-backups mode = %o, want 0700", m)
	}
}

func TestImport_ApplyKeepsTheMainFileSymlink(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, mgAbsent, mgManagedHeader)
	real := filepath.Join(e.dir, "dotfiles", "config.real")
	mgWrite(t, real, strings.ReplaceAll(strings.ReplaceAll(imMain, "@M@", e.managed), "@D@", e.dir), 0o640)
	mgWrite(t, e.extra(), imExtra, 0o600)
	if err := os.Symlink(real, e.main); err != nil {
		t.Fatal(err)
	}
	origMain := mgRead(t, real)
	spans := imSpans(t, origMain)

	_, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	fi, lerr := os.Lstat(e.main)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the main file is no longer a symlink: %v %v", fi, lerr)
	}
	if dest, _ := os.Readlink(e.main); dest != real {
		t.Errorf("symlink now points to %q", dest)
	}
	mgCheckMainAfterMove(t, origMain, spans, mgRead(t, real))
	if m := mgMode(t, real); m != 0o640 {
		t.Errorf("target mode = %o, want 0640", m)
	}
	if !strings.Contains(e.readManaged(t), "Host web-1") {
		t.Error("blocks did not reach the managed file")
	}
}

// ---- I5: equivalence --------------------------------------------------------------------------

const imShadowMain = `Include @M@

Host pat-*
  ProxyJump none

Host *
  User fallback
  ProxyJump jump.example.com

Host web-1
  HostName 10.0.0.1
  User mainuser

Host proxy-1
  HostName 10.0.0.2
  ProxyJump none

Host pat-1
  HostName 10.0.0.3
  ProxyJump hop.example.com
`

var imShadowDiff = []string{
	"web-1: -user fallback",
	"web-1: +user mainuser",
	"proxy-1: -proxyjump jump.example.com",
	"pat-1: +proxyjump hop.example.com",
}

func TestImport_RestoresBothFilesWhenSSHResolvesDifferently(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, imShadowMain, mgManagedHeader)
	before := e.snap(t)
	resolved := mgSSHAll(t, e.main, []string{"web-1", "proxy-1", "pat-1"})

	res, err := e.a.Import(ImportOptions{Apply: true})
	if !errors.Is(err, ErrNotEquivalent) {
		t.Fatalf("err = %v, want ErrNotEquivalent", err)
	}
	if res.Applied || !res.Checked || res.Equivalent {
		t.Errorf("result: Applied=%v Checked=%v Equivalent=%v, want not applied, checked, not equivalent", res.Applied, res.Checked, res.Equivalent)
	}
	got := append([]string(nil), res.Diff...)
	want := append([]string(nil), imShadowDiff...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Diff = %q\nwant (any order between hosts) %q", res.Diff, imShadowDiff)
	}
	// Per differing line: the '-' entry comes first, directly followed by its '+' entry.
	for i, d := range res.Diff {
		if d == "web-1: -user fallback" && (i+1 >= len(res.Diff) || res.Diff[i+1] != "web-1: +user mainuser") {
			t.Errorf("'-user fallback' is not directly followed by '+user mainuser': %q", res.Diff)
		}
	}
	mgRequireRestored(t, before, e.snap(t), e.main, e.managed) // bytes back, backups allowed
	mgRequireSameResolution(t, e.main, resolved)
}

func TestImport_ForceKeepsTheMoveAndReportsTheDifference(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, imShadowMain, mgManagedHeader)
	res, err := e.a.Import(ImportOptions{Apply: true, Force: true})
	mgRequireNoErr(t, err)
	if !res.Applied || !res.Checked || res.Equivalent {
		t.Errorf("result: Applied=%v Checked=%v Equivalent=%v, want applied, checked, not equivalent", res.Applied, res.Checked, res.Equivalent)
	}
	got := append([]string(nil), res.Diff...)
	want := append([]string(nil), imShadowDiff...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Diff = %q, want %q", res.Diff, imShadowDiff)
	}
	for _, h := range []string{"Host web-1", "Host proxy-1", "Host pat-1"} {
		if strings.Contains(e.readMain(t), h) || !strings.Contains(e.readManaged(t), h) {
			t.Errorf("%q was not moved", h)
		}
	}
	if got := mgVal(mgSSHG(t, e.main, "web-1"), "user"); got != "mainuser" {
		t.Errorf("web-1 user = %q after the forced move", got)
	}
}

// ---- I6 ----------------------------------------------------------------------------------------

func TestImport_ConflictWithAHostInTheManagedFile(t *testing.T) {
	t.Parallel()
	managed := mgManagedHeader + "\nHost web-1\n  HostName 10.0.0.77\n"
	for _, opts := range []ImportOptions{{Apply: true}, {Apply: true, Force: true}} {
		e := newImEnvWith(t, imMain, managed)
		before := e.snap(t)
		_, err := e.a.Import(opts)
		if !errors.Is(err, ErrImportConflict) {
			t.Fatalf("Import(%+v) err = %v, want ErrImportConflict", opts, err)
		}
		if !strings.Contains(err.Error(), "web-1") {
			t.Errorf("error %q does not list the conflicting name", err)
		}
		if strings.Contains(err.Error(), "db-1") || strings.Contains(err.Error(), "solo") {
			t.Errorf("error %q lists names that do not conflict", err)
		}
		mgRequireUnchanged(t, before, e.snap(t)) // aborted before any write: not even a backup
	}
}

// ---- I7 ----------------------------------------------------------------------------------------

func TestImport_CannotVerifyWithoutSSH(t *testing.T) {
	mgNoSSHOnPath(t)
	e := newImEnv(t)
	before := e.snap(t)

	if res, err := e.a.Import(ImportOptions{}); err != nil || len(res.Move) != 3 {
		t.Errorf("dry run without ssh: err=%v, %d blocks; the plan needs no ssh", err, len(res.Move))
	}
	_, err := e.a.Import(ImportOptions{Apply: true})
	if !errors.Is(err, ErrCannotVerify) {
		t.Fatalf("err = %v, want ErrCannotVerify", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))

	res, err := e.a.Import(ImportOptions{Apply: true, Force: true})
	mgRequireNoErr(t, err)
	if !res.Applied || res.Checked || len(res.Notes) == 0 {
		t.Errorf("forced result: Applied=%v Checked=%v Notes=%q, want applied, unchecked, with a note", res.Applied, res.Checked, res.Notes)
	}
	if !strings.Contains(e.readManaged(t), "Host web-1") || strings.Contains(e.readMain(t), "Host web-1") {
		t.Error("--force did not move the blocks")
	}
}

func TestImport_CannotVerifyWithMatchExecAndNeverRunsIt(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newImEnvWith(t, imMain+"\nMatch exec \"touch @D@/exec-ran\"\n  Compression no\n", mgManagedHeader)
	marker := filepath.Join(e.dir, "exec-ran")
	before := e.snap(t)
	_, err := e.a.Import(ImportOptions{Apply: true})
	if !errors.Is(err, ErrCannotVerify) {
		t.Fatalf("err = %v, want ErrCannotVerify", err)
	}
	mgRequireUnchanged(t, before, e.snap(t))
	res, err := e.a.Import(ImportOptions{Apply: true, Force: true})
	mgRequireNoErr(t, err)
	if !res.Applied || res.Checked {
		t.Errorf("forced result: Applied=%v Checked=%v", res.Applied, res.Checked)
	}
	if mgExists(marker) {
		t.Fatal("the Match exec command was run")
	}
}

// ---- I8 ------------------------------------------------------------------------------------------

func TestImport_SecondRunHasNothingToImport(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newImEnv(t)
	_, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	e.backdate(t)
	before := e.snap(t)
	for _, opts := range []ImportOptions{{}, {Apply: true}} {
		res, err := e.a.Import(opts)
		mgRequireNoErr(t, err)
		if len(res.Move) != 0 || res.Applied {
			t.Errorf("Import(%+v): Move=%v Applied=%v, want nothing to do", opts, imNames(res), res.Applied)
		}
		mgRequireUnchanged(t, before, e.snap(t))
	}
}

// ---- I9: disabled groups ----------------------------------------------------------------------------

func TestImport_DisabledGroupsMoveWithMarkersAndState(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	// The disabled state an earlier sshm left in the main file: the group's blocks
	// between markers there, and the group listed in the main file's sidecar.
	e := newMgEnv(t, "Include @M@\n"+disabledMainText, mgManagedHeader)
	mgWrite(t, mgSidecar(e.main), "# sshm group state\ndeploy\n", 0o600)
	e.backdate(t)

	statesBefore, err := e.a.ListGroupsState()
	mgRequireNoErr(t, err)
	hosts := []string{"web-1", "deploy-acq", "deploy-eu", "misc"}
	resolved := mgSSHAll(t, e.main, hosts)

	plan, err := e.a.Import(ImportOptions{})
	mgRequireNoErr(t, err)
	byName := map[string]ImportBlock{}
	for _, b := range plan.Move {
		byName[b.Name] = b
	}
	if len(plan.Move) != 4 {
		t.Fatalf("Move = %v, want web-1, deploy-acq, deploy-eu, misc", imNames(plan))
	}
	for _, n := range []string{"deploy-acq", "deploy-eu"} {
		if b := byName[n]; !b.Disabled || b.Group != "deploy" {
			t.Errorf("%s: %+v, want Disabled with group deploy", n, b)
		}
	}
	if b := byName["web-1"]; b.Disabled || b.Group != "web" {
		t.Errorf("web-1: %+v, want enabled, group web", b)
	}
	if b := byName["misc"]; b.Disabled || b.Group != "" {
		t.Errorf("misc: %+v, want enabled, no group", b)
	}

	_, err = e.a.Import(ImportOptions{Apply: true})
	mgRequireNoErr(t, err)
	if strings.Contains(e.readMain(t), "sshm disabled") || strings.Contains(e.readMain(t), "Host deploy") || strings.Contains(e.readMain(t), "Host web-1") {
		t.Errorf("main file still holds moved hosts:\n%s", e.readMain(t))
	}
	m := e.readManaged(t)
	for _, want := range []string{domain.DisabledMarkerStart("deploy"), domain.DisabledMarkerEnd("deploy"), "Host deploy-acq", "Host deploy-eu", "Host web-1"} {
		if !strings.Contains(m, want) {
			t.Errorf("managed file lacks %q:\n%s", want, m)
		}
	}
	if side := mgSidecar(e.managed); !mgExists(side) || !mgHasLine(mgRead(t, side), "deploy") {
		t.Errorf("sidecar %s does not list the group", mgSidecar(e.managed))
	}
	if side := mgSidecar(e.main); mgExists(side) && mgHasLine(mgRead(t, side), "deploy") {
		t.Error("the main file's sidecar still lists the moved group")
	}
	statesAfter, err := e.a.ListGroupsState()
	mgRequireNoErr(t, err)
	if !reflect.DeepEqual(statesBefore, statesAfter) {
		t.Errorf("groups state changed:\nbefore %+v\nafter  %+v", statesBefore, statesAfter)
	}
	mgRequireSameResolution(t, e.main, resolved)

	// Enabling afterwards works in the managed file and restores the blocks as they were.
	mainAfterImport := e.snap(t)[e.main]
	mgRequireNoErr(t, e.a.EnableGroup("deploy"))
	m = e.readManaged(t)
	for _, block := range []string{
		"Host deploy-acq\n  HostName 192.168.1.10\n  User deploy",
		"Host deploy-eu\n  HostName 192.168.1.11\n  User deploy",
	} {
		if !strings.Contains(m, block) {
			t.Errorf("enabled managed file lacks the original block %q:\n%s", block, m)
		}
	}
	if strings.Contains(m, "sshm disabled") {
		t.Errorf("markers left after enable:\n%s", m)
	}
	if e.snap(t)[e.main] != mainAfterImport {
		t.Error("enable touched the main file")
	}
	if side := mgSidecar(e.managed); mgExists(side) && mgHasLine(mgRead(t, side), "deploy") {
		t.Error("sidecar still lists the group after enable")
	}
	if got := mgVal(mgSSHG(t, e.main, "deploy-acq"), "hostname"); got != "192.168.1.10" {
		t.Errorf("deploy-acq hostname = %q after enable", got)
	}
}

// ---- I11 ---------------------------------------------------------------------------------------------

// The managed file is written first. If the main file then cannot be written, the
// managed file must be put back. Failure injection: read-only main file in a
// read-only directory (so neither an in-place write nor a rename can succeed).
func TestImport_MainWriteFailureRestoresTheManagedFile(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection does not work as root")
	}

	// Control: the same fixture imports fine, so the failure below is the injected one.
	control := newImEnv(t)
	if res, err := control.a.Import(ImportOptions{Apply: true}); err != nil || !res.Applied {
		t.Fatalf("control import failed: applied=%v err=%v", res.Applied, err)
	}

	e := newImEnv(t)
	if err := os.MkdirAll(e.backupDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	origMain, origManaged := e.readMain(t), e.readManaged(t)
	resolved := mgSSHAll(t, e.main, imHosts)
	if err := os.Chmod(e.main, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(e.dir, 0o700) })
	before := e.snap(t)

	_, err := e.a.Import(ImportOptions{Apply: true})
	mgRequireErr(t, err)
	for _, not := range []error{ErrCannotVerify, ErrNotEquivalent, ErrImportConflict, ErrNotSetUp} {
		if errors.Is(err, not) {
			t.Fatalf("err = %v: wrong failure, want a write error", err)
		}
	}
	if got := e.readManaged(t); got != origManaged {
		t.Errorf("managed file not restored after the main write failed:\n%s", got)
	}
	if got := e.readMain(t); got != origMain {
		t.Errorf("main file changed:\n%s", got)
	}
	if m := mgMode(t, e.managed); m != 0o600 {
		t.Errorf("managed mode = %o", m)
	}
	mgRequireRestored(t, before, e.snap(t), e.managed)
	mgRequireSameResolution(t, e.main, resolved)
}
