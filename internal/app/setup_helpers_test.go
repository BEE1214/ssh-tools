package app

// Shared test infrastructure for the setup / routing / import tests. These are
// black-box helpers: they only use the public App API, the config package's
// public Doc API as an oracle for expected bytes, and real `ssh -F <main> -G`.
//
// Nothing here touches the real ~/.ssh: every fixture lives in t.TempDir(),
// Include paths are absolute, and ssh is always called with -F.

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// mgRealSSH is the ssh binary found at process start. Tests that empty PATH to
// simulate a missing ssh still use it for their own oracle calls.
var mgRealSSH, _ = exec.LookPath("ssh")

// mgAbsent as a body means: do not create that file.
const mgAbsent = "\x00absent"

// mgManagedHeader is what a freshly set-up managed file looks like.
const mgManagedHeader = "# Managed by sshm. Hosts in this file are edited by sshm.\n# Lines you add by hand are kept.\n"

var mgPast = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

func mgNeedSSH(t *testing.T) {
	t.Helper()
	if mgRealSSH == "" {
		t.Skip("ssh not in PATH")
	}
}

// mgNoSSHOnPath empties PATH for the test (and so forbids t.Parallel).
func mgNoSSHOnPath(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// mgEnv is a temp dir with a main config and (optionally) a managed file.
type mgEnv struct {
	dir, main, managed string
	a                  *App
}

// newMgEnv creates dir/config (mainBody) and dir/config.d/sshm.conf
// (managedBody). Either body may be mgAbsent. In both bodies @M@ is the
// managed path, @D@ the temp dir and @C@ the main path. All files get mode
// 0600 and an mtime far in the past, so any rewrite (even with identical
// bytes) is visible as an mtime change.
func newMgEnv(t *testing.T, mainBody, managedBody string) *mgEnv {
	t.Helper()
	dir := t.TempDir()
	e := &mgEnv{
		dir:     dir,
		main:    filepath.Join(dir, "config"),
		managed: filepath.Join(dir, "config.d", "sshm.conf"),
	}
	if managedBody != mgAbsent {
		mgWrite(t, e.managed, e.sub(managedBody), 0o600)
	}
	if mainBody != mgAbsent {
		mgWrite(t, e.main, e.sub(mainBody), 0o600)
	}
	e.backdate(t)
	e.a = NewAppWithPath(e.main)
	return e
}

func (e *mgEnv) sub(s string) string {
	return strings.NewReplacer("@M@", e.managed, "@D@", e.dir, "@C@", e.main).Replace(s)
}

func (e *mgEnv) backdate(t *testing.T) { mgBackdate(t, e.dir) }

func (e *mgEnv) readMain(t *testing.T) string    { return mgRead(t, e.main) }
func (e *mgEnv) readManaged(t *testing.T) string { return mgRead(t, e.managed) }
func (e *mgEnv) snap(t *testing.T) mgTree        { return mgSnap(t, e.dir) }
func (e *mgEnv) backupDir() string               { return filepath.Join(e.dir, "sshm-backups") }

// groupState is the sidecar file belonging to a config file.
func mgSidecar(cfg string) string { return cfg + ".sshm-groups" }

func mgWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mgPast, mgPast); err != nil {
		t.Fatal(err)
	}
}

func mgRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mgMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func mgExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// mgBackdate sets every regular file under root to mgPast.
func mgBackdate(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 || d.IsDir() {
			return nil
		}
		return os.Chtimes(p, mgPast, mgPast)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ---- tree snapshots --------------------------------------------------------

type mgEntry struct {
	dir   bool
	link  string
	data  string
	mode  os.FileMode
	mtime int64
}

type mgTree map[string]mgEntry

// mgSnap records every file, directory and symlink below root (the lock file
// that managed writes may leave behind is ignored; stray temp files are not).
func mgSnap(t *testing.T, root string) mgTree {
	t.Helper()
	tr := mgTree{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root || d.Name() == ".sshm.lock" {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		e := mgEntry{dir: fi.IsDir(), mode: fi.Mode()}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			e.link, _ = os.Readlink(p)
			e.mode = fs.ModeSymlink
			e.mtime = fi.ModTime().UnixNano()
		case fi.IsDir():
			// directory mtimes change with the lock file; only presence and mode count
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			e.data = string(b)
			e.mtime = fi.ModTime().UnixNano()
		}
		tr[p] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// mgDiff lists the differences between two snapshots. With allowBackups,
// new entries below an sshm-backups directory are not differences. Paths in
// contentOnly are compared by bytes and mode but not by mtime (a file that was
// rewritten with its old bytes, e.g. by a rollback).
func mgDiff(before, after mgTree, allowBackups bool, contentOnly ...string) []string {
	co := map[string]bool{}
	for _, p := range contentOnly {
		co[p] = true
	}
	var out []string
	for p, b := range before {
		a, ok := after[p]
		switch {
		case !ok:
			out = append(out, "removed "+p)
		case a.dir != b.dir || a.link != b.link || a.data != b.data || a.mode != b.mode:
			out = append(out, "changed "+p)
		case a.mtime != b.mtime && !co[p]:
			out = append(out, "rewritten (mtime) "+p)
		}
	}
	for p := range after {
		if _, ok := before[p]; ok {
			continue
		}
		if allowBackups && strings.Contains(p, string(filepath.Separator)+"sshm-backups") {
			continue
		}
		out = append(out, "added "+p)
	}
	sort.Strings(out)
	return out
}

func mgRequireUnchanged(t *testing.T, before, after mgTree) {
	t.Helper()
	if d := mgDiff(before, after, false); len(d) > 0 {
		t.Errorf("files changed, want everything untouched (bytes, modes, mtimes, no new files):\n  %s", strings.Join(d, "\n  "))
	}
}

// mgRequireRestored: like unchanged, but backups may have been added and the
// listed files may have been rewritten as long as their bytes are the old ones.
func mgRequireRestored(t *testing.T, before, after mgTree, contentOnly ...string) {
	t.Helper()
	if d := mgDiff(before, after, true, contentOnly...); len(d) > 0 {
		t.Errorf("state not restored:\n  %s", strings.Join(d, "\n  "))
	}
}

// mgBackupFiles returns the files below dir/sshm-backups as path -> bytes.
func mgBackupFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ents, err := os.ReadDir(filepath.Join(dir, "sshm-backups"))
	if os.IsNotExist(err) {
		return out
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		p := filepath.Join(dir, "sshm-backups", e.Name())
		out[p] = mgRead(t, p)
	}
	return out
}

// mgBackupWith returns the backup files whose bytes equal want.
func mgBackupWith(t *testing.T, dir, want string) []string {
	t.Helper()
	var out []string
	for p, b := range mgBackupFiles(t, dir) {
		if b == want {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// ---- errors ----------------------------------------------------------------

// mgRequireErr: err is a real refusal, not the skeleton's placeholder.
func mgRequireErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if errors.Is(err, ErrNotImplemented) {
		t.Fatalf("got the skeleton's ErrNotImplemented, want the specified behaviour")
	}
}

func mgRequireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---- ssh oracle ------------------------------------------------------------

// mgSSHG returns `ssh -F main -G host`.
func mgSSHG(t *testing.T, main, host string) string {
	t.Helper()
	if mgRealSSH == "" {
		t.Skip("ssh not in PATH")
	}
	out, err := exec.Command(mgRealSSH, "-F", main, "-G", host).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -F %s -G %s: %v\n%s", main, host, err, out)
	}
	return string(out)
}

const mgSentinel = "sshm-sentinel-host.invalid"

// mgSSHAll resolves every host plus the sentinel.
func mgSSHAll(t *testing.T, main string, hosts []string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, h := range append(append([]string{}, hosts...), mgSentinel) {
		m[h] = mgSSHG(t, main, h)
	}
	return m
}

// mgRequireSameResolution fails if any host resolves differently than before.
func mgRequireSameResolution(t *testing.T, main string, before map[string]string) {
	t.Helper()
	for h, old := range before {
		if now := mgSSHG(t, main, h); now != old {
			t.Errorf("ssh -G %s changed:\n%s", h, mgLineDiff(old, now))
		}
	}
}

// mgVal returns the values of one `ssh -G` key joined with ",".
func mgVal(out, key string) string {
	var vals []string
	for _, l := range strings.Split(out, "\n") {
		if k, v, _ := strings.Cut(l, " "); k == key {
			vals = append(vals, v)
		}
	}
	return strings.Join(vals, ",")
}

func mgLineDiff(a, b string) string {
	as, bs := map[string]bool{}, map[string]bool{}
	for _, l := range strings.Split(a, "\n") {
		as[l] = true
	}
	for _, l := range strings.Split(b, "\n") {
		bs[l] = true
	}
	var out []string
	for _, l := range strings.Split(a, "\n") {
		if !bs[l] {
			out = append(out, "- "+l)
		}
	}
	for _, l := range strings.Split(b, "\n") {
		if !as[l] {
			out = append(out, "+ "+l)
		}
	}
	return strings.Join(out, "\n")
}

// ---- text helpers ----------------------------------------------------------

func mgLines(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// mgLineOf returns the 1-based number of the first line equal to needle.
func mgLineOf(t *testing.T, text, needle string) int {
	t.Helper()
	for i, l := range mgLines(text) {
		if l == needle {
			return i + 1
		}
	}
	t.Fatalf("fixture has no line %q", needle)
	return 0
}

// mgSpan returns lines from..to (1-based, inclusive) joined with "\n".
func mgSpan(text string, from, to int) string {
	return strings.Join(mgLines(text)[from-1:to], "\n")
}

func mgHasLine(text, line string) bool {
	for _, l := range mgLines(text) {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

// mgCheckMainAfterMove verifies I4 for the main file: the moved spans are
// gone, plus exactly one adjacent blank line per span, and every other line
// is identical and in order. Spans are 1-based inclusive line ranges.
func mgCheckMainAfterMove(t *testing.T, orig string, spans [][2]int, got string) {
	t.Helper()
	ok, kept := mgMainAfterMoveOK(orig, spans, got)
	if !ok {
		t.Errorf("main file after the move is not 'original minus the moved spans minus one adjacent blank line each' (ending in a newline).\ngot:\n%s\n---\nkept lines (spans removed, before blank-line removal):\n%s", got, strings.Join(kept, "\n"))
	}
}

// mgMainAfterMoveOK is the predicate behind mgCheckMainAfterMove; it also
// returns the lines left after removing the spans.
func mgMainAfterMoveOK(orig string, spans [][2]int, got string) (bool, []string) {
	ol := mgLines(orig)
	var kept []string
	var gaps []int // number of kept lines before each span
	for i := 1; i <= len(ol); i++ {
		in := false
		for _, s := range spans {
			if i >= s[0] && i <= s[1] {
				in = true
			}
			if i == s[0] {
				gaps = append(gaps, len(kept))
			}
		}
		if !in {
			kept = append(kept, ol[i-1])
		}
	}
	want := mgMainCandidates(kept, gaps)
	gl := strings.Join(mgLines(got), "\n")
	for _, w := range want {
		if strings.Join(w, "\n") == gl {
			return strings.HasSuffix(got, "\n"), kept
		}
	}
	return false, kept
}

// mgMainCandidates enumerates the results of removing one adjacent blank line
// (before or after the gap) for each gap.
func mgMainCandidates(kept []string, gaps []int) [][]string {
	var out [][]string
	var rec func(k int, removed map[int]bool)
	rec = func(k int, removed map[int]bool) {
		if k == len(gaps) {
			var res []string
			for i, l := range kept {
				if !removed[i] {
					res = append(res, l)
				}
			}
			out = append(out, res)
			return
		}
		g := gaps[k]
		var opts []int
		if g-1 >= 0 && kept[g-1] == "" && !removed[g-1] {
			opts = append(opts, g-1)
		}
		if g < len(kept) && kept[g] == "" && !removed[g] {
			opts = append(opts, g)
		}
		if len(opts) == 0 {
			rec(k+1, removed)
			return
		}
		for _, o := range opts {
			next := map[int]bool{}
			for kk, v := range removed {
				next[kk] = v
			}
			next[o] = true
			rec(k+1, next)
		}
	}
	rec(0, map[int]bool{})
	return out
}

// mgNoteHas reports whether any note contains sub (case-insensitive).
func mgNoteHas(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(strings.ToLower(n), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
