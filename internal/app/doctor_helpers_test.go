package app

// Helpers for the doctor (P5) tests. Black-box: they use App.Doctor / App.Validate,
// the config package's home override, and the real ssh / ssh-keygen as oracle.
//
// Every fixture lives in t.TempDir(); Include and key paths are absolute; the
// passwd home (config.SetHomeDirForTest) and $HOME both point at a temp dir, so
// no test reads or writes the real ~/.ssh, and the home-mismatch rule (D17)
// stays quiet unless a test provokes it. Tests built on newDrEnv set $HOME and
// must not be parallel.

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// drKeygen is the ssh-keygen found at process start ("" when absent). Tests
// that empty PATH still create their certificates with it.
var drKeygen, _ = exec.LookPath("ssh-keygen")

// The probe host name doctor hands to `ssh -G` (PLAN-p5.md section 4).
const drProbe = "sshm-doctor-probe"

const drKeyBody = "-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n"

// drHardened is a `Host *` block that silences D21 and D22.
const drHardened = "Host *\n  HashKnownHosts yes\n  IdentitiesOnly yes\n"

// drEnv is a temp dir with a main config and (optionally) a managed file, plus
// a private passwd home. In bodies: @M@ managed path, @D@ temp dir, @C@ main
// path, @K@ <dir>/keys, @H@ the passwd home.
type drEnv struct {
	dir, main, managed, keys, home string
	a                              *App
}

func newDrEnv(t *testing.T, mainBody, managedBody string) *drEnv {
	t.Helper()
	e := &drEnv{dir: t.TempDir(), home: t.TempDir()}
	e.main = filepath.Join(e.dir, "config")
	e.managed = filepath.Join(e.dir, "config.d", "sshm.conf")
	e.keys = filepath.Join(e.dir, "keys")
	t.Cleanup(config.SetHomeDirForTest(e.home))
	t.Setenv("HOME", e.home)
	if managedBody != mgAbsent {
		e.file(t, e.managed, managedBody, 0o600)
	}
	if mainBody != mgAbsent {
		e.file(t, e.main, mainBody, 0o600)
	}
	e.a = NewAppWithPath(e.main)
	return e
}

func (e *drEnv) sub(s string) string {
	return strings.NewReplacer("@M@", e.managed, "@D@", e.dir, "@C@", e.main, "@K@", e.keys, "@H@", e.home).Replace(s)
}

// file writes a fixture file (placeholders substituted) with an old mtime.
func (e *drEnv) file(t *testing.T, path, body string, mode os.FileMode) string {
	t.Helper()
	mgWrite(t, path, e.sub(body), mode)
	return path
}

// key writes a placeholder private key <keys>/name with the given mode.
func (e *drEnv) key(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(e.keys, name)
	mgWrite(t, p, drKeyBody, mode)
	return p
}

// setMain rewrites the main file (mode 0600).
func (e *drEnv) setMain(t *testing.T, body string) { e.file(t, e.main, body, 0o600) }

// run calls Doctor; any error, the skeleton's ErrNotImplemented included, fails
// the test.
func (e *drEnv) run(t *testing.T, skipFiles bool) []domain.Issue {
	t.Helper()
	is, err := e.a.Doctor(DoctorOptions{SkipFiles: skipFiles})
	if err != nil {
		t.Fatalf("Doctor returned an error: %v", err)
	}
	return is
}

// ---- finding helpers -----------------------------------------------------------

func drFmt(i domain.Issue) string {
	return fmt.Sprintf("%s [%s] host=%q file=%q line=%d: %s", i.Severity, i.Rule, i.HostName, i.File, i.Line, i.Message)
}

func drDump(is []domain.Issue) string {
	if len(is) == 0 {
		return "  (no findings)"
	}
	var b strings.Builder
	for _, i := range is {
		b.WriteString("  " + drFmt(i) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// drRule returns the findings of one rule, in result order.
func drRule(is []domain.Issue, rules ...string) []domain.Issue {
	var out []domain.Issue
	for _, i := range is {
		for _, r := range rules {
			if i.Rule == r {
				out = append(out, i)
				break
			}
		}
	}
	return out
}

// drWantN fails unless exactly n findings carry the rule; returns them.
func drWantN(t *testing.T, is []domain.Issue, rule string, n int) []domain.Issue {
	t.Helper()
	got := drRule(is, rule)
	if len(got) != n {
		t.Errorf("want %d %q finding(s), got %d; all findings:\n%s", n, rule, len(got), drDump(is))
	}
	return got
}

// drNoRule fails if any finding carries one of the rules.
func drNoRule(t *testing.T, is []domain.Issue, rules ...string) {
	t.Helper()
	if got := drRule(is, rules...); len(got) > 0 {
		t.Errorf("want no %v finding, got:\n%s", rules, drDump(got))
	}
}

func drRuleNames(is []domain.Issue) []string {
	out := make([]string, len(is))
	for i, x := range is {
		out[i] = x.Rule
	}
	return out
}

// drMsgs returns the sorted messages.
func drMsgs(is []domain.Issue) []string {
	out := make([]string, len(is))
	for i, x := range is {
		out[i] = x.Message
	}
	sort.Strings(out)
	return out
}

func drHas(msg string, subs ...string) bool {
	low := strings.ToLower(msg)
	for _, s := range subs {
		if !strings.Contains(low, strings.ToLower(s)) {
			return false
		}
	}
	return true
}

// fileOK reports whether got is acceptable as the Issue.File of a finding in file want. Validate clears File for
// the main file; PLAN-p5 says "File = source file", so for the main file both ""
// and the main path are accepted (reported as a spec ambiguity).
func (e *drEnv) fileOK(got, want string) bool {
	if want == e.main {
		return got == "" || got == e.main
	}
	return got == want
}

// drLineHas returns the 1-based number of the first line of text containing sub.
func drLineHas(t *testing.T, text, sub string) int {
	t.Helper()
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, sub) {
			return i + 1
		}
	}
	t.Fatalf("fixture has no line containing %q", sub)
	return 0
}

// ---- snapshots (D1) --------------------------------------------------------------

type drNode struct {
	kind  string // "file", "dir", "link"
	mode  os.FileMode
	mtime int64
	data  string // file bytes, link target, or sorted entry names of a dir
}

// drSnap records every file (bytes, mode, mtime), directory (mode, mtime and
// listing) and symlink below the roots. Unlike mgSnap it keeps directory mtimes
// and the lock file: doctor must create nothing at all.
func drSnap(t *testing.T, roots ...string) map[string]drNode {
	t.Helper()
	out := map[string]drNode{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			fi, err := os.Lstat(p)
			if err != nil {
				return err
			}
			n := drNode{mode: fi.Mode(), mtime: fi.ModTime().UnixNano()}
			switch {
			case fi.Mode()&fs.ModeSymlink != 0:
				n.kind = "link"
				n.data, _ = os.Readlink(p)
			case fi.IsDir():
				n.kind = "dir"
				ents, err := os.ReadDir(p)
				if err != nil {
					return err
				}
				names := make([]string, len(ents))
				for i, e := range ents {
					names[i] = e.Name()
				}
				sort.Strings(names)
				n.data = strings.Join(names, "\n")
			default:
				n.kind = "file"
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				n.data = string(b)
			}
			out[p] = n
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func drRequireUnchanged(t *testing.T, before, after map[string]drNode) {
	t.Helper()
	if reflect.DeepEqual(before, after) {
		return
	}
	var d []string
	for p, b := range before {
		a, ok := after[p]
		switch {
		case !ok:
			d = append(d, "removed "+p)
		case a != b:
			d = append(d, "changed (bytes, mode, mtime or listing) "+p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			d = append(d, "added "+p)
		}
	}
	sort.Strings(d)
	t.Errorf("doctor modified the tree, want everything untouched:\n  %s", strings.Join(d, "\n  "))
}

// ---- certificates ----------------------------------------------------------------

func drNeedKeygen(t *testing.T) {
	t.Helper()
	if drKeygen == "" {
		t.Skip("ssh-keygen not in PATH")
	}
}

func drRunKeygen(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(drKeygen, args...).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
	}
}

// drCert signs a fresh ed25519 key with a fresh CA in dir and returns the path
// of the certificate (<dir>/<name>-cert.pub). validity is the ssh-keygen -V
// value; the CA and the key are created with the absolute ssh-keygen found at
// process start, so PATH may be empty afterwards.
func drCert(t *testing.T, dir, name, validity string) string {
	t.Helper()
	drNeedKeygen(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, name+"-ca")
	key := filepath.Join(dir, name)
	drRunKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", ca)
	drRunKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", key)
	drRunKeygen(t, "-q", "-s", ca, "-I", "dr-"+name, "-n", "user", "-V", validity, key+".pub")
	return key + "-cert.pub"
}

// ---- real ssh as the oracle ------------------------------------------------------

// drSSHProbe runs `ssh -F main -G sshm-doctor-probe` the way doctor is
// specified to, returning the effective values and ssh's stderr.
func drSSHProbe(t *testing.T, main string) (out string, firstErrLine string, exit int) {
	t.Helper()
	mgNeedSSH(t)
	cmd := exec.Command(mgRealSSH, "-F", main, "-G", drProbe)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("running ssh: %v", err)
		}
	}
	for _, l := range strings.Split(se.String(), "\n") {
		if strings.TrimSpace(l) != "" {
			firstErrLine = strings.TrimSpace(l)
			break
		}
	}
	return so.String(), firstErrLine, exit
}
