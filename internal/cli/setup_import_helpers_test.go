package cli

// Helpers for the setup / import / hint CLI tests. They run the real root
// command against fixtures in a temp dir: SSH_AUTH_CONFIG points at a temp main
// config, the home lookup is redirected to a temp dir, and every Include path is
// absolute, so the real ~/.ssh is never read or written.
//
// The commands print with fmt.Print* to the process stdout/stderr as well as via
// cobra's writers, so runCLI captures both. Tests using it must not be parallel.

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

var cliRealSSH, _ = exec.LookPath("ssh")

var cliPast = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

const cliManagedHeader = "# Managed by sshm. Hosts in this file are edited by sshm.\n# Lines you add by hand are kept.\n"

const cliAbsent = "\x00absent"

type cliEnv struct {
	dir, main, managed string
}

// newCLIEnv writes dir/config and dir/config.d/sshm.conf (either may be
// cliAbsent); @M@ is the managed path, @D@ the temp dir. Files get mode 0600
// and an old mtime so a rewrite is visible.
func newCLIEnv(t *testing.T, mainBody, managedBody string) *cliEnv {
	t.Helper()
	dir := t.TempDir()
	e := &cliEnv{dir: dir, main: filepath.Join(dir, "config"), managed: filepath.Join(dir, "config.d", "sshm.conf")}
	t.Cleanup(config.SetHomeDirForTest(t.TempDir()))
	t.Setenv("SSH_AUTH_CONFIG", e.main)
	if managedBody != cliAbsent {
		e.write(t, e.managed, managedBody)
	}
	if mainBody != cliAbsent {
		e.write(t, e.main, mainBody)
	}
	return e
}

func (e *cliEnv) sub(s string) string {
	return strings.NewReplacer("@M@", e.managed, "@D@", e.dir, "@C@", e.main).Replace(s)
}

func (e *cliEnv) write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(e.sub(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, cliPast, cliPast); err != nil {
		t.Fatal(err)
	}
}

func (e *cliEnv) readMain(t *testing.T) string    { return cliRead(t, e.main) }
func (e *cliEnv) readManaged(t *testing.T) string { return cliRead(t, e.managed) }

func cliRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runCLI runs `sshm args...` and returns everything printed to stdout and to
// stderr (cobra's writers and the process streams alike) and the command error
// (a non-nil error is exit status 1).
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	re, we, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	os.Stdout, os.Stderr = wo, we
	outc, errc := make(chan string, 1), make(chan string, 1)
	go func() { b, _ := io.ReadAll(ro); outc <- string(b) }()
	go func() { b, _ := io.ReadAll(re); errc <- string(b) }()

	var ob, eb bytes.Buffer
	root := NewRootCmd()
	root.SetArgs(args)
	root.SetOut(&ob)
	root.SetErr(&eb)
	err = root.Execute()

	wo.Close()
	we.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-outc + ob.String(), <-errc + eb.String(), err
}

// ---- snapshots ------------------------------------------------------------------

type cliEntry struct {
	dir   bool
	data  string
	mtime int64
}

type cliTree map[string]cliEntry

func cliSnap(t *testing.T, root string) cliTree {
	t.Helper()
	tr := cliTree{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root || d.Name() == ".sshm.lock" {
			return nil
		}
		if d.IsDir() {
			tr[p] = cliEntry{dir: true}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		tr[p] = cliEntry{data: string(b), mtime: fi.ModTime().UnixNano()}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// cliRequireUnchanged: same files, same bytes, same mtimes, nothing new.
func cliRequireUnchanged(t *testing.T, before, after cliTree) {
	t.Helper()
	var d []string
	for p, b := range before {
		if a, ok := after[p]; !ok {
			d = append(d, "removed "+p)
		} else if a != b {
			d = append(d, "changed "+p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			d = append(d, "added "+p)
		}
	}
	sort.Strings(d)
	if len(d) > 0 {
		t.Errorf("files changed, want everything untouched:\n  %s", strings.Join(d, "\n  "))
	}
}

// cliRequireBytes: file contents (not mtimes) are as before; other files may be added.
func cliRequireBytes(t *testing.T, path, want string) {
	t.Helper()
	if got := cliRead(t, path); got != want {
		t.Errorf("%s changed:\n%s", path, got)
	}
}

// ---- text helpers -----------------------------------------------------------------

func cliLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// cliNorm collapses runs of whitespace so column widths do not matter.
func cliNorm(l string) string { return strings.Join(strings.Fields(l), " ") }

func cliLineOf(t *testing.T, text, needle string) int {
	t.Helper()
	for i, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if l == needle {
			return i + 1
		}
	}
	t.Fatalf("fixture has no line %q", needle)
	return 0
}

func cliSSHVal(t *testing.T, main, host, key string) string {
	t.Helper()
	if cliRealSSH == "" {
		t.Skip("ssh not in PATH")
	}
	out, err := exec.Command(cliRealSSH, "-F", main, "-G", host).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G %s: %v\n%s", host, err, out)
	}
	var vals []string
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, _ := strings.Cut(l, " "); k == key {
			vals = append(vals, v)
		}
	}
	return strings.Join(vals, ",")
}

func cliNeedSSH(t *testing.T) {
	t.Helper()
	if cliRealSSH == "" {
		t.Skip("ssh not in PATH")
	}
}
