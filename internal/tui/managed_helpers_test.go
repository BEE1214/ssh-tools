package tui

// Fixtures and helpers for the P6 tests (managed_test.go, PLAN-p6.md).
//
// Everything lives in t.TempDir(): a main config whose FIRST line is an
// absolute Include of <tmp>/config.d/sshm.conf, the managed file (0600 in a
// 0700 directory) with the editable hosts, hosts in the main file and in a
// third included file for the read-only cases, and a Host * block. Hosts and
// addresses are placeholders. ssh is only ever called with -F <temp main>.
// The helpers use no Model field that PLAN-p6.md removes (no `editable`).

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/adamdvorsky/ssh-tools/internal/app"
)

// tmAbsent as a file body means: do not create that file.
const tmAbsent = "\x00absent"

var tmPast = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

const tmMainBody = `Include @M@
Include @D@/extra.conf

# notes in the main file
Host main-1
  HostName 10.0.0.9
  User mainuser
  IdentityFile /keys/main1

# DevPod Start other.devpod
Host other.devpod
  User root
  ProxyCommand "/usr/bin/devpod-cli" ssh --stdio --context default --user root other
  ForwardAgent yes
  StrictHostKeyChecking no
  LogLevel error
  HostKeyAlgorithms rsa-sha2-256
# DevPod End other.devpod

Host *
  ServerAliveInterval 30
`

const tmManagedBody = `# Managed by sshm. Hosts in this file are edited by sshm.

# primary web host
Host web-1
  # the web node
  HostName 10.0.0.1
  User alice
  Port 2222
  IdentityFile /keys/web1
  # keepalive for web-1
  ServerAliveInterval 40

Host db-1
  HostName 10.0.0.2
  User bob
  IdentityFile /keys/db1

Host nouser-1
  HostName 10.0.0.3
  IdentityFile /keys/n1

Host bare-1
  HostName 10.0.0.4
  User carol

# DevPod Start demo.devpod
Host demo.devpod
  User root
  ProxyCommand "/usr/bin/devpod-cli" ssh --stdio --context default --user root demo
  ForwardAgent yes
  StrictHostKeyChecking no
  LogLevel error
  HostKeyAlgorithms rsa-sha2-256
# DevPod End demo.devpod

Host old-1
  HostName 10.0.0.31
  IdentityFile /keys/old1

Host old-2
  HostName 10.0.0.32
  IdentityFile /keys/old2
`

const tmExtraBody = `Host inc-1
  HostName 10.0.0.70
  User incuser
  IdentityFile /keys/inc1

Host inc-2
  HostName 10.0.0.71
`

// tmLegacyMainBody: the same editable hosts without the Include of the
// managed file (legacy mode); web-1 and db-1 sit in the main file.
const tmLegacyMainBody = `Include @D@/extra.conf

# primary web host
Host web-1
  # the web node
  HostName 10.0.0.1
  User alice
  Port 2222
  IdentityFile /keys/web1
  # keepalive for web-1
  ServerAliveInterval 40

Host db-1
  HostName 10.0.0.2
  User bob
  IdentityFile /keys/db1

Host main-1
  HostName 10.0.0.9
  User mainuser
  IdentityFile /keys/main1

Host *
  ServerAliveInterval 30
`

// tmEnv is one temp config tree.
type tmEnv struct {
	dir, main, managed, extra string
	a                         *app.App
}

func (e *tmEnv) sub(s string) string {
	return strings.NewReplacer("@M@", e.managed, "@D@", e.dir, "@C@", e.main).Replace(s)
}

func tmWrite(t *testing.T, path, body string, mode os.FileMode) {
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
	if err := os.Chtimes(path, tmPast, tmPast); err != nil {
		t.Fatal(err)
	}
}

// tmNewEnv writes the main file, the managed file (unless tmAbsent) and the
// extra included file. Every file gets an mtime far in the past so a rewrite,
// even with identical bytes, is visible.
func tmNewEnv(t *testing.T, mainBody, managedBody string) *tmEnv {
	t.Helper()
	dir := t.TempDir()
	e := &tmEnv{
		dir:     dir,
		main:    filepath.Join(dir, "config"),
		managed: filepath.Join(dir, "config.d", "sshm.conf"),
		extra:   filepath.Join(dir, "extra.conf"),
	}
	if managedBody != tmAbsent {
		tmWrite(t, e.managed, e.sub(managedBody), 0o600)
	}
	tmWrite(t, e.extra, tmExtraBody, 0o600)
	tmWrite(t, e.main, e.sub(mainBody), 0o600)
	e.a = app.NewAppWithPath(e.main)
	return e
}

// tmModel builds a Model over e. The window is large so no row is scrolled
// out of view. It uses New only: nothing else switches editing on.
func tmModel(e *tmEnv) Model {
	m := New(e.a)
	m, _ = send(m, tea.WindowSizeMsg{Width: 140, Height: 60})
	return m
}

// tmManaged is the managed fixture. With gate it disables the group "old"
// (old-1, old-2, both in the managed file) through the app layer, which
// needs ssh.
func tmManaged(t *testing.T, gate bool) (Model, *tmEnv) {
	t.Helper()
	e := tmNewEnv(t, tmMainBody, tmManagedBody)
	if gate {
		tmNeedSSH(t)
		if err := e.a.DisableGroup("old"); err != nil {
			t.Fatalf("fixture: DisableGroup: %v", err)
		}
		tmBackdate(t, e.dir)
	}
	return tmModel(e), e
}

func tmLegacy(t *testing.T) (Model, *tmEnv) {
	t.Helper()
	e := tmNewEnv(t, tmLegacyMainBody, tmAbsent)
	return tmModel(e), e
}

func tmBackdate(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return err
		}
		return os.Chtimes(p, tmPast, tmPast)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// tmTree records every file below root (bytes, mode, mtime) and every
// directory (mode). The lock file that managed writes may leave behind is
// ignored; stray temp files and backups are not.
func tmTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
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
		if fi.IsDir() {
			out[p] = "dir " + fi.Mode().String()
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = fi.Mode().String() + " " + fi.ModTime().UTC().Format(time.RFC3339Nano) + "\n" + string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// tmRequireSame fails when anything below the tree changed (bytes, modes,
// mtimes, added or removed entries).
func tmRequireSame(t *testing.T, before, after map[string]string) {
	t.Helper()
	var diffs []string
	for p, b := range before {
		a, ok := after[p]
		switch {
		case !ok:
			diffs = append(diffs, "removed "+p)
		case a != b:
			diffs = append(diffs, "changed "+p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			diffs = append(diffs, "added "+p)
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Errorf("files changed, want everything untouched:\n  %s", strings.Join(diffs, "\n  "))
	}
}

// tmOnlyChanged fails unless exactly the listed files changed (by bytes).
func tmOnlyChanged(t *testing.T, before, after map[string]string, files ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, f := range files {
		want[f] = true
	}
	for p, b := range before {
		a, ok := after[p]
		if !ok {
			t.Errorf("removed %s", p)
			continue
		}
		if changed := tmBody(a) != tmBody(b); changed != want[p] {
			if changed {
				t.Errorf("%s changed, want it untouched", p)
			} else {
				t.Errorf("%s did not change", p)
			}
		}
	}
}

// tmBody strips the "mode mtime" header line of a tmTree entry.
func tmBody(entry string) string {
	_, body, _ := strings.Cut(entry, "\n")
	return body
}

func tmNeedSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}
}

// tmSSHG returns `ssh -F main -G host` as option -> values.
func tmSSHG(t *testing.T, main, host string) map[string][]string {
	t.Helper()
	tmNeedSSH(t)
	out, err := exec.Command("ssh", "-F", main, "-G", host).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -F %s -G %s: %v\n%s", main, host, err, out)
	}
	m := map[string][]string{}
	for _, l := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(l, " ")
		if k != "" {
			m[k] = append(m[k], v)
		}
	}
	return m
}

func tmSame(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv := b[k]
		if strings.Join(av, "\x00") != strings.Join(bv, "\x00") {
			return false
		}
	}
	return true
}

// tmDiffKeys lists the options whose values differ.
func tmDiffKeys(a, b map[string][]string) []string {
	var out []string
	seen := map[string]bool{}
	for k, av := range a {
		seen[k] = true
		if strings.Join(av, "\x00") != strings.Join(b[k], "\x00") {
			out = append(out, k)
		}
	}
	for k := range b {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// tmHostsToResolve is every fixture host plus one that matches only Host *.
var tmHostsToResolve = []string{"web-1", "db-1", "nouser-1", "bare-1", "main-1", "inc-1", "unmatched.invalid"}

func tmResolveAll(t *testing.T, e *tmEnv) map[string]map[string][]string {
	t.Helper()
	out := map[string]map[string][]string{}
	for _, h := range tmHostsToResolve {
		out[h] = tmSSHG(t, e.main, h)
	}
	return out
}

// tmRequireOnlyChangedOptions fails unless, between before and after, only
// the named options of the named host resolve differently.
func tmRequireOnlyChangedOptions(t *testing.T, before, after map[string]map[string][]string, host string, keys ...string) {
	t.Helper()
	sort.Strings(keys)
	for h, b := range before {
		got := tmDiffKeys(b, after[h])
		if h == host {
			if strings.Join(got, ",") != strings.Join(keys, ",") {
				t.Errorf("ssh -G %s: changed options %v, want exactly %v", h, got, keys)
			}
		} else if len(got) > 0 {
			t.Errorf("ssh -G %s changed (options %v), want it untouched", h, got)
		}
	}
}

// ---- view helpers ---------------------------------------------------------

// tmRow returns the list row of the named host (the line whose first word is
// the name), or "".
func tmRow(view, name string) string {
	for _, l := range strings.Split(view, "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == name {
			return l
		}
	}
	return ""
}

// tmExpandAll expands every group so every host has a row.
func tmExpandAll(m Model) Model {
	for _, h := range m.hosts {
		if !h.IsWildcard() {
			m = onHost(m, h.Name)
		}
	}
	return m
}

func tmHints(m Model) string { return ansi.Strip(m.hintsLine()) }

// tmHelp opens the help overlay, returns its text and closes it again.
func tmHelp(t *testing.T, m Model) (Model, string) {
	t.Helper()
	m, _ = press(m, "?")
	if m.mode != modeHelp {
		t.Fatalf("? did not open the help overlay: mode=%v", m.mode)
	}
	text := plain(m)
	m, _ = press(m, "x")
	if m.mode != modeList {
		t.Fatalf("a key did not close the help overlay: mode=%v", m.mode)
	}
	return m, text
}

// tmSetupToast is the T8 toast.
func tmSetupToast(e *tmEnv) string {
	return "editing needs setup: run 'sshm setup' to create " + e.a.ManagedPath()
}

// tmFillNew types a new-host form from the Host field to the end: name,
// HostName, User, Port, IdentityFile (replaced), ProxyJump (left empty).
func tmFillNew(m Model, name, host, user, port, ident string) Model {
	m = typeText(m, name)
	m, _ = press(m, "tab")
	m = set(m, host)
	m, _ = press(m, "tab")
	m = set(m, user)
	m, _ = press(m, "tab")
	m = set(m, port)
	m, _ = press(m, "tab")
	m = set(m, ident)
	return m
}

func tmLines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

// tmSubLines reports whether the lines of block appear in s as consecutive lines.
func tmSubLines(s, block string) bool {
	return strings.Contains("\n"+s, "\n"+strings.TrimSuffix(block, "\n")+"\n") ||
		strings.HasSuffix(s, "\n"+strings.TrimSuffix(block, "\n"))
}
