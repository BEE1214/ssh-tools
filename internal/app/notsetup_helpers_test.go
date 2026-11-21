package app

// Fixtures and helpers for the not-set-up gate, init-fresh, multi-pattern,
// hostname and backup-hint tests (PLAN-p7.md). Everything is built by hand in
// t.TempDir(): a not-set-up fixture is a plain main file, a set-up fixture has
// an absolute Include of the managed file as line 1 plus the managed file
// (0600). `sshm setup` is never used to build a fixture. ssh is only called
// with -F <temp main>; the real ~/.ssh is never touched.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// nsGateText is the user-visible text of ErrNotSetUp (PLAN-p7.md G1), spelled
// out so a change of the sentinel's text is noticed.
const nsGateText = "sshm is not set up: run 'sshm setup' first"

const nsExtraBody = "Host inc-1\n  HostName 10.0.1.1\n"

// nsHostBlocks are the hosts of the standard fixtures: web-1 (references a
// certificate), sign-1 (a key without certificate), db-1, a multi-pattern line.
const nsHostBlocks = `Host web-1
  HostName 10.0.0.1
  User alice
  IdentityFile @D@/keys/web1
  CertificateFile @D@/keys/web1-cert.pub

Host sign-1
  HostName 10.0.0.4
  User carol
  IdentityFile @D@/keys/sign1

Host db-1
  HostName 10.0.0.2

Host p-1 p-2
  HostName 10.0.0.3
`

const nsTail = "\nHost *\n  ServerAliveInterval 30\n"

// nsNotSetUpMain is a main file without an Include of the managed file; inc-1
// lives in an included file.
const nsNotSetUpMain = "Include @D@/extra.conf\n\n" + nsHostBlocks + nsTail

// nsSetUpMain / nsSetUpManaged are the same hosts in a set-up config.
const nsSetUpMain = "Include @M@\nInclude @D@/extra.conf\n" + nsTail

const nsSetUpManaged = mgManagedHeader + "\n" + nsHostBlocks

// nsNew builds an environment from hand-written bodies (see newMgEnv for the
// substitutions) plus the key files and extra.conf every fixture shares.
func nsNew(t *testing.T, mainBody, managedBody string) *mgEnv {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	e := newMgEnv(t, mainBody, managedBody)
	mgWrite(t, filepath.Join(e.dir, "extra.conf"), nsExtraBody, 0o600)
	for name, body := range map[string]string{
		"keys/ca":              "CA-PRIVATE\n",
		"keys/web1":            "PRIVATE\n",
		"keys/web1.pub":        "ssh-ed25519 AAAAweb1 test\n",
		"keys/web1-cert.pub":   "OLD-CERT\n",
		"keys/sign1":           "PRIVATE\n",
		"keys/sign1.pub":       "ssh-ed25519 AAAAsign1 test\n",
		"keys/orphan-cert.pub": "ORPHAN-CERT\n",
	} {
		mgWrite(t, filepath.Join(e.dir, name), body, 0o600)
	}
	return e
}

// nsNotSetUp: a plain main file, no managed file.
func nsNotSetUp(t *testing.T) *mgEnv { t.Helper(); return nsNew(t, nsNotSetUpMain, mgAbsent) }

// nsSetUp: Include of the managed file as line 1, managed file with the hosts.
func nsSetUp(t *testing.T) *mgEnv { t.Helper(); return nsNew(t, nsSetUpMain, nsSetUpManaged) }

// ---- tree snapshot (G2) ---------------------------------------------------------

type nsNode struct {
	dir   bool
	mode  os.FileMode
	sum   [sha256.Size]byte
	mtime int64 // regular files only; directories change mtime with any entry
}

type nsTree map[string]nsNode

// nsSnap records every file and directory below root: relative path, mode, a
// content hash (and the mtime of files, which the fixtures set far in the past,
// so a rewrite with identical bytes shows). Lock files are NOT ignored.
func nsSnap(t *testing.T, root string) nsTree {
	t.Helper()
	tr := nsTree{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		n := nsNode{dir: fi.IsDir(), mode: fi.Mode()}
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			n.sum = sha256.Sum256(b)
			n.mtime = fi.ModTime().UnixNano()
		}
		tr[rel] = n
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) == 0 {
		// A fixture without files would make every "unchanged" check vacuous.
		t.Fatalf("fixture %s is empty", root)
	}
	return tr
}

func nsDiff(before, after nsTree) []string {
	var out []string
	for p, b := range before {
		a, ok := after[p]
		switch {
		case !ok:
			out = append(out, "removed "+p)
		case a != b:
			out = append(out, "changed "+p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			out = append(out, "added "+p)
		}
	}
	sort.Strings(out)
	return out
}

func nsRequireSame(t *testing.T, before, after nsTree) {
	t.Helper()
	if d := nsDiff(before, after); len(d) > 0 {
		t.Errorf("the ssh dir changed, want nothing created or modified (no file, no directory, no lock, no backup):\n  %s", strings.Join(d, "\n  "))
	}
}

// nsRequireSameExceptLock is nsRequireSame for refusals of a save that is past
// the gate: those take the .sshm.lock of the file, which stays behind (saves
// leave it by design, see managedLockName); everything else must be unchanged.
func nsRequireSameExceptLock(t *testing.T, before, after nsTree) {
	t.Helper()
	var d []string
	for _, line := range nsDiff(before, after) {
		if !strings.HasSuffix(line, ".sshm.lock") {
			d = append(d, line)
		}
	}
	if len(d) > 0 {
		t.Errorf("the ssh dir changed (a lock file is tolerated):\n  %s", strings.Join(d, "\n  "))
	}
}

// ---- errors ------------------------------------------------------------------------

// nsRequireGate: err is the refusal of the gate (G1): errors.Is(ErrNotSetUp)
// and the fixed text.
func nsRequireGate(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want ErrNotSetUp (%s)", nsGateText)
	}
	if errors.Is(err, ErrNotImplemented) {
		t.Fatalf("got the skeleton's ErrNotImplemented, want ErrNotSetUp (%s)", nsGateText)
	}
	if !errors.Is(err, ErrNotSetUp) {
		t.Fatalf("got %q, want an error that is ErrNotSetUp (%s)", err, nsGateText)
	}
	if !strings.Contains(err.Error(), nsGateText) {
		t.Fatalf("error text %q does not contain %q", err, nsGateText)
	}
}

// ---- fake ssh-keygen -----------------------------------------------------------------

// nsFakeKeygen puts an ssh-keygen first in PATH that records every call in a
// marker file and, like the real one for `-s`, writes <pub minus .pub>-cert.pub.
// `-L` (inspect) fails quietly. It returns the marker path (absent = never run).
func nsFakeKeygen(t *testing.T) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "ran")
	script := fmt.Sprintf(`#!/bin/sh
case "$1" in -L) exit 1;; esac
echo "$@" >> '%s'
eval "pub=\${$#}"
cert="${pub%%.pub}-cert.pub"
echo FAKE-CERT > "$cert"
`, marker)
	if err := os.WriteFile(filepath.Join(dir, "ssh-keygen"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

// ---- snapshot lookups -------------------------------------------------------------------

// nsEntry returns the Snapshot entry named name; it fails when there is none or
// several (a helper that returns the zero value would make bound checks vacuous).
func nsEntry(t *testing.T, a *App, name string) HostEntry {
	t.Helper()
	snap, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	var got []HostEntry
	for _, e := range snap.Hosts {
		if e.Name == name {
			got = append(got, e)
		}
	}
	if len(got) != 1 {
		var names []string
		for _, e := range snap.Hosts {
			names = append(names, fmt.Sprintf("%q", e.Name))
		}
		t.Fatalf("Snapshot has %d entries named %q, want exactly 1 (names: %s)", len(got), name, strings.Join(names, ", "))
	}
	return got[0]
}

// nsHostByLine returns the host (merged view) whose Host line is at the given
// 1-based line of file.
func nsHostByLine(t *testing.T, a *App, file string, line int) domain.Host {
	t.Helper()
	snap, err := a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for _, e := range snap.Hosts {
		if e.LineStart == line && filepath.Clean(e.SourceFile) == filepath.Clean(file) {
			return e.Host
		}
	}
	t.Fatalf("no host at %s:%d", file, line)
	return domain.Host{}
}

// nsEmptyPath empties PATH so an exec-ing method stops at "not found".
func nsEmptyPath(t *testing.T) { t.Helper(); t.Setenv("PATH", t.TempDir()) }
