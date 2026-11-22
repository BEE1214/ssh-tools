package cli

// Fixtures and helpers for the not-set-up gate, init-fresh, multi-pattern,
// hostname and interrupt tests (PLAN-p7.md). Built by hand in temp dirs: a
// not-set-up fixture is a plain main file, a set-up fixture has an absolute
// Include of the managed file as line 1 plus the managed file (0600). The real
// ~/.ssh is never read or written; ssh runs only with -F <temp main>.

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const nsGateText = "sshm is not set up: run 'sshm setup' first"

const nsExtraBody = "Host inc-1\n  HostName 10.0.1.1\n"

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

const nsNotSetUpMain = "Include @D@/extra.conf\n\n" + nsHostBlocks + nsTail
const nsSetUpMain = "Include @M@\nInclude @D@/extra.conf\n" + nsTail
const nsSetUpManaged = cliManagedHeader + "\n" + nsHostBlocks

// nsNew builds the fixture (newCLIEnv: SSH_AUTH_CONFIG, home lookup redirected)
// plus extra.conf, the key files and a HOME with an empty .ssh (cert list).
func nsNew(t *testing.T, mainBody, managedBody string) *cliEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	e := newCLIEnv(t, mainBody, managedBody)
	e.write(t, filepath.Join(e.dir, "extra.conf"), nsExtraBody)
	for name, body := range map[string]string{
		"keys/ca":              "CA-PRIVATE\n",
		"keys/web1":            "PRIVATE\n",
		"keys/web1.pub":        "ssh-ed25519 AAAAweb1 test\n",
		"keys/web1-cert.pub":   "OLD-CERT\n",
		"keys/sign1":           "PRIVATE\n",
		"keys/sign1.pub":       "ssh-ed25519 AAAAsign1 test\n",
		"keys/orphan-cert.pub": "ORPHAN-CERT\n",
	} {
		e.write(t, filepath.Join(e.dir, name), body)
	}
	return e
}

func nsNotSetUp(t *testing.T) *cliEnv { t.Helper(); return nsNew(t, nsNotSetUpMain, cliAbsent) }
func nsSetUp(t *testing.T) *cliEnv    { t.Helper(); return nsNew(t, nsSetUpMain, nsSetUpManaged) }

// ---- tree snapshot -----------------------------------------------------------------

type nsNode struct {
	dir   bool
	mode  os.FileMode
	sum   [sha256.Size]byte
	mtime int64
}

type nsTree map[string]nsNode

// nsSnap records every file and directory below root (relative path, mode,
// content hash, mtime of files). Lock files are NOT ignored.
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
		t.Fatalf("fixture %s is empty: an 'unchanged' check would be vacuous", root)
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

// ---- fake ssh-keygen ------------------------------------------------------------------

// nsFakeKeygen puts an ssh-keygen first in PATH that records each call in a
// marker file and, like the real `-s`, writes <pub minus .pub>-cert.pub.
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

func nsEmptyPath(t *testing.T) { t.Helper(); t.Setenv("PATH", t.TempDir()) }

// nsAll is everything a command printed, for "does not mention X" checks.
func nsAll(stdout, stderr string, err error) string {
	s := stdout + "\n" + stderr
	if err != nil {
		s += "\n" + err.Error()
	}
	return s
}
