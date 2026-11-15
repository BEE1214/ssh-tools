package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

// testHome is the fake passwd home for this package's tests: "~" and relative
// Include paths resolve here instead of the real ~/.ssh.
var testHome string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sshm-app-home-")
	if err != nil {
		panic(err)
	}
	testHome = dir
	restore := config.SetHomeDirForTest(dir)
	code := m.Run()
	restore()
	os.RemoveAll(dir)
	os.Exit(code)
}

// TestNoTestTouchesRealHome is a source-level guard: tests in the layers that
// load configs must build their App with NewAppWithPath on a temp file. The
// constructors that resolve the real ~/.ssh/config (NewApp, FindConfig) and
// $HOME lookups are banned from test files.
func TestNoTestTouchesRealHome(t *testing.T) {
	banned := regexp.MustCompile(`\bNewApp\(\)|\bFindConfig\(|\bUserHomeDir\(|\bapp\.NewApp\b`)
	for _, pkg := range []string{"../app", "../tui", "../cli", "../config"} {
		files, err := filepath.Glob(filepath.Join(pkg, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no test files found in %s: guard would be vacuous", pkg)
		}
		for _, f := range files {
			if filepath.Base(f) == "guard_test.go" {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for n, line := range strings.Split(string(data), "\n") {
				if banned.MatchString(line) {
					t.Errorf("%s:%d resolves the real home config: %s", f, n+1, strings.TrimSpace(line))
				}
			}
		}
	}
}

// The override must actually be in effect: a relative and a tilde pattern
// resolve under testHome, not the real home.
func TestHomeOverrideInEffect(t *testing.T) {
	if err := os.MkdirAll(filepath.Join(testHome, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	for pat, want := range map[string]string{
		"~/guard-a.conf": filepath.Join(testHome, "guard-a.conf"),
		"guard-b.conf":   filepath.Join(testHome, ".ssh", "guard-b.conf"),
	} {
		if err := os.WriteFile(want, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(want) })
		got, warn := config.ExpandInclude(pat)
		if warn != "" || len(got) != 1 || got[0] != want {
			t.Errorf("ExpandInclude(%q) = %v, %q; want [%s]", pat, got, warn, want)
		}
	}
}
