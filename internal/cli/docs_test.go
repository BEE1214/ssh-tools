package cli

// P7 clause X5 (PLAN-p7.md), as far as a test can see it: README and
// ARCHITECTURE no longer describe a legacy mode, name `sshm init` (fresh machine)
// and `sshm setup` as the first run, and list the limits. Keyword checks only
// (the wording is the implementer's): the clause is oracle-less, a reviewer has
// to read the text.

import (
	"os"
	"strings"
	"testing"
)

func docsText(t *testing.T) (readme, arch string) {
	t.Helper()
	r, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile("../../ARCHITECTURE.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(r) == 0 || len(a) == 0 {
		t.Fatal("README.md or ARCHITECTURE.md is empty")
	}
	return string(r), string(a)
}

// Green now: neither document talks about a legacy mode of the writer.
func TestDocs_NoLegacyMode(t *testing.T) {
	readme, arch := docsText(t)
	for name, text := range map[string]string{"README.md": readme, "ARCHITECTURE.md": arch} {
		low := strings.ToLower(text)
		for _, bad := range []string{"legacy mode", "legacy writer"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s still mentions %q", name, bad)
			}
		}
	}
}

// First run and limits are documented (README).
func TestDocs_FirstRunAndLimits(t *testing.T) {
	readme, _ := docsText(t)
	low := strings.ToLower(readme)
	for _, c := range []struct {
		what string
		any  []string
	}{
		{"first run with `sshm init`", []string{"sshm init"}},
		{"first run with `sshm setup`", []string{"sshm setup"}},
		{"limit: multi-pattern Host lines", []string{"multi-pattern", "several patterns"}},
		{"limit: DevPod blocks stay in the main file", []string{"devpod"}},
		{"limit: Match blocks stay in the main file", []string{"match"}},
		{"limit: a dotfile manager that overwrites the main file", []string{"dotfile"}},
		{"limit: SIGKILL during a save", []string{"sigkill"}},
		{"limit: clients that do not follow Include", []string{"do not follow", "does not follow", "don't follow", "not follow `include`", "not follow include"}},
	} {
		ok := false
		for _, kw := range c.any {
			if strings.Contains(low, kw) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("README.md lacks %s (looked for any of %q)", c.what, c.any)
		}
	}
}

// ARCHITECTURE describes the write path without the main-file rewrite.
func TestDocs_ArchitectureHasNoMainFileRewrite(t *testing.T) {
	_, arch := docsText(t)
	low := strings.ToLower(arch)
	for _, bad := range []string{"config.write", "re-serialize the main", "reserialize the main"} {
		if strings.Contains(low, bad) {
			t.Errorf("ARCHITECTURE.md still describes %q", bad)
		}
	}
}
