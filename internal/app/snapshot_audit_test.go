package app

// Mutation-audit tests for P6 (PLAN-p6.md): clauses the original tests let a
// mutant slip through. Same fixtures (newMgEnv) and conventions as
// snapshot_managed_test.go / snapshot_problem_test.go. Placeholders only.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

func newHostNamed(name string) domain.Host {
	return domain.Host{Name: name, HostName: "10.0.0.99", IdentityFile: "/keys/new"}
}

// T6: "exists" is decided by the host's PATTERN, not by the raw text of its
// Host line: `Host cm-1 # prod` defines cm-1 (managed mode: managedView.has),
// so CheckHostName / CheckNewHost must refuse cm-1 whichever file holds it.
func TestSauT6_InlineRemarkHostNameExists(t *testing.T) {
	t.Parallel()
	const mainBody = "Include @M@\n\nHost main-r # remark\n  HostName 10.0.0.9\n"
	const managedBody = "# Managed by sshm.\n\nHost cm-1 # prod\n  HostName 10.0.0.5\n  User u\n"
	e := newMgEnv(t, mainBody, managedBody)
	e.backdate(t)
	before := e.snap(t)

	for _, name := range []string{"cm-1", "main-r"} {
		if err := e.a.CheckHostName(name); err == nil {
			t.Errorf("CheckHostName(%q) = nil, want an 'already exists' error (the host line carries an inline remark)", name)
		} else if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("CheckHostName(%q) = %v, want 'already exists'", name, err)
		}
		issues, err := e.a.CheckNewHost(newHostNamed(name))
		if err != nil {
			t.Fatalf("CheckNewHost(%q): %v", name, err)
		}
		found := false
		for _, i := range issues {
			if i.Rule == "host-name" && strings.Contains(i.Message, "already exists") {
				found = true
			}
		}
		if !found {
			t.Errorf("CheckNewHost(%q) has no host-name 'already exists' issue: %v", name, issues)
		}
	}
	// and AddHost really refuses it, i.e. the preview agrees with the write
	if err := e.a.AddHost(newHostNamed("cm-1")); err == nil {
		t.Errorf("AddHost(cm-1) succeeded, but the preview says the name is free")
	}
	if d := mgDiff(before, e.snap(t), false); len(d) != 0 {
		t.Errorf("checks/refused add changed files: %v", d)
	}
}

// T18: the reason is cut at the first ": " OUTSIDE quotes. A group name may
// contain ": ", and the parser quotes it with %q.
func TestSauT18_ReasonKeepsColonsInsideQuotes(t *testing.T) {
	t.Parallel()
	broken := smpHealthy + "\n# sshm disabled group=a: b start\n#Host zzz-1\n#  HostName 10.0.0.50\n"
	e := newMgEnv(t, smpMainInclude, broken)
	e.backdate(t)
	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	want := `managed file cannot be loaded (unterminated disabled group block "a: b"): ` + e.managed
	if s.ManagedProblem != want {
		t.Errorf("ManagedProblem = %q\n want %q", s.ManagedProblem, want)
	}
}

// T18: the managed file is reached by an Include spelled differently from
// ManagedPath (a symlinked directory), so no load warning names the managed
// path. The problem must still be reported and name the first blind spot
// (Loaded.Unfollowed[0], "<main>:<line>") instead of a generic "not loaded".
func TestSauT18_DifferentlySpelledIncludeNamesTheBlindSpot(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, "Include @D@/link/sshm.conf\n\nHost main-1\n  HostName 10.0.0.9\n", smpBroken)
	if err := os.Symlink(filepath.Join(e.dir, "config.d"), filepath.Join(e.dir, "link")); err != nil {
		t.Fatal(err)
	}
	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.Managed {
		t.Fatalf("Managed = true for a managed file that cannot be loaded")
	}
	want := "managed file cannot be loaded (" + e.main + ":1): " + e.managed
	if s.ManagedProblem != want {
		t.Errorf("ManagedProblem = %q\n want %q", s.ManagedProblem, want)
	}
}

// T18: the reason comes from the warning of the MANAGED file, not from the
// first load warning: a broken sibling include listed before it must not be
// reported in its place.
func TestSauT18_ReasonIsTheManagedFilesNotAnotherBrokenInclude(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, "Include @D@/other.conf\nInclude @M@\n\nHost main-1\n  HostName 10.0.0.9\n", smpBroken)
	mgWrite(t, filepath.Join(e.dir, "other.conf"), "# sshm disabled group=other start\n#Host o-1\n#  HostName 10.0.0.60\n", 0o600)
	e.backdate(t)
	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	want := `managed file cannot be loaded (unterminated disabled group block "zzz")`
	if !strings.HasPrefix(s.ManagedProblem, want) || !strings.HasSuffix(s.ManagedProblem, ": "+e.managed) {
		t.Errorf("ManagedProblem = %q, want prefix %q and the managed path last", s.ManagedProblem, want)
	}
	if strings.Contains(s.ManagedProblem, `group block "other"`) {
		t.Errorf("ManagedProblem = %q reports the other include's problem", s.ManagedProblem)
	}
}
