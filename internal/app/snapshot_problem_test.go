package app

// Black-box tests for T18 (PLAN-p6.md 4.2): Snapshot.ManagedProblem.
//
// A managed file that an UNCONDITIONAL Include reaches, that exists, but that
// cannot be loaded (unparsable or unreadable) is reported in ManagedProblem;
// Managed stays false. A missing managed file, a missing Include, a
// conditional Include and a healthy file leave it empty. Fixtures live in
// t.TempDir() (newMgEnv); hosts and addresses are placeholders.

import (
	"os"
	"strings"
	"testing"
)

const smpMainInclude = `Include @M@

Host main-1
  HostName 10.0.0.9
  User mainuser
`

// smpMainNoInclude never mentions the managed file.
const smpMainNoInclude = `Host main-1
  HostName 10.0.0.9
  User mainuser
`

// smpMainConditional includes the managed file below a Host line, so ssh
// applies it only inside that block.
const smpMainConditional = `Host main-1
  HostName 10.0.0.9
  User mainuser

Include @M@
`

const smpHealthy = `# Managed by sshm. Hosts in this file are edited by sshm.

Host web-1
  HostName 10.0.0.1
  User alice
`

// smpBroken has a disabled-group start marker without its end marker, which
// config.Parse refuses ("unterminated disabled group block").
const smpBroken = smpHealthy + `
# sshm disabled group=zzz start
#Host zzz-1
#  HostName 10.0.0.50
`

func smpSnapshot(t *testing.T, mainBody, managedBody string) (Snapshot, *mgEnv) {
	t.Helper()
	e := newMgEnv(t, mainBody, managedBody)
	e.backdate(t)
	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	return s, e
}

func TestSmpT18_UnparsableManagedFileIsReported(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, smpMainInclude, smpBroken)
	e.backdate(t)
	before := e.snap(t)

	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v (a broken managed file is a problem to report, not a load failure)", err)
	}
	if s.ManagedProblem == "" {
		t.Fatalf("ManagedProblem is empty, want the managed file's load problem")
	}
	if !strings.Contains(s.ManagedProblem, e.managed) {
		t.Errorf("ManagedProblem = %q, want it to name the managed path %s", s.ManagedProblem, e.managed)
	}
	want := `managed file cannot be loaded (unterminated disabled group block "zzz"`
	if !strings.HasPrefix(s.ManagedProblem, want) {
		t.Errorf("ManagedProblem = %q, want the reason first, prefix %q", s.ManagedProblem, want)
	}
	if !strings.HasSuffix(s.ManagedProblem, "): "+e.managed) {
		t.Errorf("ManagedProblem = %q, want the path last", s.ManagedProblem)
	}
	if n := strings.Count(s.ManagedProblem, e.managed); n != 1 {
		t.Errorf("ManagedProblem = %q names the managed path %d times, want once", s.ManagedProblem, n)
	}
	if s.Managed {
		t.Errorf("Managed = true with a managed file that cannot be loaded, want false")
	}
	if s.ManagedPath != e.managed {
		t.Errorf("ManagedPath = %q, want %q", s.ManagedPath, e.managed)
	}
	if d := mgDiff(before, e.snap(t), false); len(d) != 0 {
		t.Errorf("Snapshot changed files: %v", d)
	}
}

func TestSmpT18_UnreadableManagedFileIsReported(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of their mode")
	}
	e := newMgEnv(t, smpMainInclude, smpHealthy)
	if err := os.Chmod(e.managed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.managed, 0o600) })

	s, err := e.a.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if s.ManagedProblem == "" || !strings.Contains(s.ManagedProblem, e.managed) {
		t.Errorf("ManagedProblem = %q, want a text naming %s", s.ManagedProblem, e.managed)
	}
	if s.Managed {
		t.Errorf("Managed = true for an unreadable managed file, want false")
	}
}

func TestSmpT18_MissingManagedFileIsNotAProblem(t *testing.T) {
	t.Parallel()
	s, e := smpSnapshot(t, smpMainInclude, mgAbsent)
	if s.ManagedProblem != "" {
		t.Errorf("ManagedProblem = %q for a managed file that was never created, want empty", s.ManagedProblem)
	}
	if s.Managed {
		t.Errorf("Managed = true without a managed file, want false")
	}
	if s.ManagedPath != e.managed {
		t.Errorf("ManagedPath = %q, want %q", s.ManagedPath, e.managed)
	}
}

func TestSmpT18_NoIncludeIsNotAProblem(t *testing.T) {
	t.Parallel()
	// Even a broken managed file does not matter while nothing includes it.
	for name, managedBody := range map[string]string{"broken": smpBroken, "healthy": smpHealthy, "absent": mgAbsent} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, _ := smpSnapshot(t, smpMainNoInclude, managedBody)
			if s.ManagedProblem != "" {
				t.Errorf("ManagedProblem = %q without an Include of the managed file, want empty", s.ManagedProblem)
			}
			if s.Managed {
				t.Errorf("Managed = true without an Include, want false")
			}
		})
	}
}

func TestSmpT18_ConditionalIncludeIsNotAProblem(t *testing.T) {
	t.Parallel()
	s, _ := smpSnapshot(t, smpMainConditional, smpBroken)
	if s.ManagedProblem != "" {
		t.Errorf("ManagedProblem = %q for a conditional Include, want empty (only an unconditional Include counts)", s.ManagedProblem)
	}
	if s.Managed {
		t.Errorf("Managed = true for a conditional Include, want false")
	}
}

func TestSmpT18_HealthyManagedFileHasNoProblem(t *testing.T) {
	t.Parallel()
	s, _ := smpSnapshot(t, smpMainInclude, smpHealthy)
	if s.ManagedProblem != "" {
		t.Errorf("ManagedProblem = %q for a healthy managed file, want empty", s.ManagedProblem)
	}
	if !s.Managed {
		t.Errorf("Managed = false for a healthy managed file, want true")
	}
}

// Fixing the file clears the problem on the next snapshot.
func TestSmpT18_ProblemClearsWhenTheFileIsFixed(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, smpMainInclude, smpBroken)
	s, err := e.a.Snapshot()
	if err != nil || s.ManagedProblem == "" {
		t.Fatalf("setup: Snapshot = %+v, %v; want a problem", s.ManagedProblem, err)
	}
	mgWrite(t, e.managed, smpHealthy, 0o600)
	s, err = e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.ManagedProblem != "" || !s.Managed {
		t.Errorf("after the fix: ManagedProblem=%q Managed=%v, want empty and true", s.ManagedProblem, s.Managed)
	}
}
