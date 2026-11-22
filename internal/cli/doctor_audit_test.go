package cli

// Mutation-audit addition for `sshm doctor` (PLAN-p5.md section 1: the synopsis is
// `sshm doctor [--strict] [--skip-files]`, no positional arguments). Reuses the
// helpers of doctor_test.go; temp dirs only.

import "testing"

// Mutant: `Args: cobra.NoArgs` removed from newDoctorCmd. `sshm doctor extra` (a
// typo for a flag, or a host name expected to be checked alone) would be accepted
// and silently ignored, and a clean config would print "No issues found.".
func TestAuditDoctorCLI_RejectsPositionalArguments(t *testing.T) {
	cliNeedSSH(t)
	newDocCLI(t, "Include @M@\n\n"+dcWeb1+"\n"+dcStar, cliManagedHeader)
	// Sanity: without the argument this fixture is clean.
	if stdout, _, err := dcRun(t); err != nil || stdout != dcNoIssu+"\n" {
		t.Fatalf("fixture error: want a clean run, got stdout=%q err=%v", stdout, err)
	}
	stdout, stderr, err := dcRun(t, "web-1")
	if err == nil {
		t.Errorf("doctor web-1: want an error for a positional argument, got nil\nstdout=%q stderr=%q", stdout, stderr)
	}
	if stdout != "" {
		t.Errorf("doctor web-1: stdout = %q, want nothing (the run must not start)", stdout)
	}
}
