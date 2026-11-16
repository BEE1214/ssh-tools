package app

// Mutation-audit additions for `sshm doctor` (PLAN-p5.md). Each test below was
// written for a mutant of internal/app/doctor.go that the original doctor tests
// (doctor_test.go, doctor_ssh_test.go) let survive; the mutant is named in the
// comment. Black-box through App.Doctor, real ssh / ssh-keygen as the oracle,
// temp dirs only (newDrEnv sets $HOME and the passwd home to temp dirs).
//
// Not parallel: they set $HOME and the passwd-home override.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// auIndex is the index of the first finding matching pred, or -1.
func auIndex(is []domain.Issue, pred func(domain.Issue) bool) int {
	for i, x := range is {
		if pred(x) {
			return i
		}
	}
	return -1
}

// Mutants: any rule-name literal in doctor.go changed (e.g. "hardening-hashknownhosts"
// -> "hardening-hashknownhost"). The original tests compare findings against the
// Rule* constants only, so a typo in a literal is invisible to them; the rule name
// is what the user sees in `[rule]` and what scripts grep for (PLAN-p5.md section 4).
func TestAuditDoctor_RuleNamesAreTheSpecifiedStrings(t *testing.T) {
	for _, c := range [][2]string{
		{RuleMissingIdentityFile, "missing-identity-file"},
		{RuleMissingCertFile, "missing-cert-file"},
		{RuleUnsafePermissions, "unsafe-permissions"},
		{RuleManagedPermissions, "managed-permissions"},
		{RuleCertExpired, "cert-expired"},
		{RuleNotSetUp, "not-set-up"},
		{RuleIncludeConditional, "include-conditional"},
		{RuleHomeMismatch, "home-mismatch"},
		{RuleSSHMissing, "ssh-missing"},
		{RuleVerifySkipped, "verify-skipped"},
		{RuleSSHRejectsConfig, "ssh-rejects-config"},
		{RuleHardeningHashKnownHosts, "hardening-hashknownhosts"},
		{RuleHardeningIdentitiesOnly, "hardening-identitiesonly"},
		{RuleAgentForwardingDefault, "agent-forwarding-default"},
	} {
		if c[0] != c[1] {
			t.Errorf("rule name %q, want %q", c[0], c[1])
		}
	}
}

// Mutant: `~user/x` expanded as if it were `~/x` (HasPrefix "~" instead of "~" or
// "~/"). doctor cannot resolve another user's home, so it must say nothing about
// such a value (doctorCheckablePath documents "a ~user path" as not checked)
// instead of reporting a bogus "<home>user/x does not exist".
func TestAuditDoctor_D7_TildeUserPathIsNotChecked(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n"+
		"  IdentityFile ~dr-no-such-user/id_missing\n"+
		"  CertificateFile ~dr-no-such-user/id_missing-cert.pub\n", mgAbsent)
	// Where the mutant would look: the passwd home with "dr-no-such-user/..." glued on.
	is := e.run(t, false)
	drNoRule(t, is, RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions, RuleCertExpired)
}

// Mutant: the `|| h.Disabled` skip removed from the file checks. A block inside a
// disabled group region is commented out; ssh never reads it, so a key it names
// is no finding.
func TestAuditDoctor_D7_DisabledBlocksAreNotChecked(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n\n"+
		"# sshm disabled group=ops start\n"+
		"# Host ops-1\n#   HostName 10.0.0.41\n#   IdentityFile @K@/gone\n#   CertificateFile @K@/gone-cert.pub\n"+
		"# sshm disabled group=ops end\n", mgAbsent)
	e.key(t, "ok", 0o600)
	is := e.run(t, false)
	drNoRule(t, is, RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions)
}

// Mutant: issueFile always returns the path (the main file is reported with its
// path). PLAN-p5.md 5.2: Issue.File is empty for findings in the main file, the
// exact path for any other file. The original tests accept both for the main file
// (drEnv.fileOK), so this pins it for D7, D8, D9, D10, D12 and D16.
func TestAuditDoctor_5_2_MainFileFindingsHaveEmptyFile(t *testing.T) {
	cert := ""
	e := newDrEnv(t, mgAbsent, mgAbsent)
	if drKeygen != "" {
		cert = "  CertificateFile " + drCert(t, e.keys, "expired", "20200101:20200102") + "\n"
	}
	inc := filepath.Join(e.dir, "inc.conf")
	e.setMain(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/gone\n  IdentityFile @K@/loose\n"+
		"  CertificateFile @K@/gone-cert.pub\n"+cert+"  Include @D@/inc.conf\n")
	e.file(t, inc, "Host inc-1\n  HostName 10.0.0.2\n  IdentityFile @K@/inc-gone\n", 0o600)
	e.key(t, "loose", 0o644)
	if err := os.Chmod(e.main, 0o664); err != nil { // D10 on the main file
		t.Fatal(err)
	}
	is := e.run(t, false)
	seen := map[string]bool{}
	for _, x := range is {
		switch x.Rule {
		case RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions, RuleCertExpired, RuleIncludeConditional:
		default:
			continue
		}
		want := "" // main file
		if x.HostName == "inc-1" {
			want = inc
		}
		if x.File != want {
			t.Errorf("File = %q, want %q for %s", x.File, want, drFmt(x))
		}
		seen[x.Rule] = true
	}
	for _, r := range []string{RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions, RuleIncludeConditional} {
		if !seen[r] {
			t.Errorf("fixture error: no %s finding; all findings:\n%s", r, drDump(is))
		}
	}
	if drKeygen != "" && !seen[RuleCertExpired] {
		t.Errorf("fixture error: no %s finding; all findings:\n%s", RuleCertExpired, drDump(is))
	}
}

// Mutant: os.Lstat instead of os.Stat for IdentityFile. ssh follows symlinks: a
// dangling link is a missing key (D7) and a link to a group-readable key is an
// unsafe key (D9), a link to a private key is fine.
func TestAuditDoctor_D7_D9_SymlinkedKeysAreFollowed(t *testing.T) {
	e := newDrEnv(t, "Host a\n  HostName 10.0.0.1\n"+
		"  IdentityFile @K@/dangling\n  IdentityFile @K@/to-loose\n  IdentityFile @K@/to-ok\n", mgAbsent)
	e.key(t, "real-loose", 0o644)
	e.key(t, "real-ok", 0o600)
	for link, target := range map[string]string{
		"dangling": "no-such-target",
		"to-loose": "real-loose",
		"to-ok":    "real-ok",
	} {
		if err := os.Symlink(filepath.Join(e.keys, target), filepath.Join(e.keys, link)); err != nil {
			t.Fatal(err)
		}
	}
	is := e.run(t, false)
	if m := drWantN(t, is, RuleMissingIdentityFile, 1); len(m) == 1 && !strings.Contains(m[0].Message, "/keys/dangling") {
		t.Errorf("missing-identity-file = %s, want the dangling link", drFmt(m[0]))
	}
	if u := drWantN(t, is, RuleUnsafePermissions, 1); len(u) == 1 && !strings.Contains(u[0].Message, "/keys/to-loose") {
		t.Errorf("unsafe-permissions = %s, want the link to the loose key", drFmt(u[0]))
	}
}

// Mutant: D12 findings placed before everything else (append(expired, out...)).
// D5: table order is D7, D8, D9, D10, D11, D12. The original D5 order test has no
// expired certificate in its fixture.
func TestAuditDoctor_D5_FileChecksFollowTableOrderIncludingD12(t *testing.T) {
	drNeedKeygen(t)
	e := newDrEnv(t, mgAbsent, mgAbsent)
	expired := drCert(t, e.keys, "expired", "20200101:20200102")
	e.setMain(t, "Include @M@\n\nHost web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/gone\n  IdentityFile @K@/loose\n"+
		"  CertificateFile @K@/gone-cert.pub\n  CertificateFile "+expired+"\n")
	e.file(t, e.managed, drManagedBody, 0o644) // D11
	e.key(t, "loose", 0o644)                   // D9
	e.key(t, "ok", 0o600)
	if err := os.Chmod(e.main, 0o664); err != nil { // D10
		t.Fatal(err)
	}
	is := e.run(t, false)
	pos := []int{
		auIndex(is, func(x domain.Issue) bool { return x.Rule == RuleMissingIdentityFile }), // D7
		auIndex(is, func(x domain.Issue) bool { return x.Rule == RuleMissingCertFile }),     // D8
		auIndex(is, func(x domain.Issue) bool {
			return x.Rule == RuleUnsafePermissions && strings.Contains(x.Message, "loose")
		}), // D9
		auIndex(is, func(x domain.Issue) bool { return x.Rule == RuleUnsafePermissions && drNames(x.Message, e.main) }), // D10
		auIndex(is, func(x domain.Issue) bool { return x.Rule == RuleManagedPermissions }),                              // D11
		auIndex(is, func(x domain.Issue) bool { return x.Rule == RuleCertExpired }),                                     // D12
	}
	for i, p := range pos {
		if p < 0 {
			t.Fatalf("fixture error: clause #%d (D7..D12) has no finding; all findings:\n%s", i, drDump(is))
		}
		if i > 0 && p <= pos[i-1] {
			t.Errorf("D7..D12 out of table order (positions %v); all findings:\n%s", pos, drDump(is))
			break
		}
	}
}

// Mutant: D16 skips Includes of a file that is itself read only conditionally
// (`!inc.Conditional && !f.Conditional` -> `!inc.Conditional`). inc.conf is
// included from below a Host line; its own top-level Include of other.conf is
// read only for hosts matching that Host line, so it is a D16 finding too.
func TestAuditDoctor_D16_IncludeInsideConditionallyIncludedFile(t *testing.T) {
	e := drWithOther(t, "Include @M@\n\n"+drWeb1+"  Include @D@/inc.conf\n", drManagedBody)
	inc := e.file(t, filepath.Join(e.dir, "inc.conf"), "Include @D@/other.conf\n", 0o600)
	got := drWantN(t, e.run(t, false), RuleIncludeConditional, 2)
	i := auIndex(got, func(x domain.Issue) bool { return x.File == inc })
	if i < 0 {
		t.Fatalf("no D16 finding in %s; got:\n%s", inc, drDump(got))
	}
	if want := "Include " + e.dir + "/other.conf is read only for matching hosts"; got[i].Message != want || got[i].Line != 1 {
		t.Errorf("got %s, want line 1 and message %q", drFmt(got[i]), want)
	}
}

// Mutant: includeReaches without glob expansion. A conditional Include whose glob
// reaches the managed file is D15 only; D16 must not report the same line again.
func TestAuditDoctor_D15_D16_ConditionalGlobReachingManagedIsReportedOnce(t *testing.T) {
	e := drWithOther(t, drWeb1+"Include @D@/config.d/*\n", drManagedBody)
	is := e.run(t, false)
	got := drWantN(t, is, RuleIncludeConditional, 1)
	if len(got) == 1 && strings.Contains(got[0].Message, "read only for matching hosts") {
		t.Errorf("the glob that reaches the managed file was reported as a D16 finding: %s", drFmt(got[0]))
	}
	drNoRule(t, is, RuleNotSetUp)
}

// Mutant: the probe host name is not sshm-doctor-probe. `Host * !sshm-doctor-probe`
// matches every name but the probe, so a different probe name sees the
// ForwardAgent / HashKnownHosts / IdentitiesOnly values and gets the opposite
// verdict. (ssh -G on the real probe name is the oracle.)
func TestAuditDoctor_D21toD23_ProbeIsExactlySshmDoctorProbe(t *testing.T) {
	mgNeedSSH(t)
	e := drWithOther(t, "Include @M@\n\nHost * !"+drProbe+"\n  HashKnownHosts yes\n  IdentitiesOnly yes\n  ForwardAgent yes\n", drManagedBody)
	out, _, exit := drSSHProbe(t, e.main)
	if exit != 0 || !strings.Contains(out, "\nhashknownhosts no\n") || !strings.Contains(out, "\nforwardagent no\n") {
		t.Fatalf("oracle: ssh -G %s (exit %d) must see the defaults, got:\n%s", drProbe, exit, out)
	}
	is := e.run(t, false)
	drWantN(t, is, RuleHardeningHashKnownHosts, 1)
	drWantN(t, is, RuleHardeningIdentitiesOnly, 1)
	drNoRule(t, is, RuleAgentForwardingDefault)
}

// Mutant: isManaged := p == managed (no samePath). The managed file reached through
// a symlinked directory is still the managed file: D11 applies (and nothing is
// reported as "not set up").
func TestAuditDoctor_D11_ManagedFileReachedThroughASymlinkedDirectory(t *testing.T) {
	e := drWithOther(t, "Include @D@/link/sshm.conf\n\n"+drWeb1, drManagedBody)
	if err := os.Symlink(filepath.Dir(e.managed), filepath.Join(e.dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.managed, 0o644); err != nil {
		t.Fatal(err)
	}
	is := e.run(t, false)
	drWantN(t, is, RuleManagedPermissions, 1)
	drNoRule(t, is, RuleNotSetUp, RuleIncludeConditional, RuleUnsafePermissions)
}
