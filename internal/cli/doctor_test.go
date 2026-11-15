package cli

// Black-box CLI tests for `sshm doctor` (PLAN-p5.md D3, D4, D6, D25 and the
// section 5.1 clarifications). They drive the real root command with
// SSH_AUTH_CONFIG pointing at a temp main file; the passwd home and $HOME are
// both redirected to a temp dir, so the real ~/.ssh is never read.
//
// Not parallel (runCLI swaps os.Stdout/os.Stderr and the tests set $HOME).
//
// The TestReportDoctor_* tests exercise the already implemented presentation
// function directly; each is marked GREEN or RED against the skeleton.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

const (
	dcWeb1   = "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @D@/keys/ok\n"
	dcStar   = "Host *\n  HashKnownHosts yes\n  IdentitiesOnly yes\n"
	dcKey    = "-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n"
	dcNoSet  = "info [not-set-up] sshm-managed file is not included; run 'sshm setup'"
	dcSumRe  = `^\d+ error\(s\), \d+ warning\(s\) found\.$`
	dcNoIssu = "No issues found."
)

// newDocCLI is newCLIEnv plus the key every fixture refers to and a $HOME equal
// to the passwd home (so the home-mismatch rule stays quiet).
func newDocCLI(t *testing.T, mainBody, managedBody string) *cliEnv {
	t.Helper()
	e := newCLIEnv(t, mainBody, managedBody)
	home := t.TempDir()
	t.Cleanup(config.SetHomeDirForTest(home))
	t.Setenv("HOME", home)
	e.write(t, filepath.Join(e.dir, "keys", "ok"), dcKey)
	return e
}

func dcRun(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return runCLI(t, append([]string{"doctor"}, args...)...)
}

// dcSummaries returns the summary lines of the combined output.
func dcSummaries(s string) []string {
	re := regexp.MustCompile(dcSumRe)
	var out []string
	for _, l := range cliLines(s) {
		if re.MatchString(l) {
			out = append(out, l)
		}
	}
	return out
}

// dcCapture runs fn with os.Stdout / os.Stderr redirected.
func dcCapture(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	re, we, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wo, we
	outc, errc := make(chan string, 1), make(chan string, 1)
	go func() { b, _ := io.ReadAll(ro); outc <- string(b) }()
	go func() { b, _ := io.ReadAll(re); errc <- string(b) }()
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	fn()
	wo.Close()
	we.Close()
	return <-outc, <-errc
}

// ---- D3: no issues ---------------------------------------------------------------------------

func TestDoctorCLI_D3_NoIssues(t *testing.T) {
	cliNeedSSH(t)
	newDocCLI(t, "Include @M@\n\n"+dcWeb1+"\n"+dcStar, cliManagedHeader)
	for _, args := range [][]string{{}, {"--strict"}, {"--skip-files"}, {"--strict", "--skip-files"}} {
		stdout, stderr, err := dcRun(t, args...)
		if err != nil {
			t.Errorf("doctor %v: unexpected error %v\nstderr:\n%s", args, err, stderr)
		}
		if stdout != dcNoIssu+"\n" {
			t.Errorf("doctor %v: stdout = %q, want %q", args, stdout, dcNoIssu+"\n")
		}
		if stderr != "" {
			t.Errorf("doctor %v: stderr = %q, want nothing", args, stderr)
		}
	}
}

// ---- D3: info only: lines, no summary, exit 0 ---------------------------------------------------

func TestDoctorCLI_D3_InfoOnlyPrintsNoSummaryAndNeverFails(t *testing.T) {
	cliNeedSSH(t)
	newDocCLI(t, dcWeb1+"\n"+dcStar, cliManagedHeader)
	for _, args := range [][]string{{}, {"--strict"}} {
		stdout, stderr, err := dcRun(t, args...)
		if err != nil {
			t.Errorf("doctor %v: info findings must not fail, got %v", args, err)
		}
		if stdout != "" {
			t.Errorf("doctor %v: stdout = %q; %q is only for the no-finding case", args, stdout, dcNoIssu)
		}
		lines := cliLines(stderr)
		if len(lines) != 1 || !strings.HasPrefix(lines[0], dcNoSet) {
			t.Errorf("doctor %v: stderr lines = %q, want exactly the not-set-up info line %q", args, lines, dcNoSet)
		}
		if len(dcSummaries(stderr)) != 0 || strings.Contains(stderr, "error(s)") {
			t.Errorf("doctor %v: a summary line must not be printed when only info findings exist:\n%s", args, stderr)
		}
	}
}

// ---- D3, D4, D5: output format, summary, exit status ---------------------------------------------

func TestDoctorCLI_D3_ErrorsAndWarningsOutput(t *testing.T) {
	main := "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @D@/keys/gone\n\nHost web-2\n  HostName 10.0.0.2\n  StrictHostKeyChecking no\n"
	e := newDocCLI(t, main, cliAbsent)
	body := cliRead(t, e.main)
	l1, l2 := cliLineOf(t, body, "Host web-1"), cliLineOf(t, body, "Host web-2")

	vout, verr, err := runCLI(t, "validate")
	if err != nil {
		t.Fatal(err)
	}
	vlines := cliLines(verr)
	if len(vlines) != 2 || vout != "" {
		t.Fatalf("fixture error: validate printed %q / %q", vout, verr)
	}

	stdout, stderr, derr := dcRun(t)
	if derr == nil {
		t.Fatalf("want a non-nil error (exit 1) for 1 error, 2 warnings; stderr:\n%s", stderr)
	}
	const summary = "1 error(s), 2 warning(s) found."
	if derr.Error() != summary {
		t.Errorf("error = %q, want the summary line %q", derr, summary)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want nothing (issue lines and the summary go to stderr)", stdout)
	}
	lines := cliLines(stderr)
	if len(lines) == 0 || lines[len(lines)-1] != summary {
		t.Errorf("the last stderr line must be %q, stderr:\n%s", summary, stderr)
	}
	if n := strings.Count(stderr, summary); n != 1 {
		t.Errorf("the summary appears %d times, want exactly once:\n%s", n, stderr)
	}
	if strings.Contains(stderr, "Error:") {
		t.Errorf("cobra must not print the failure again:\n%s", stderr)
	}
	// D2/D5: validate's lines first, unchanged.
	if len(lines) < len(vlines) || strings.Join(lines[:len(vlines)], "\n") != strings.Join(vlines, "\n") {
		t.Errorf("the first lines must be validate's:\nvalidate:\n%s\ndoctor:\n%s", strings.Join(vlines, "\n"), stderr)
	}
	// D3 format of the validate lines and of the doctor-only ones.
	want := []string{
		fmt.Sprintf("warning [missing-identity] web-2: no IdentityFile set (will use ssh-agent or default key) (line %d)", l2),
		fmt.Sprintf("warning [strict-no] web-2: StrictHostKeyChecking no — consider accept-new (line %d)", l2),
	}
	for _, w := range want {
		if !containsLine(lines, w) {
			t.Errorf("missing line %q in:\n%s", w, stderr)
		}
	}
	d7 := regexp.MustCompile(fmt.Sprintf(`^error \[missing-identity-file\] web-1: IdentityFile %s/keys/gone does not exist \((%s )?line %d\)$`,
		regexp.QuoteMeta(e.dir), regexp.QuoteMeta(e.main), l1))
	found := false
	for _, l := range lines {
		if d7.MatchString(l) {
			found = true
		}
	}
	if !found {
		t.Errorf("no D7 line matching %s in:\n%s", d7, stderr)
	}
	// The summary counts errors and warnings, not the info findings.
	hasInfo := false
	for _, l := range lines {
		if strings.HasPrefix(l, dcNoSet) {
			hasInfo = true
		}
	}
	if !hasInfo {
		t.Errorf("expected the not-set-up info line in:\n%s", stderr)
	}
}

func containsLine(lines []string, line string) bool {
	for _, l := range lines {
		if l == line {
			return true
		}
	}
	return false
}

func TestDoctorCLI_D3_IncludedFileLocation(t *testing.T) {
	e := newDocCLI(t, "Include @D@/inc.conf\n\n"+dcWeb1, cliAbsent)
	e.write(t, filepath.Join(e.dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.5\n  IdentityFile @D@/keys/gone\n")
	_, stderr, err := dcRun(t)
	if err == nil {
		t.Fatalf("want an error for the missing key, stderr:\n%s", stderr)
	}
	want := fmt.Sprintf("error [missing-identity-file] inc-1: IdentityFile %s/keys/gone does not exist (%s/inc.conf line 1)", e.dir, e.dir)
	if !containsLine(cliLines(stderr), want) {
		t.Errorf("missing line %q in:\n%s", want, stderr)
	}
}

// D4 + D25: exit status per severity mix, and --strict changes nothing else.
func TestDoctorCLI_D4_D25_ExitStatusAndStrict(t *testing.T) {
	cases := []struct {
		name, main               string
		summary                  string // "" = no summary line expected
		failsNormal, failsStrict bool
	}{
		{
			name:        "errors only",
			main:        "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @D@/keys/gone\n",
			summary:     "1 error(s), 0 warning(s) found.",
			failsNormal: true, failsStrict: true,
		},
		{
			name:        "errors and warnings",
			main:        "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @D@/keys/gone\n\nHost web-2\n  HostName 10.0.0.2\n  StrictHostKeyChecking no\n",
			summary:     "1 error(s), 2 warning(s) found.",
			failsNormal: true, failsStrict: true,
		},
		{
			name:        "warnings only",
			main:        dcWeb1 + "\nHost web-2\n  HostName 10.0.0.2\n  StrictHostKeyChecking no\n",
			summary:     "0 error(s), 2 warning(s) found.",
			failsNormal: false, failsStrict: true,
		},
		{
			name:        "one warning",
			main:        dcWeb1 + "  StrictHostKeyChecking no\n",
			summary:     "0 error(s), 1 warning(s) found.",
			failsNormal: false, failsStrict: true,
		},
		{
			name:        "info only",
			main:        dcWeb1,
			summary:     "",
			failsNormal: false, failsStrict: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newDocCLI(t, c.main, cliAbsent)
			outN, errN, errNormal := dcRun(t)
			outS, errS, errStrict := dcRun(t, "--strict")

			if (errNormal != nil) != c.failsNormal {
				t.Errorf("without --strict: error = %v, want failure=%v\nstderr:\n%s", errNormal, c.failsNormal, errN)
			}
			if (errStrict != nil) != c.failsStrict {
				t.Errorf("with --strict: error = %v, want failure=%v\nstderr:\n%s", errStrict, c.failsStrict, errS)
			}
			// D25: identical output either way.
			if outN != outS || errN != errS {
				t.Errorf("--strict changed the output.\nwithout: %q / %q\nwith:    %q / %q", outN, errN, outS, errS)
			}
			if outN != "" {
				t.Errorf("stdout = %q, want empty when there are findings", outN)
			}
			sums := dcSummaries(errN)
			if c.summary == "" {
				if len(sums) != 0 || strings.Contains(errN, "error(s)") {
					t.Errorf("no summary expected, stderr:\n%s", errN)
				}
				return
			}
			if len(sums) != 1 || sums[0] != c.summary || strings.Count(errN, "error(s)") != 1 {
				t.Errorf("summaries = %q, want exactly %q; stderr:\n%s", sums, c.summary, errN)
			}
			for _, e := range []error{errNormal, errStrict} {
				if e != nil && e.Error() != c.summary {
					t.Errorf("error = %q, want the summary line %q", e, c.summary)
				}
			}
			if lines := cliLines(errN); len(lines) == 0 || lines[len(lines)-1] != c.summary {
				t.Errorf("the summary must be the last stderr line:\n%s", errN)
			}
		})
	}
}

// ---- D6, 5.1: failure of Doctor itself ------------------------------------------------------------

func TestDoctorCLI_D6_MissingConfigPrintsErrorOnce(t *testing.T) {
	e := newDocCLI(t, cliAbsent, cliAbsent)
	if _, err := os.Stat(e.main); err == nil {
		t.Fatal("fixture error: main file exists")
	}
	_, _, verr := runCLI(t, "validate")
	if verr == nil {
		t.Fatal("fixture error: validate succeeded on a missing config")
	}
	before := cliSnap(t, e.dir)
	for _, args := range [][]string{{}, {"--strict"}, {"--skip-files"}} {
		stdout, stderr, err := dcRun(t, args...)
		if err == nil {
			t.Fatalf("doctor %v: want validate's error for a missing config, got success (stdout %q)", args, stdout)
		}
		if err.Error() != verr.Error() {
			t.Errorf("doctor %v: error = %q, want validate's %q", args, err, verr)
		}
		if n := strings.Count(stderr, "Error: "+err.Error()); n != 1 {
			t.Errorf("doctor %v: 'Error: %s' appears %d times in stderr, want once:\n%s", args, err, n, stderr)
		}
		if strings.Count(stderr, "Error:") != 1 {
			t.Errorf("doctor %v: stderr has more than the single Error line:\n%s", args, stderr)
		}
		if stdout != "" || strings.Contains(stderr, "error(s)") || strings.Contains(stderr, dcNoIssu) {
			t.Errorf("doctor %v: no summary and no 'No issues found.' on failure; stdout %q stderr:\n%s", args, stdout, stderr)
		}
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
}

// ---- D24 at the CLI -------------------------------------------------------------------------------

func TestDoctorCLI_D24_SkipFilesDropsOnlyTheFileChecks(t *testing.T) {
	newDocCLI(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @D@/keys/gone\n", cliAbsent)
	_, full, errFull := dcRun(t)
	_, skip, errSkip := dcRun(t, "--skip-files")
	if errFull == nil || errFull.Error() != "1 error(s), 0 warning(s) found." {
		t.Fatalf("full run: error = %v, want the 1 error summary; stderr:\n%s", errFull, full)
	}
	if errSkip != nil {
		t.Errorf("--skip-files: only info findings remain, want success, got %v\nstderr:\n%s", errSkip, skip)
	}
	var want []string
	for _, l := range cliLines(full) {
		if strings.Contains(l, "[missing-identity-file]") || l == errFull.Error() {
			continue
		}
		want = append(want, l)
	}
	if got := cliLines(skip); strings.Join(got, "\n") != strings.Join(want, "\n") || len(got) == 0 {
		t.Errorf("--skip-files output must be the full output minus the file-check line and the summary.\nwant:\n%s\ngot:\n%s", strings.Join(want, "\n"), skip)
	}
}

// ---- D1 at the CLI --------------------------------------------------------------------------------

func TestDoctorCLI_D1_ReadOnly(t *testing.T) {
	e := newDocCLI(t, "Include @M@\n\nHost web-1\n  HostName 10.0.0.1\n  IdentityFile @D@/keys/gone\n  IdentityFile @D@/keys/ok\n", cliManagedHeader+"Host m-1\n  HostName 10.0.0.9\n")
	e.write(t, e.main+".sshm-groups", "# state\ngrp\n")
	before := cliSnap(t, e.dir)
	for _, args := range [][]string{{}, {"--strict"}, {"--skip-files"}} {
		_, stderr, _ := dcRun(t, args...)
		if len(cliLines(stderr)) == 0 {
			t.Errorf("doctor %v printed nothing: the test would be vacuous", args)
		}
	}
	_, stderr, err := dcRun(t)
	if err == nil || !strings.Contains(stderr, "[missing-identity-file]") {
		t.Errorf("fixture error: want the D7 error, got %v / %q", err, stderr)
	}
	cliRequireUnchanged(t, before, cliSnap(t, e.dir))
	if _, err := os.Stat(filepath.Join(e.dir, "sshm-backups")); err == nil {
		t.Error("doctor created sshm-backups/")
	}
}

// ---- reportDoctor (presentation), PLAN-p5 D3/D4 and 5.1 -------------------------------------------------

func dcIssue(sev domain.Severity, rule, host, msg string, line int) domain.Issue {
	return domain.Issue{Severity: sev, Rule: rule, HostName: host, Message: msg, Line: line}
}

// GREEN against the skeleton.
func TestReportDoctor_NoIssuesPrintsToStdout(t *testing.T) {
	var err error
	stdout, stderr := dcCapture(t, func() { err = reportDoctor(nil, false) })
	if err != nil || stdout != dcNoIssu+"\n" || stderr != "" {
		t.Errorf("err=%v stdout=%q stderr=%q, want nil, %q, empty", err, stdout, stderr, dcNoIssu+"\n")
	}
}

// GREEN against the skeleton.
func TestReportDoctor_SummaryCountsErrorsAndWarningsOnly(t *testing.T) {
	is := []domain.Issue{
		dcIssue(domain.SeverityWarning, "w1", "h", "warn one", 3),
		dcIssue(domain.SeverityInfo, "i1", "", "info one", 0),
		dcIssue(domain.SeverityError, "e1", "h", "error one", 5),
		dcIssue(domain.SeverityWarning, "w2", "", "warn two", 0),
		dcIssue(domain.SeverityInfo, "i2", "h", "info two", 7),
	}
	var err error
	stdout, stderr := dcCapture(t, func() { err = reportDoctor(is, false) })
	const summary = "1 error(s), 2 warning(s) found."
	if err == nil || err.Error() != summary {
		t.Errorf("err = %v, want errors.New(%q)", err, summary)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	want := []string{
		"warning [w1] h: warn one (line 3)",
		"info [i1] info one",
		"error [e1] h: error one (line 5)",
		"warning [w2] warn two",
		"info [i2] h: info two (line 7)",
		summary,
	}
	if got := cliLines(stderr); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("stderr lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// GREEN against the skeleton.
func TestReportDoctor_WarningsFailOnlyWithStrict(t *testing.T) {
	is := []domain.Issue{dcIssue(domain.SeverityWarning, "w1", "h", "warn", 1)}
	var e1, e2 error
	_, s1 := dcCapture(t, func() { e1 = reportDoctor(is, false) })
	_, s2 := dcCapture(t, func() { e2 = reportDoctor(is, true) })
	if e1 != nil {
		t.Errorf("warnings without --strict: err = %v, want nil", e1)
	}
	if e2 == nil || e2.Error() != "0 error(s), 1 warning(s) found." {
		t.Errorf("warnings with --strict: err = %v, want the summary", e2)
	}
	if s1 != s2 || !strings.HasSuffix(s1, "0 error(s), 1 warning(s) found.\n") {
		t.Errorf("output differs or lacks the summary:\n%q\n%q", s1, s2)
	}
}

// RED against the skeleton: it prints "0 error(s), 0 warning(s) found." (5.1).
func TestReportDoctor_InfoOnlyHasNoSummaryAndNeverFails(t *testing.T) {
	is := []domain.Issue{
		dcIssue(domain.SeverityInfo, "not-set-up", "", "sshm-managed file is not included; run 'sshm setup'", 0),
		dcIssue(domain.SeverityInfo, "hardening-hashknownhosts", "", "hash", 0),
	}
	for _, strict := range []bool{false, true} {
		var err error
		stdout, stderr := dcCapture(t, func() { err = reportDoctor(is, strict) })
		if err != nil {
			t.Errorf("strict=%v: err = %v, want nil", strict, err)
		}
		if stdout != "" {
			t.Errorf("strict=%v: stdout = %q, want empty", strict, stdout)
		}
		want := "info [not-set-up] sshm-managed file is not included; run 'sshm setup'\ninfo [hardening-hashknownhosts] hash\n"
		if stderr != want {
			t.Errorf("strict=%v: stderr = %q, want %q (issue lines only, no summary)", strict, stderr, want)
		}
	}
}

// GREEN against the skeleton.
func TestReportDoctor_ErrorsFailWithAndWithoutStrict(t *testing.T) {
	is := []domain.Issue{dcIssue(domain.SeverityError, "e", "h", "boom", 2)}
	for _, strict := range []bool{false, true} {
		var err error
		_, stderr := dcCapture(t, func() { err = reportDoctor(is, strict) })
		if err == nil || err.Error() != "1 error(s), 0 warning(s) found." {
			t.Errorf("strict=%v: err = %v", strict, err)
		}
		if strings.Count(stderr, "1 error(s), 0 warning(s) found.") != 1 {
			t.Errorf("strict=%v: the summary must be printed exactly once:\n%s", strict, stderr)
		}
	}
}
