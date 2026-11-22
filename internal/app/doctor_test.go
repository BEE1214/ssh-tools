package app

// Black-box tests for `sshm doctor` (PLAN-p5.md): output/ordering (D1, D2, D5,
// D6) and the file checks (D7-D13). The include and ssh checks (D14-D24) are in
// doctor_ssh_test.go. Every test starts with e.run, which fails on any error, so
// against the skeleton (ErrNotImplemented) all of them are red.
//
// Not parallel: they set $HOME and the passwd-home override.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// drDoctorRules are the rule names of the doctor-only findings.
var drDoctorRules = []string{
	RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions, RuleManagedPermissions,
	RuleCertExpired, RuleNotSetUp, RuleIncludeConditional, RuleHomeMismatch, RuleSSHMissing,
	RuleVerifySkipped, RuleSSHRejectsConfig, RuleHardeningHashKnownHosts,
	RuleHardeningIdentitiesOnly, RuleAgentForwardingDefault,
}

// drFileRules are the rules of D7-D13 (what --skip-files must drop).
var drFileRules = []string{
	RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions, RuleManagedPermissions, RuleCertExpired,
}

// drNames reports whether msg names the file path as a whole path (so
// <dir>/config does not match <dir>/config.d/sshm.conf).
func drNames(msg, path string) bool {
	return regexp.MustCompile(regexp.QuoteMeta(path) + `($|[^\w./-])`).MatchString(msg)
}

// drRequireOrder: the first finding of each rule exists and they appear in the
// given order.
func drRequireOrder(t *testing.T, is []domain.Issue, rules ...string) {
	t.Helper()
	last := -1
	for _, r := range rules {
		idx := -1
		for i, x := range is {
			if x.Rule == r {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Errorf("no %q finding; all findings:\n%s", r, drDump(is))
			return
		}
		if idx <= last {
			t.Errorf("%q is out of order (want %v in this order); all findings:\n%s", r, rules, drDump(is))
			return
		}
		last = idx
	}
}

// ---- D1: never modifies anything ---------------------------------------------------------

// drRich builds a config with findings of every file/include kind: loose and
// missing keys, an expired certificate (when ssh-keygen exists), a group-writable
// main file, a group-readable managed file, a conditional Include, a Match exec
// in an included file, and sidecar files next to the main and the managed file.
func drRich(t *testing.T, extraMain string) *drEnv {
	t.Helper()
	cert := ""
	e := newDrEnv(t, mgAbsent, mgAbsent)
	if drKeygen != "" {
		cert = "  CertificateFile " + drCert(t, e.keys, "c", "20200101:20200102") + "\n"
	}
	e.setMain(t, "Include @M@\n\n"+
		"Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/loose\n  IdentityFile @K@/gone\n  CertificateFile @K@/gone-cert.pub\n"+cert+"\n"+
		"Host web-2\n  HostName 10.0.0.2\n  IdentityFile @K@/ok\n  StrictHostKeyChecking no\n\n"+
		"Host db-1\n  HostName 10.0.0.4\n  IdentityFile @K@/ok\n  Include @D@/extra.conf\n\n"+extraMain)
	e.file(t, e.managed, mgManagedHeader+"Host m-1\n  HostName 10.0.0.9\n  IdentityFile @K@/ok\n", 0o644)
	e.file(t, filepath.Join(e.dir, "extra.conf"), "Match exec \"touch @D@/exec-ran\"\n  Compression no\n", 0o600)
	e.file(t, mgSidecar(e.main), "# state\ngrp-a\n", 0o600)
	e.file(t, mgSidecar(e.managed), "# state\ngrp-b\n", 0o600)
	e.key(t, "loose", 0o644)
	e.key(t, "ok", 0o600)
	if err := os.Chmod(e.main, 0o664); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestDoctor_D1_NeverModifiesAnything(t *testing.T) {
	cases := []struct {
		name      string
		extraMain string
		skipFiles bool
		noSSH     bool
	}{
		{name: "default"},
		{name: "skip-files", skipFiles: true},
		{name: "ssh rejects the config", extraMain: "Host *\n  BogusOption yes\n"},
		{name: "ssh not in PATH", noSSH: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drRich(t, c.extraMain)
			if c.noSSH {
				mgNoSSHOnPath(t)
			}
			before := drSnap(t, e.dir, e.home)
			is := e.run(t, c.skipFiles)
			drRequireUnchanged(t, before, drSnap(t, e.dir, e.home))
			if len(is) == 0 {
				t.Error("the fixture produced no findings: the test would be vacuous")
			}
			if mgExists(filepath.Join(e.dir, "sshm-backups")) {
				t.Error("doctor created sshm-backups/")
			}
			if mgExists(filepath.Join(e.dir, "exec-ran")) {
				t.Error("doctor ran the Match exec command")
			}
		})
	}
}

// ---- D2, D5: validate's issues first, unchanged; deterministic order ---------------------

func TestDoctor_D2_ValidateIssuesAreFirstAndUnchanged(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/gone\n  StrictHostKeyChecking no\n  LocalForward bad\n\n"+
		"Host web-1\n  HostName 10.0.0.2\n\n"+
		"Host web-3\n  HostName 10.0.0.3\n  LocalForward 8080 localhost:80\n\n"+
		"Host web-4\n  HostName 10.0.0.4\n  LocalForward 8080 localhost:81\n\n"+
		"Include @D@/extra.conf\n", mgAbsent)
	e.file(t, filepath.Join(e.dir, "extra.conf"), "Host web-3\n  HostName 10.0.0.5\n  IdentityFile @K@/gone\n", 0o600)
	v, err := e.a.Validate()
	mgRequireNoErr(t, err)
	rules := map[string]bool{}
	for _, i := range v {
		rules[i.Rule] = true
	}
	for _, r := range []string{"duplicate-host", "strict-no", "missing-identity", "dup-host-cross-file", "duplicate-listen-port"} {
		if !rules[r] {
			t.Fatalf("fixture error: Validate() has no %q issue:\n%s", r, drDump(v))
		}
	}
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip-files=%v", skip), func(t *testing.T) {
			is := e.run(t, skip)
			if len(is) < len(v) || !reflect.DeepEqual(is[:len(v)], v) {
				t.Errorf("the first %d findings must be Validate()'s, unchanged and in order.\nvalidate:\n%s\ndoctor:\n%s", len(v), drDump(v), drDump(is))
				return
			}
			for _, x := range is[len(v):] {
				if !drIn(drDoctorRules, x.Rule) {
					t.Errorf("after validate's issues only doctor-only rules may follow, got %s", drFmt(x))
				}
			}
		})
	}
}

func drIn(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// D5 on one fixture that has a finding of (almost) every clause: validate first,
// then D7, D8, D9, D10, D11, D15, D16, D17, D21, D22, D23 in table order, even
// where a later clause sits on an earlier line (the D16 Include precedes the D15 one).
func TestDoctor_D5_OrderIsTableOrderThenFileThenLine(t *testing.T) {
	mgNeedSSH(t)
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/gone-a\n  IdentityFile @K@/loose-a\n\n"+
		"Host web-2\n  HostName 10.0.0.2\n  IdentityFile @K@/gone-b\n  CertificateFile @K@/gone-cert-a.pub\n  StrictHostKeyChecking no\n\n"+
		"Include @D@/extra.conf\n"+
		"Include @M@\n\n"+
		"Host *\n  ForwardAgent yes\n", mgManagedHeader+"Host m-1\n  HostName 10.0.0.9\n  IdentityFile @K@/ok\n")
	e.file(t, e.managed, mgManagedHeader+"Host m-1\n  HostName 10.0.0.9\n  IdentityFile @K@/ok\n", 0o644)
	e.file(t, filepath.Join(e.dir, "extra.conf"), "Host x-1\n  HostName 10.0.0.5\n  IdentityFile @K@/gone-c\n", 0o600)
	e.key(t, "loose-a", 0o644)
	e.key(t, "ok", 0o600)
	if err := os.Chmod(e.main, 0o664); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir()) // differs from the passwd home: D17

	v, err := e.a.Validate()
	mgRequireNoErr(t, err)
	if len(v) == 0 {
		t.Fatal("fixture error: Validate() returned nothing")
	}
	first := e.run(t, false)
	for n := 0; n < 3; n++ {
		if again := e.run(t, false); !reflect.DeepEqual(first, again) {
			t.Fatalf("Doctor is not deterministic:\nfirst:\n%s\nagain:\n%s", drDump(first), drDump(again))
		}
	}
	if len(first) < len(v) || !reflect.DeepEqual(first[:len(v)], v) {
		t.Fatalf("validate's issues must come first.\nvalidate:\n%s\ndoctor:\n%s", drDump(v), drDump(first))
	}
	tail := first[len(v):]
	want := []string{
		RuleMissingIdentityFile, RuleMissingIdentityFile, RuleMissingIdentityFile,
		RuleMissingCertFile,
		RuleUnsafePermissions, RuleUnsafePermissions,
		RuleManagedPermissions,
		RuleIncludeConditional, RuleIncludeConditional,
		RuleHomeMismatch,
		RuleHardeningHashKnownHosts, RuleHardeningIdentitiesOnly, RuleAgentForwardingDefault,
	}
	if got := drRuleNames(tail); !reflect.DeepEqual(got, want) {
		t.Fatalf("doctor-only findings in this order:\n  %v\nwant\n  %v\nall findings:\n%s", got, want, drDump(first))
	}
	// D7: main file blocks by line, then the included file.
	for i, key := range []string{"gone-a", "gone-b", "gone-c"} {
		if !strings.Contains(tail[i].Message, "/keys/"+key) {
			t.Errorf("D7 finding %d = %s, want the one for %s", i, drFmt(tail[i]), key)
		}
	}
	// D9 (the key) before D10 (the config file).
	if !strings.Contains(tail[4].Message, "loose-a") || !drNames(tail[5].Message, e.main) {
		t.Errorf("unsafe-permissions order: want the key (D9) then the main file (D10), got\n  %s\n  %s", drFmt(tail[4]), drFmt(tail[5]))
	}
	// D15 (the managed Include, on the later line) before D16 (extra.conf, on the earlier line).
	body := mgRead(t, e.main)
	lm := drLineHas(t, body, "Include "+e.managed)
	if lx := drLineHas(t, body, "Include "+e.dir+"/extra.conf"); lx >= lm {
		t.Fatalf("fixture error: extra.conf Include (line %d) must precede the managed Include (line %d)", lx, lm)
	}
	if !strings.Contains(tail[7].Message, fmt.Sprintf("%s line %d", e.main, lm)) || !strings.Contains(tail[8].Message, "read only for matching hosts") {
		t.Errorf("include-conditional order: want D15 (%s line %d) then D16, got\n  %s\n  %s", e.main, lm, drFmt(tail[7]), drFmt(tail[8]))
	}
}

// Within one clause the order is file evaluation order (main, then the included
// files), not alphabetical or map order.
func TestDoctor_D5_SameClauseFollowsFileEvaluationOrder(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n\n"+
		"Include @D@/zz.conf\nInclude @D@/aa.conf\n", mgAbsent)
	e.key(t, "ok", 0o600)
	e.file(t, filepath.Join(e.dir, "zz.conf"), "Host z-1\n  HostName 10.0.0.2\n  IdentityFile @K@/ok\n", 0o666)
	e.file(t, filepath.Join(e.dir, "aa.conf"), "Host a-1\n  HostName 10.0.0.3\n  IdentityFile @K@/ok\n", 0o666)
	for _, p := range []string{e.main, filepath.Join(e.dir, "zz.conf"), filepath.Join(e.dir, "aa.conf")} {
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	is := drRule(e.run(t, false), RuleUnsafePermissions)
	if len(is) != 3 {
		t.Fatalf("want 3 unsafe-permissions findings (main, zz.conf, aa.conf), got:\n%s", drDump(is))
	}
	for i, p := range []string{e.main, filepath.Join(e.dir, "zz.conf"), filepath.Join(e.dir, "aa.conf")} {
		if !drNames(is[i].Message, p) {
			t.Errorf("finding %d = %s, want it to name %s (main, then include order)", i, drFmt(is[i]), p)
		}
	}
}

// ---- D6: missing main file --------------------------------------------------------------

func TestDoctor_D6_MissingMainFileIsValidatesError(t *testing.T) {
	for _, c := range []struct {
		name    string
		managed bool
		mkdir   bool
	}{
		{name: "no main file"},
		{name: "no main file, managed file present", managed: true},
		{name: "main path is a directory", mkdir: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			managed := mgAbsent
			if c.managed {
				managed = mgManagedHeader + "Host m-1\n  HostName 10.0.0.9\n"
			}
			e := newDrEnv(t, mgAbsent, managed)
			if c.mkdir {
				if err := os.MkdirAll(e.main, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			_, verr := e.a.Validate()
			if verr == nil {
				t.Fatal("fixture error: Validate() succeeded")
			}
			before := drSnap(t, e.dir, e.home)
			for _, skip := range []bool{false, true} {
				is, derr := e.a.Doctor(DoctorOptions{SkipFiles: skip})
				if derr == nil {
					t.Fatalf("Doctor succeeded (%d findings), want validate's error %q", len(is), verr)
				}
				if errors.Is(derr, ErrNotImplemented) {
					t.Fatalf("got the skeleton's ErrNotImplemented, want validate's error %q", verr)
				}
				if derr.Error() != verr.Error() {
					t.Errorf("Doctor error = %q, want validate's %q", derr, verr)
				}
				if len(is) != 0 {
					t.Errorf("no extra findings expected with the error, got:\n%s", drDump(is))
				}
			}
			drRequireUnchanged(t, before, drSnap(t, e.dir, e.home))
		})
	}
}

// ---- D7: missing IdentityFile -------------------------------------------------------------

func drSig(is []domain.Issue) []string {
	out := make([]string, len(is))
	for i, x := range is {
		out[i] = fmt.Sprintf("%s|%d|%s", x.HostName, x.Line, x.Message)
	}
	sort.Strings(out)
	return out
}

func TestDoctor_D7_MissingIdentityFile(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/web-1-missing\n  IdentityFile @K@/web-1-present\n  IdentityFile @K@/web-1-missing2\n\n"+
		"Host web-2\n  HostName 10.0.0.2\n  IdentityFile @K@/web-1-missing\n  IdentityFile @K@/web-1-missing\n\n"+
		"Host *\n  IdentityFile @K@/star-missing\n", mgAbsent)
	e.key(t, "web-1-present", 0o600)
	body := mgRead(t, e.main)
	l1, l2, l3 := drLineHas(t, body, "Host web-1"), drLineHas(t, body, "Host web-2"), drLineHas(t, body, "Host *")
	got := drWantN(t, e.run(t, false), RuleMissingIdentityFile, 4)
	for _, x := range got {
		if x.Severity != domain.SeverityError {
			t.Errorf("severity = %v, want error: %s", x.Severity, drFmt(x))
		}
		if !e.fileOK(x.File, e.main) {
			t.Errorf("File = %q, want the main file: %s", x.File, drFmt(x))
		}
	}
	want := []string{
		fmt.Sprintf("web-1|%d|IdentityFile %s/web-1-missing does not exist", l1, e.keys),
		fmt.Sprintf("web-1|%d|IdentityFile %s/web-1-missing2 does not exist", l1, e.keys),
		fmt.Sprintf("web-2|%d|IdentityFile %s/web-1-missing does not exist", l2, e.keys),
		fmt.Sprintf("*|%d|IdentityFile %s/star-missing does not exist", l3, e.keys),
	}
	sort.Strings(want)
	if g := drSig(got); !reflect.DeepEqual(g, want) {
		t.Errorf("findings (host|line|message):\n  %s\nwant\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestDoctor_D7_FileAndLineOfIncludedAndManagedFiles(t *testing.T) {
	e := newDrEnv(t, "Include @M@\nInclude @D@/inc.conf\n\nHost web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n",
		mgManagedHeader+"\nHost m-1\n  HostName 10.0.0.9\n  IdentityFile @K@/m-missing\n")
	e.file(t, filepath.Join(e.dir, "inc.conf"), "# c\nHost inc-1\n  HostName 10.0.0.5\n  IdentityFile @K@/inc-missing\n", 0o600)
	e.key(t, "ok", 0o600)
	inc := filepath.Join(e.dir, "inc.conf")
	got := drWantN(t, e.run(t, false), RuleMissingIdentityFile, 2)
	if len(got) != 2 {
		return
	}
	byHost := map[string]domain.Issue{got[0].HostName: got[0], got[1].HostName: got[1]}
	if x := byHost["inc-1"]; x.File != inc || x.Line != 2 {
		t.Errorf("inc-1: File=%q Line=%d, want %s line 2", x.File, x.Line, inc)
	}
	if x := byHost["m-1"]; x.File != e.managed || x.Line != drLineHas(t, mgRead(t, e.managed), "Host m-1") {
		t.Errorf("m-1: File=%q Line=%d, want %s line %d", x.File, x.Line, e.managed, drLineHas(t, mgRead(t, e.managed), "Host m-1"))
	}
}

// Values that ssh expands at connect time or resolves against the cwd are not
// checked, even when the file they would name does not exist.
func TestDoctor_D7_UncheckedValues(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n"+
		"  IdentityFile none\n"+
		"  IdentityFile %d/id_missing\n"+
		"  IdentityFile @K@/id_%h\n"+
		"  IdentityFile $DR_UNSET/id_missing\n"+
		"  IdentityFile @K@/$DR_UNSET_KEY\n"+
		"  IdentityFile relative-missing\n"+
		"  IdentityFile ./relative-missing\n"+
		"  IdentityFile relative-loose\n"+
		"  IdentityFile @K@/really-missing\n"+
		"  CertificateFile none\n"+
		"  CertificateFile %d/cert-missing.pub\n"+
		"  CertificateFile $DR_UNSET/cert-missing.pub\n"+
		"  CertificateFile relative-cert-missing.pub\n", mgAbsent)
	if err := os.MkdirAll(e.keys, 0o700); err != nil {
		t.Fatal(err)
	}
	e.file(t, filepath.Join(e.keys, "relative-loose"), drKeyBody, 0o644)
	t.Chdir(e.keys)
	is := e.run(t, false)
	got := drWantN(t, is, RuleMissingIdentityFile, 1)
	if len(got) == 1 && got[0].Message != "IdentityFile "+e.keys+"/really-missing does not exist" {
		t.Errorf("message = %q, want the one for really-missing", got[0].Message)
	}
	drNoRule(t, is, RuleMissingCertFile, RuleUnsafePermissions)
}

// "~" is the passwd home (the config package's home), never $HOME.
func TestDoctor_D7_TildeUsesPasswdHomeNotEnv(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n"+
		"  IdentityFile ~/.ssh/dr_missing\n"+
		"  IdentityFile ~/.ssh/dr_present\n"+
		"  IdentityFile ~/.ssh/dr_only_in_env_home\n"+
		"  IdentityFile ~/.ssh/dr_loose\n"+
		"  CertificateFile ~/.ssh/dr_cert_missing.pub\n", mgAbsent)
	mgWrite(t, filepath.Join(e.home, ".ssh", "dr_present"), drKeyBody, 0o600)
	mgWrite(t, filepath.Join(e.home, ".ssh", "dr_loose"), drKeyBody, 0o644)
	other := t.TempDir()
	mgWrite(t, filepath.Join(other, ".ssh", "dr_only_in_env_home"), drKeyBody, 0o600)
	t.Setenv("HOME", other) // ssh ignores it; D17 will warn, which is not under test here
	is := e.run(t, false)
	got := drWantN(t, is, RuleMissingIdentityFile, 2)
	want := []string{"IdentityFile ~/.ssh/dr_missing does not exist", "IdentityFile ~/.ssh/dr_only_in_env_home does not exist"}
	if g := drMsgs(got); !reflect.DeepEqual(g, want) {
		t.Errorf("D7 messages = %q, want %q (path as written; $HOME must be ignored)", g, want)
	}
	if c := drWantN(t, is, RuleMissingCertFile, 1); len(c) == 1 && c[0].Message != "CertificateFile ~/.ssh/dr_cert_missing.pub does not exist" {
		t.Errorf("D8 message = %q", c[0].Message)
	}
	if u := drWantN(t, is, RuleUnsafePermissions, 1); len(u) == 1 && !strings.Contains(u[0].Message, "~/.ssh/dr_loose") {
		t.Errorf("D9 message %q must name the path as written (~/.ssh/dr_loose)", u[0].Message)
	}
}

// ---- D8: missing CertificateFile -----------------------------------------------------------

func TestDoctor_D8_MissingCertificateFile(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n  CertificateFile @K@/c-missing-cert.pub\n  CertificateFile @K@/c-present-cert.pub\n  CertificateFile @K@/c-missing2-cert.pub\n\n"+
		"Host web-2\n  HostName 10.0.0.2\n  IdentityFile @K@/ok\n  CertificateFile @K@/c-missing-cert.pub\n  CertificateFile @K@/c-missing-cert.pub\n\n"+
		"Host web-3\n  HostName 10.0.0.3\n  IdentityFile @K@/ok\n  CertificateFile @K@/c-present-cert.pub\n\n"+
		"Host *\n  CertificateFile @K@/c-star-cert.pub\n", mgAbsent)
	e.key(t, "ok", 0o600)
	e.file(t, filepath.Join(e.keys, "c-present-cert.pub"), "placeholder\n", 0o644)
	body := mgRead(t, e.main)
	l1, l2, l4 := drLineHas(t, body, "Host web-1"), drLineHas(t, body, "Host web-2"), drLineHas(t, body, "Host *")
	is := e.run(t, false)
	got := drWantN(t, is, RuleMissingCertFile, 4)
	for _, x := range got {
		if x.Severity != domain.SeverityWarning {
			t.Errorf("severity = %v, want warning: %s", x.Severity, drFmt(x))
		}
		if !e.fileOK(x.File, e.main) {
			t.Errorf("File = %q, want the main file: %s", x.File, drFmt(x))
		}
	}
	want := []string{
		fmt.Sprintf("web-1|%d|CertificateFile %s/c-missing-cert.pub does not exist", l1, e.keys),
		fmt.Sprintf("web-1|%d|CertificateFile %s/c-missing2-cert.pub does not exist", l1, e.keys),
		fmt.Sprintf("web-2|%d|CertificateFile %s/c-missing-cert.pub does not exist", l2, e.keys),
		fmt.Sprintf("*|%d|CertificateFile %s/c-star-cert.pub does not exist", l4, e.keys),
	}
	sort.Strings(want)
	if g := drSig(got); !reflect.DeepEqual(g, want) {
		t.Errorf("findings (host|line|message):\n  %s\nwant\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
	drNoRule(t, is, RuleMissingIdentityFile, RuleUnsafePermissions, RuleCertExpired)
}

// ---- D9: unsafe private key permissions ---------------------------------------------------

func TestDoctor_D9_KeyPermissions(t *testing.T) {
	cases := []struct {
		file string
		mode os.FileMode
		fire bool
	}{
		{"k0644", 0o644, true}, {"k0640", 0o640, true}, {"k0604", 0o604, true},
		{"k0660", 0o660, true}, {"k0666", 0o666, true}, {"k0755", 0o755, true}, {"k0707", 0o707, true},
		{"k0600", 0o600, false}, {"k0400", 0o400, false}, {"k0700", 0o700, false},
		{"loose.pub", 0o644, false}, // a public key may be world readable
	}
	var b strings.Builder
	e := newDrEnv(t, mgAbsent, mgAbsent)
	for _, c := range cases {
		e.key(t, c.file, c.mode)
		fmt.Fprintf(&b, "Host h-%s\n  HostName 10.0.0.1\n  IdentityFile @K@/%s\n\n", strings.ReplaceAll(c.file, ".", "-"), c.file)
	}
	// A loose private key in the wildcard block, and a missing one (D7 only).
	e.key(t, "star0644", 0o644)
	b.WriteString("Host *\n  IdentityFile @K@/star0644\n  IdentityFile @K@/never-created\n")
	e.setMain(t, b.String())

	is := e.run(t, false)
	unsafe := drRule(is, RuleUnsafePermissions)
	nFire := 1 // star0644
	for _, c := range cases {
		path := filepath.Join(e.keys, c.file)
		var hits []domain.Issue
		for _, x := range unsafe {
			if drNames(x.Message, path) {
				hits = append(hits, x)
			}
		}
		if !c.fire {
			if len(hits) != 0 {
				t.Errorf("%s (mode %04o): want no unsafe-permissions finding, got:\n%s", c.file, c.mode, drDump(hits))
			}
			continue
		}
		nFire++
		if len(hits) != 1 {
			t.Errorf("%s (mode %04o): want exactly 1 unsafe-permissions finding, got:\n%s", c.file, c.mode, drDump(hits))
			continue
		}
		x := hits[0]
		if x.Severity != domain.SeverityError {
			t.Errorf("%s: severity = %v, want error", c.file, x.Severity)
		}
		if !strings.Contains(x.Message, fmt.Sprintf("%o", c.mode)) || !strings.Contains(x.Message, "chmod 600") {
			t.Errorf("%s: message %q must name the octal mode %o and 'chmod 600'", c.file, x.Message, c.mode)
		}
		if want := "h-" + strings.ReplaceAll(c.file, ".", "-"); x.HostName != want {
			t.Errorf("%s: HostName = %q, want %q", c.file, x.HostName, want)
		}
	}
	if len(unsafe) != nFire {
		t.Errorf("want %d unsafe-permissions findings in total, got %d:\n%s", nFire, len(unsafe), drDump(unsafe))
	}
	for _, x := range unsafe {
		if x.HostName == "*" && !drNames(x.Message, filepath.Join(e.keys, "star0644")) {
			t.Errorf("wildcard finding names the wrong key: %s", drFmt(x))
		}
	}
	// The key that does not exist is a D7 matter only.
	if m := drWantN(t, is, RuleMissingIdentityFile, 1); len(m) == 1 && !strings.Contains(m[0].Message, "never-created") {
		t.Errorf("D7 finding = %s, want never-created", drFmt(m[0]))
	}
}

// Only IdentityFile values are keys: loose CertificateFile permissions are fine,
// and values ssh expands or resolves relative to the cwd are never inspected.
func TestDoctor_D9_OnlyCheckedIdentityValues(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile relative-loose\n  IdentityFile @K@/id_%h\n  CertificateFile @K@/loose-cert.pub\n", mgAbsent)
	e.file(t, filepath.Join(e.keys, "relative-loose"), drKeyBody, 0o666)
	e.file(t, filepath.Join(e.keys, "id_%h"), drKeyBody, 0o666)
	e.file(t, filepath.Join(e.keys, "loose-cert.pub"), "placeholder\n", 0o666)
	t.Chdir(e.keys)
	drNoRule(t, e.run(t, false), RuleUnsafePermissions, RuleMissingIdentityFile, RuleMissingCertFile)
}

func TestDoctor_D9_KeyInIncludedFileNamesThatFile(t *testing.T) {
	e := newDrEnv(t, "Include @D@/inc.conf\n", mgAbsent)
	e.file(t, filepath.Join(e.dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.5\n  IdentityFile @K@/loose\n", 0o600)
	e.key(t, "loose", 0o640)
	got := drWantN(t, e.run(t, false), RuleUnsafePermissions, 1)
	if len(got) == 1 && (got[0].HostName != "inc-1" || !strings.Contains(got[0].Message, "640")) {
		t.Errorf("got %s, want the inc-1 key at mode 640", drFmt(got[0]))
	}
}

// ---- D10: config files writable by group/other ---------------------------------------------

func TestDoctor_D10_ConfigFileWritableByOthers(t *testing.T) {
	cases := []struct {
		name                string
		main, inc, managed  os.FileMode
		wantUnsafe          []string // "main", "inc", "managed"
		wantManagedReadable bool     // D11
	}{
		{"all 0600", 0o600, 0o600, 0o600, nil, false},
		{"all 0400", 0o400, 0o400, 0o400, nil, false},
		{"readable but not writable: only the managed file is flagged (D11)", 0o644, 0o644, 0o644, nil, true},
		{"main 0664", 0o664, 0o600, 0o600, []string{"main"}, false},
		{"main 0620", 0o620, 0o600, 0o600, []string{"main"}, false},
		{"main 0602", 0o602, 0o600, 0o600, []string{"main"}, false},
		{"include 0666", 0o600, 0o666, 0o600, []string{"inc"}, false},
		{"managed 0664: D10 only, not D11", 0o600, 0o600, 0o664, []string{"managed"}, false},
		{"managed 0666: D10 only, not D11", 0o600, 0o600, 0o666, []string{"managed"}, false},
		{"all three", 0o602, 0o620, 0o662, []string{"main", "inc", "managed"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newDrEnv(t, "Include @M@\nInclude @D@/inc.conf\n\nHost web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n", mgManagedHeader)
			inc := e.file(t, filepath.Join(e.dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.2\n  IdentityFile @K@/ok\n", 0o600)
			e.key(t, "ok", 0o600)
			paths := map[string]string{"main": e.main, "inc": inc, "managed": e.managed}
			modes := map[string]os.FileMode{"main": c.main, "inc": c.inc, "managed": c.managed}
			for k, p := range paths {
				if err := os.Chmod(p, modes[k]); err != nil {
					t.Fatal(err)
				}
			}
			is := e.run(t, false)
			unsafe := drRule(is, RuleUnsafePermissions)
			if len(unsafe) != len(c.wantUnsafe) {
				t.Errorf("want %d unsafe-permissions finding(s) %v, got:\n%s", len(c.wantUnsafe), c.wantUnsafe, drDump(unsafe))
			}
			for _, k := range c.wantUnsafe {
				var hit []domain.Issue
				for _, x := range unsafe {
					if drNames(x.Message, paths[k]) {
						hit = append(hit, x)
					}
				}
				if len(hit) != 1 {
					t.Errorf("%s file (%04o): want exactly one finding naming %s, got:\n%s", k, modes[k], paths[k], drDump(unsafe))
					continue
				}
				if hit[0].Severity != domain.SeverityError {
					t.Errorf("%s: severity = %v, want error", k, hit[0].Severity)
				}
				if !strings.Contains(hit[0].Message, fmt.Sprintf("%o", modes[k])) {
					t.Errorf("%s: message %q must name the octal mode %o", k, hit[0].Message, modes[k])
				}
			}
			n := 0
			if c.wantManagedReadable {
				n = 1
			}
			drWantN(t, is, RuleManagedPermissions, n)
		})
	}
}

func TestDoctor_D10_NestedIncludeIsChecked(t *testing.T) {
	e := newDrEnv(t, "Include @D@/one.conf\n\nHost web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n", mgAbsent)
	e.key(t, "ok", 0o600)
	e.file(t, filepath.Join(e.dir, "one.conf"), "Include @D@/two.conf\n", 0o600)
	two := e.file(t, filepath.Join(e.dir, "two.conf"), "Host two-1\n  HostName 10.0.0.2\n  IdentityFile @K@/ok\n", 0o600)
	if err := os.Chmod(two, 0o662); err != nil {
		t.Fatal(err)
	}
	got := drWantN(t, e.run(t, false), RuleUnsafePermissions, 1)
	if len(got) == 1 && !drNames(got[0].Message, two) {
		t.Errorf("got %s, want it to name %s", drFmt(got[0]), two)
	}
}

// ---- D11: managed file readable by group/other ---------------------------------------------

func TestDoctor_D11_ManagedFileReadableByOthers(t *testing.T) {
	cases := []struct {
		name     string
		mode     os.FileMode
		included bool
		fire     bool
	}{
		{"0600 included", 0o600, true, false},
		{"0400 included", 0o400, true, false},
		{"0644 included", 0o644, true, true},
		{"0640 included", 0o640, true, true},
		{"0604 included", 0o604, true, true},
		{"0644 not included", 0o644, false, true},
		{"0600 not included", 0o600, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			main := "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n"
			if c.included {
				main = "Include @M@\n\n" + main
			}
			e := newDrEnv(t, main, mgManagedHeader+"Host m-1\n  HostName 10.0.0.9\n  IdentityFile @K@/ok\n")
			e.key(t, "ok", 0o600)
			if err := os.Chmod(e.managed, c.mode); err != nil {
				t.Fatal(err)
			}
			is := e.run(t, false)
			drNoRule(t, is, RuleUnsafePermissions)
			if !c.fire {
				drNoRule(t, is, RuleManagedPermissions)
				return
			}
			got := drWantN(t, is, RuleManagedPermissions, 1)
			if len(got) == 1 {
				if got[0].Severity != domain.SeverityWarning {
					t.Errorf("severity = %v, want warning", got[0].Severity)
				}
				if !strings.Contains(got[0].Message, "chmod 600") {
					t.Errorf("message %q must suggest 'chmod 600'", got[0].Message)
				}
			}
		})
	}
}

func TestDoctor_D11_NoManagedFileNoFinding(t *testing.T) {
	e := newDrEnv(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n", mgAbsent)
	e.key(t, "ok", 0o600)
	if err := os.Chmod(e.main, 0o644); err != nil { // the main file may be world readable
		t.Fatal(err)
	}
	drNoRule(t, e.run(t, false), RuleManagedPermissions, RuleUnsafePermissions)
}

// ---- D12: expired certificate ----------------------------------------------------------------

func TestDoctor_D12_ExpiredCertificate(t *testing.T) {
	drNeedKeygen(t)
	e := newDrEnv(t, mgAbsent, mgAbsent)
	expired := drCert(t, e.keys, "expired", "20200101:20200102")
	valid := drCert(t, e.keys, "valid", "+52w")
	forever := drCert(t, e.keys, "forever", "always:forever")
	garbage := e.file(t, filepath.Join(e.keys, "garbage-cert.pub"), "not a certificate\n", 0o644)
	e.setMain(t, "Host h-expired\n  HostName 10.0.0.1\n  CertificateFile "+expired+"\n\n"+
		"Host h-expired-2\n  HostName 10.0.0.2\n  CertificateFile "+expired+"\n  CertificateFile "+expired+"\n\n"+
		"Host h-valid\n  HostName 10.0.0.3\n  CertificateFile "+valid+"\n\n"+
		"Host h-forever\n  HostName 10.0.0.4\n  CertificateFile "+forever+"\n\n"+
		"Host h-garbage\n  HostName 10.0.0.5\n  CertificateFile "+garbage+"\n\n"+
		"Host h-missing\n  HostName 10.0.0.6\n  CertificateFile @K@/missing-cert.pub\n\n"+
		"Host h-none\n  HostName 10.0.0.7\n  CertificateFile none\n  CertificateFile relative-cert.pub\n")
	is := e.run(t, false)
	got := drWantN(t, is, RuleCertExpired, 2)
	var hosts []string
	for _, x := range got {
		hosts = append(hosts, x.HostName)
		if x.Severity != domain.SeverityWarning {
			t.Errorf("severity = %v, want warning: %s", x.Severity, drFmt(x))
		}
	}
	sort.Strings(hosts)
	if want := []string{"h-expired", "h-expired-2"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("cert-expired hosts = %v, want %v (one finding per host block and path)", hosts, want)
	}
	// The missing certificate is D8's, not D12's.
	drWantN(t, is, RuleMissingCertFile, 1)
}

func TestDoctor_D12_NoSSHKeygenMeansNoFinding(t *testing.T) {
	drNeedKeygen(t)
	e := newDrEnv(t, mgAbsent, mgAbsent)
	expired := drCert(t, e.keys, "expired", "20200101:20200102")
	e.setMain(t, "Host h-expired\n  HostName 10.0.0.1\n  CertificateFile "+expired+"\n")
	// Sanity: with ssh-keygen the finding exists.
	drWantN(t, e.run(t, false), RuleCertExpired, 1)
	mgNoSSHOnPath(t)
	drNoRule(t, e.run(t, false), RuleCertExpired) // and Doctor must not fail either
}

// ---- D13: one finding per (host block, path) ------------------------------------------------

func TestDoctor_D13_OneFindingPerBlockAndPath(t *testing.T) {
	e := newDrEnv(t, mgAbsent, mgAbsent)
	rules := []string{RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions}
	certA, certB := "", ""
	if drKeygen != "" { // the cert-expired part needs ssh-keygen
		expired := drCert(t, e.keys, "expired", "20200101:20200102")
		certA = "  CertificateFile " + expired + "\n  CertificateFile " + expired + "\n"
		certB = "  CertificateFile " + expired + "\n"
		rules = append(rules, RuleCertExpired)
	}
	e.key(t, "loose", 0o644)
	e.setMain(t, "Host a\n  HostName 10.0.0.1\n"+
		"  IdentityFile @K@/gone\n  IdentityFile @K@/gone\n  IdentityFile @K@/loose\n  IdentityFile @K@/loose\n"+
		"  CertificateFile @K@/gone-cert.pub\n  CertificateFile @K@/gone-cert.pub\n"+certA+"\n"+
		"Host b\n  HostName 10.0.0.2\n  IdentityFile @K@/gone\n  IdentityFile @K@/loose\n"+
		"  CertificateFile @K@/gone-cert.pub\n"+certB)
	is := e.run(t, false)
	for _, rule := range rules {
		got := drWantN(t, is, rule, 2)
		var hosts []string
		for _, x := range got {
			hosts = append(hosts, x.HostName)
		}
		sort.Strings(hosts)
		if !reflect.DeepEqual(hosts, []string{"a", "b"}) {
			t.Errorf("%s: hosts = %v, want one finding for each of a and b", rule, hosts)
		}
	}
}
