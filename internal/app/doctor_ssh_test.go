package app

// Black-box tests for the include / setup checks (D14-D17), the ssh checks
// (D18-D23) and --skip-files (D24) of `sshm doctor` (PLAN-p5.md). The file checks
// are in doctor_test.go; helpers in doctor_helpers_test.go.
//
// Real `ssh -F <main> -G` is the oracle for D19-D23. Not parallel: the tests set
// $HOME, the passwd-home override and (D18) PATH.

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

const drWeb1 = "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n"

const drManagedBody = mgManagedHeader + "Host m-1\n  HostName 10.0.0.9\n  IdentityFile @K@/ok\n"

const drOtherConf = "Host other-1\n  HostName 10.0.0.2\n  IdentityFile @K@/ok\n"

// drWithOther is newDrEnv plus the key every body refers to and dir/other.conf.
func drWithOther(t *testing.T, mainBody, managedBody string) *drEnv {
	t.Helper()
	e := newDrEnv(t, mainBody, managedBody)
	e.key(t, "ok", 0o600)
	e.file(t, filepath.Join(e.dir, "other.conf"), drOtherConf, 0o600)
	return e
}

func drOtherHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

// ---- an anchor: nothing to report -----------------------------------------------------

func TestDoctor_CleanConfigHasNoFindings(t *testing.T) {
	mgNeedSSH(t)
	e := drWithOther(t, "Include @M@\n\n"+drWeb1+"\n"+drHardened, drManagedBody)
	if is := e.run(t, false); len(is) != 0 {
		t.Errorf("a clean, hardened, set-up config must produce no finding at all, got:\n%s", drDump(is))
	}
	if is := e.run(t, true); len(is) != 0 {
		t.Errorf("with --skip-files: want no finding, got:\n%s", drDump(is))
	}
}

// ---- D14: managed file not included -----------------------------------------------------

func TestDoctor_D14_ManagedFileNotIncluded(t *testing.T) {
	cases := []struct{ name, main, managed string }{
		{"managed file exists, no Include", drWeb1, drManagedBody},
		{"fresh machine: no managed file, no Include", drWeb1, mgAbsent},
		{"Include of another file only", "Include @D@/other.conf\n\n" + drWeb1, drManagedBody},
		{"main file with only a comment", "# nothing here\n", mgAbsent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, c.main, c.managed)
			is := e.run(t, false)
			got := drWantN(t, is, RuleNotSetUp, 1)
			if len(got) == 1 {
				if got[0].Severity != domain.SeverityInfo {
					t.Errorf("severity = %v, want info", got[0].Severity)
				}
				if want := "sshm-managed file is not included; run 'sshm setup'"; got[0].Message != want {
					t.Errorf("message = %q, want %q", got[0].Message, want)
				}
			}
			drNoRule(t, is, RuleIncludeConditional)
		})
	}
}

func TestDoctor_D14_NotReportedWhenManagedFileIsIncluded(t *testing.T) {
	cases := []struct{ name, main string }{
		{"unconditional Include at the top", "Include @M@\n\n" + drWeb1},
		{"quoted, lower case include", "include \"@M@\"\n\n" + drWeb1},
		{"glob that reaches the managed file", "Include @D@/config.d/*\n\n" + drWeb1},
		{"below a bare Host *", "Host *\n  Include @M@\n\n" + drWeb1},
		{"below Match all", "Match all\n  Include @M@\n\n" + drWeb1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, c.main, drManagedBody)
			is := e.run(t, false)
			drNoRule(t, is, RuleNotSetUp, RuleIncludeConditional)
		})
	}
}

// The "~/.ssh/config.d/sshm.conf" spelling counts when the main file is <home>/.ssh/config.
func TestDoctor_D14_TildeSpellingCountsAsIncluded(t *testing.T) {
	e := newDrEnv(t, mgAbsent, mgAbsent)
	main := filepath.Join(e.home, ".ssh", "config")
	managed := filepath.Join(e.home, ".ssh", "config.d", "sshm.conf")
	e.key(t, "ok", 0o600)
	mgWrite(t, main, e.sub("Include ~/.ssh/config.d/sshm.conf\n\n"+drWeb1), 0o600)
	mgWrite(t, managed, e.sub(drManagedBody), 0o600)
	e.a = NewAppWithPath(main)
	drNoRule(t, e.run(t, false), RuleNotSetUp, RuleIncludeConditional)
}

// ---- D15: managed file included only conditionally ----------------------------------------

func TestDoctor_D15_ManagedIncludeIsConditional(t *testing.T) {
	cases := []struct{ name, main, line string }{
		{"below a Host line", "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\nInclude @M@\n", "4"},
		{"below two Host blocks", "# c\nHost a\n  User a\n\nHost b\n  User b\n\nInclude @M@\n", "8"},
		{"below a Match line", "Match host x.example.com\n  User m\nInclude @M@\n", "3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, c.main, drManagedBody)
			is := e.run(t, false)
			got := drWantN(t, is, RuleIncludeConditional, 1)
			if len(got) == 1 {
				if got[0].Severity != domain.SeverityWarning {
					t.Errorf("severity = %v, want warning", got[0].Severity)
				}
				if want := e.main + " line " + c.line; !strings.Contains(got[0].Message, want) {
					t.Errorf("message %q must name %q", got[0].Message, want)
				}
			}
			drNoRule(t, is, RuleNotSetUp)
		})
	}
}

// ---- D16: other conditional Include lines --------------------------------------------------

func TestDoctor_D16_OtherConditionalInclude(t *testing.T) {
	t.Run("main file, managed file included unconditionally", func(t *testing.T) {
		e := drWithOther(t, "Include @M@\n\n"+drWeb1+"Include @D@/other.conf\n", drManagedBody)
		body := mgRead(t, e.main)
		got := drWantN(t, e.run(t, false), RuleIncludeConditional, 1)
		if len(got) != 1 {
			return
		}
		if got[0].Severity != domain.SeverityWarning {
			t.Errorf("severity = %v, want warning", got[0].Severity)
		}
		if want := "Include " + e.dir + "/other.conf is read only for matching hosts"; got[0].Message != want {
			t.Errorf("message = %q, want %q", got[0].Message, want)
		}
		if want := drLineHas(t, body, "Include "+e.dir+"/other.conf"); got[0].Line != want || !e.fileOK(got[0].File, e.main) {
			t.Errorf("File=%q Line=%d, want the main file line %d", got[0].File, got[0].Line, want)
		}
	})
	t.Run("both the managed and another Include are conditional: two findings, the managed one is D15", func(t *testing.T) {
		e := drWithOther(t, drWeb1+"Include @M@\nInclude @D@/other.conf\n", drManagedBody)
		body := mgRead(t, e.main)
		got := drWantN(t, e.run(t, false), RuleIncludeConditional, 2)
		if len(got) != 2 {
			return
		}
		managedLine := fmt.Sprintf("%s line %d", e.main, drLineHas(t, body, "Include "+e.managed))
		otherMsg := "Include " + e.dir + "/other.conf is read only for matching hosts"
		var nManaged, nOther int
		for _, x := range got {
			switch {
			case x.Message == otherMsg:
				nOther++
			case strings.Contains(x.Message, managedLine) && !strings.Contains(x.Message, "read only for matching hosts"):
				nManaged++
			}
		}
		if nManaged != 1 || nOther != 1 {
			t.Errorf("want one D15 message naming %q and one D16 message %q, got:\n%s", managedLine, otherMsg, drDump(got))
		}
	})
	t.Run("Include inside an included file", func(t *testing.T) {
		e := drWithOther(t, "Include @M@\nInclude @D@/inc.conf\n\n"+drWeb1, drManagedBody)
		inc := e.file(t, filepath.Join(e.dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.5\n  IdentityFile @K@/ok\nInclude @D@/other.conf\n", 0o600)
		got := drWantN(t, e.run(t, false), RuleIncludeConditional, 1)
		if len(got) == 1 && (got[0].File != inc || got[0].Line != 4 ||
			got[0].Message != "Include "+e.dir+"/other.conf is read only for matching hosts") {
			t.Errorf("got %s, want the Include on line 4 of %s", drFmt(got[0]), inc)
		}
	})
}

func TestDoctor_D16_UnconditionalIncludesAreNotReported(t *testing.T) {
	cases := []struct {
		name, main string
		fire       bool
	}{
		{"above the first Host", "Include @D@/other.conf\n\n" + drWeb1, false},
		{"below a bare Host *", "Host *\n  Include @D@/other.conf\n\n" + drWeb1, false},
		{"below Match all", "Match all\n  Include @D@/other.conf\n\n" + drWeb1, false},
		{"the nearest Host line above is Host *", "Host a\n  HostName 10.0.0.9\n\nHost *\n  Include @D@/other.conf\n", false},
		{"the nearest Host line above is not Host *", "Host *\n  User u\n\nHost b\n  HostName 10.0.0.9\n  Include @D@/other.conf\n", true},
		{"below Match host", "Match host x.example.com\n  Include @D@/other.conf\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, "Include @M@\n"+c.main, drManagedBody)
			is := e.run(t, false)
			n := 0
			if c.fire {
				n = 1
			}
			drWantN(t, is, RuleIncludeConditional, n)
			drNoRule(t, is, RuleNotSetUp)
		})
	}
}

// ---- D17: $HOME differs from the passwd home --------------------------------------------------

func TestDoctor_D17_HomeMismatch(t *testing.T) {
	link := func(t *testing.T, target string) string {
		l := filepath.Join(t.TempDir(), "home-link")
		if err := os.Symlink(target, l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	cases := []struct {
		name string
		home func(t *testing.T, e *drEnv) (value string, set bool)
		fire bool
	}{
		{"another directory", func(t *testing.T, e *drEnv) (string, bool) { return t.TempDir(), true }, true},
		{"a directory that does not exist", func(t *testing.T, e *drEnv) (string, bool) { return "/dr-no-such-home/x", true }, true},
		{"a symlink to another directory", func(t *testing.T, e *drEnv) (string, bool) { return link(t, t.TempDir()), true }, true},
		{"the same path", func(t *testing.T, e *drEnv) (string, bool) { return e.home, true }, false},
		{"trailing slash", func(t *testing.T, e *drEnv) (string, bool) { return e.home + "/", true }, false},
		{"dot segments", func(t *testing.T, e *drEnv) (string, bool) { return e.home + "/./sub/..", true }, false},
		{"symlink to the passwd home", func(t *testing.T, e *drEnv) (string, bool) { return link(t, e.home), true }, false},
		{"$HOME not set", func(t *testing.T, e *drEnv) (string, bool) { return "", false }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, "Include @M@\n\n"+drWeb1, drManagedBody)
			if err := os.MkdirAll(filepath.Join(e.home, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			v, set := c.home(t, e)
			if set {
				t.Setenv("HOME", v)
			} else if err := os.Unsetenv("HOME"); err != nil { // t.Setenv in newDrEnv restores it
				t.Fatal(err)
			}
			for _, skip := range []bool{false, true} { // D17 is not a file check
				is := e.run(t, skip)
				if !c.fire {
					drNoRule(t, is, RuleHomeMismatch)
					continue
				}
				got := drWantN(t, is, RuleHomeMismatch, 1)
				if len(got) == 1 {
					if got[0].Severity != domain.SeverityWarning {
						t.Errorf("severity = %v, want warning", got[0].Severity)
					}
					if !drHas(got[0].Message, "$HOME", "ignores") {
						t.Errorf("message %q must say that ssh ignores $HOME for ~", got[0].Message)
					}
				}
			}
		})
	}
}

// ---- D18: ssh missing -------------------------------------------------------------------------

func TestDoctor_D18_SSHMissing(t *testing.T) {
	e := drWithOther(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/gone\n\nMatch exec \"touch @D@/exec-ran\"\n  Compression no\n", mgAbsent)
	drOtherHome(t) // D17
	mgNoSSHOnPath(t)
	is := e.run(t, false)
	got := drWantN(t, is, RuleSSHMissing, 1)
	if len(got) == 1 {
		if got[0].Severity != domain.SeverityInfo {
			t.Errorf("severity = %v, want info", got[0].Severity)
		}
		if want := "ssh not found; ssh-based checks skipped"; got[0].Message != want {
			t.Errorf("message = %q, want %q", got[0].Message, want)
		}
	}
	// D19 is not run without ssh (D18); nothing ssh-based can be reported.
	drNoRule(t, is, RuleVerifySkipped, RuleSSHRejectsConfig, RuleHardeningHashKnownHosts, RuleHardeningIdentitiesOnly, RuleAgentForwardingDefault)
	if mgExists(filepath.Join(e.dir, "exec-ran")) {
		t.Error("the Match exec command was run")
	}
	// Everything else still runs, and the ssh finding comes last (file, include, ssh).
	drRequireOrder(t, is, RuleMissingIdentityFile, RuleNotSetUp, RuleHomeMismatch, RuleSSHMissing)
	if len(is) > 0 && is[len(is)-1].Rule != RuleSSHMissing {
		t.Errorf("the ssh-missing finding must be the last one, got %s", drFmt(is[len(is)-1]))
	}
}

func TestDoctor_D18_NotReportedWhenSSHIsPresent(t *testing.T) {
	mgNeedSSH(t)
	e := drWithOther(t, drWeb1, mgAbsent)
	drNoRule(t, e.run(t, false), RuleSSHMissing)
}

// ---- D19: Match exec -------------------------------------------------------------------------

func TestDoctor_D19_MatchExecIsNeverRun(t *testing.T) {
	mgNeedSSH(t)
	const exec = "Match exec \"touch @D@/exec-ran\"\n  Compression no\n"
	cases := []struct{ name, main, inc string }{
		{"in the main file", drWeb1 + "\n" + exec, ""},
		{"in an included file", "Include @D@/inc.conf\n\n" + drWeb1, exec},
		{"in an included file that is read only conditionally", drWeb1 + "Include @D@/inc.conf\n", exec},
		{"exec is not the first criterion", drWeb1 + "\nMatch host x.example.com exec \"touch @D@/exec-ran\"\n  Compression no\n", ""},
		{"upper case keywords", drWeb1 + "\nMATCH EXEC \"touch @D@/exec-ran\"\n  Compression no\n", ""},
		{"in the main file and in an included file", "Include @D@/inc.conf\n\n" + drWeb1 + "\n" + exec, exec},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, c.main, mgAbsent)
			if c.inc != "" {
				e.file(t, filepath.Join(e.dir, "inc.conf"), c.inc, 0o600)
			}
			is := e.run(t, false)
			if mgExists(filepath.Join(e.dir, "exec-ran")) {
				t.Fatal("doctor ran ssh: the Match exec command created its marker file")
			}
			got := drWantN(t, is, RuleVerifySkipped, 1)
			if len(got) == 1 {
				if got[0].Severity != domain.SeverityInfo {
					t.Errorf("severity = %v, want info", got[0].Severity)
				}
				if !drHas(got[0].Message, "verify", "not run") {
					t.Errorf("message %q must say that sshm cannot verify saves and that doctor did not run ssh", got[0].Message)
				}
			}
			drNoRule(t, is, RuleSSHRejectsConfig, RuleHardeningHashKnownHosts, RuleHardeningIdentitiesOnly, RuleAgentForwardingDefault, RuleSSHMissing)
		})
	}
}

// The other checks still run, and the finding comes after file and include checks.
func TestDoctor_D19_OtherChecksStillRunAndOrder(t *testing.T) {
	mgNeedSSH(t)
	e := drWithOther(t, "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/gone\n\nMatch exec \"touch @D@/exec-ran\"\n  Compression no\n", mgAbsent)
	drOtherHome(t)
	is := e.run(t, false)
	drRequireOrder(t, is, RuleMissingIdentityFile, RuleNotSetUp, RuleHomeMismatch, RuleVerifySkipped)
	if mgExists(filepath.Join(e.dir, "exec-ran")) {
		t.Error("the Match exec command was run")
	}
}

// Look-alikes are not Match exec lines: ssh is run (so the hardening rules are reported).
func TestDoctor_D19_NotTriggeredByLookAlikes(t *testing.T) {
	mgNeedSSH(t)
	cases := []struct{ name, tail string }{
		{"Match without exec", "Match host x.example.com\n  Compression no\n"},
		{"Match all", "Match all\n  Compression no\n"},
		{"a comment", "# Match exec \"touch @D@/exec-ran\"\n"},
		{"a host called exec", "Host exec\n  HostName 10.0.0.7\n  IdentityFile @K@/ok\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, drWeb1+"\n"+c.tail, mgAbsent)
			is := e.run(t, false)
			drNoRule(t, is, RuleVerifySkipped)
			drWantN(t, is, RuleHardeningHashKnownHosts, 1) // proof that ssh ran
		})
	}
}

// ---- D20: ssh rejects the config -------------------------------------------------------------

func TestDoctor_D20_SSHRejectsConfig(t *testing.T) {
	mgNeedSSH(t)
	cases := []struct {
		name, main string
		inc        string
		incMode    os.FileMode
	}{
		{"unknown option", drWeb1 + "\nHost *\n  BogusOption yes\n", "", 0},
		{"unknown option in an included file", "Include @D@/inc.conf\n\n" + drWeb1, "Host *\n  BogusOption yes\n", 0o600},
		{"group-writable included file", "Include @D@/inc.conf\n\n" + drWeb1, "Host inc-1\n  HostName 10.0.0.5\n  IdentityFile @K@/ok\n", 0o664},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, c.main, mgAbsent)
			if c.inc != "" {
				p := e.file(t, filepath.Join(e.dir, "inc.conf"), c.inc, c.incMode)
				if err := os.Chmod(p, c.incMode); err != nil {
					t.Fatal(err)
				}
			}
			drOtherHome(t)
			_, firstLine, exit := drSSHProbe(t, e.main)
			if exit == 0 || firstLine == "" {
				t.Fatalf("fixture error: ssh -F main -G %s exited %d (stderr %q), want a rejection", drProbe, exit, firstLine)
			}
			is := e.run(t, false)
			got := drWantN(t, is, RuleSSHRejectsConfig, 1)
			if len(got) == 1 {
				if got[0].Severity != domain.SeverityError {
					t.Errorf("severity = %v, want error", got[0].Severity)
				}
				if got[0].Message != firstLine {
					t.Errorf("message = %q, want ssh's first non-empty stderr line %q", got[0].Message, firstLine)
				}
			}
			drNoRule(t, is, RuleHardeningHashKnownHosts, RuleHardeningIdentitiesOnly, RuleAgentForwardingDefault, RuleVerifySkipped, RuleSSHMissing)
			drRequireOrder(t, is, RuleNotSetUp, RuleHomeMismatch, RuleSSHRejectsConfig)
			if len(is) > 0 && is[len(is)-1].Rule != RuleSSHRejectsConfig {
				t.Errorf("ssh-rejects-config must be the last finding, got %s", drFmt(is[len(is)-1]))
			}
		})
	}
}

// ---- D21-D23: what an otherwise unmatched host gets, from ssh itself --------------------------

func TestDoctor_D21toD23_ProbeValuesFromSSH(t *testing.T) {
	mgNeedSSH(t)
	const hard = "  HashKnownHosts yes\n  IdentitiesOnly yes\n"
	cases := []struct {
		name, main, inc string
	}{
		{"nothing set", drWeb1, ""},
		{"Host * fully hardened", drWeb1 + "\n" + drHardened, ""},
		{"only HashKnownHosts yes", drWeb1 + "\nHost *\n  HashKnownHosts yes\n", ""},
		{"only IdentitiesOnly yes", drWeb1 + "\nHost *\n  IdentitiesOnly yes\n", ""},
		{"explicit no", drWeb1 + "\nHost *\n  HashKnownHosts no\n  IdentitiesOnly no\n  ForwardAgent no\n", ""},
		{"ForwardAgent yes on Host *", drWeb1 + "\nHost *\n  ForwardAgent yes\n" + hard, ""},
		{"ForwardAgent yes and nothing hardened", drWeb1 + "\nHost *\n  ForwardAgent yes\n", ""},
		{"ForwardAgent yes only for web-1", "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n  ForwardAgent yes\n" + hard, ""},
		{"hardening only inside a specific host", "Host web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/ok\n" + hard, ""},
		{"ForwardAgent yes for a domain pattern", drWeb1 + "\nHost *.example.com\n  ForwardAgent yes\n" + hard, ""},
		{"first value wins: no, then yes", drWeb1 + "\nHost *\n  ForwardAgent no\n\nHost *\n  ForwardAgent yes\n", ""},
		{"first value wins: yes, then no", drWeb1 + "\nHost *\n  ForwardAgent yes\n\nHost *\n  ForwardAgent no\n" + hard, ""},
		{"ForwardAgent is a socket path", drWeb1 + "\nHost *\n  ForwardAgent /tmp/dr-agent.sock\n", ""},
		{"Match all", drWeb1 + "\nMatch all\n  ForwardAgent yes\n" + hard, ""},
		{"Match for another host", drWeb1 + "\nMatch host other.example.com\n  ForwardAgent yes\n" + hard, ""},
		{"hardened and forwarding in an included file", "Include @D@/inc.conf\n\n" + drWeb1, "Host *\n  ForwardAgent yes\n" + hard},
		{"Host * in an included file, nothing hardened", "Include @D@/inc.conf\n\n" + drWeb1, "Host *\n  Compression no\n"},
	}
	seen := map[string][2]bool{} // rule -> [fired, silent]
	note := func(rule string, fired bool) {
		s := seen[rule]
		if fired {
			s[0] = true
		} else {
			s[1] = true
		}
		seen[rule] = s
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := drWithOther(t, c.main, mgAbsent)
			if c.inc != "" {
				e.file(t, filepath.Join(e.dir, "inc.conf"), c.inc, 0o600)
			}
			out, firstLine, exit := drSSHProbe(t, e.main)
			if exit != 0 {
				t.Fatalf("fixture error: ssh rejected the config: %s", firstLine)
			}
			want := map[string]int{
				RuleHardeningHashKnownHosts: drBool(mgVal(out, "hashknownhosts") != "yes"),
				RuleHardeningIdentitiesOnly: drBool(mgVal(out, "identitiesonly") != "yes"),
				RuleAgentForwardingDefault:  drBool(mgVal(out, "forwardagent") == "yes"),
			}
			wantSev := map[string]domain.Severity{
				RuleHardeningHashKnownHosts: domain.SeverityInfo,
				RuleHardeningIdentitiesOnly: domain.SeverityInfo,
				RuleAgentForwardingDefault:  domain.SeverityWarning,
			}
			is := e.run(t, false)
			for rule, n := range want {
				note(rule, n == 1)
				for _, x := range drWantN(t, is, rule, n) {
					if x.Severity != wantSev[rule] {
						t.Errorf("%s: severity = %v, want %v", rule, x.Severity, wantSev[rule])
					}
				}
			}
			drNoRule(t, is, RuleSSHRejectsConfig, RuleSSHMissing, RuleVerifySkipped)
		})
	}
	if t.Failed() {
		return // some case did not run to its end; the coverage check would only add noise
	}
	for _, rule := range []string{RuleHardeningHashKnownHosts, RuleHardeningIdentitiesOnly, RuleAgentForwardingDefault} {
		if s := seen[rule]; !s[0] || !s[1] {
			t.Errorf("fixture table never exercised both the firing and the silent case of %s (fired=%v silent=%v)", rule, s[0], s[1])
		}
	}
}

func drBool(b bool) int {
	if b {
		return 1
	}
	return 0
}

// The three hardening rules come out in table order after everything else.
func TestDoctor_D21toD23_OrderAmongThemselves(t *testing.T) {
	mgNeedSSH(t)
	e := drWithOther(t, "Include @M@\n\n"+drWeb1+"\nHost *\n  ForwardAgent yes\n", drManagedBody)
	is := e.run(t, false)
	drRequireOrder(t, is, RuleHardeningHashKnownHosts, RuleHardeningIdentitiesOnly, RuleAgentForwardingDefault)
	if len(is) != 3 {
		t.Errorf("want exactly the three ssh findings, got:\n%s", drDump(is))
	}
}

// ---- D24: --skip-files omits exactly D7-D13 -----------------------------------------------------

func TestDoctor_D24_SkipFilesOmitsExactlyTheFileChecks(t *testing.T) {
	e := drRich(t, "")
	drOtherHome(t) // D17
	full := e.run(t, false)
	skipped := e.run(t, true)

	// Non-vacuity: the full run has every file rule, the skipped run has none.
	for _, r := range []string{RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions, RuleManagedPermissions} {
		if len(drRule(full, r)) == 0 {
			t.Errorf("fixture error: the full run has no %q finding:\n%s", r, drDump(full))
		}
	}
	if drKeygen != "" && len(drRule(full, RuleCertExpired)) == 0 {
		t.Errorf("fixture error: the full run has no cert-expired finding:\n%s", drDump(full))
	}
	drNoRule(t, skipped, drFileRules...)

	var want []domain.Issue
	for _, x := range full {
		if !drIn(drFileRules, x.Rule) {
			want = append(want, x)
		}
	}
	if !reflect.DeepEqual(skipped, want) {
		t.Errorf("--skip-files must equal the full result minus D7-D13.\nwant:\n%s\ngot:\n%s", drDump(want), drDump(skipped))
	}
	// Everything else is still there.
	for _, r := range []string{"strict-no", RuleIncludeConditional, RuleHomeMismatch} {
		if len(drRule(skipped, r)) == 0 {
			t.Errorf("--skip-files dropped %q, which is not a file check:\n%s", r, drDump(skipped))
		}
	}
	if mgRealSSH != "" {
		drWantN(t, skipped, RuleVerifySkipped, 1) // drRich has a Match exec
	} else {
		drWantN(t, skipped, RuleSSHMissing, 1)
	}
}

// With the file checks skipped, a missing key or a loose permission is not looked at at all.
func TestDoctor_D24_SkipFilesDoesNotTouchTheFilesystemChecks(t *testing.T) {
	e := drWithOther(t, "Include @M@\n\nHost web-1\n  HostName 10.0.0.1\n  IdentityFile @K@/gone\n  CertificateFile @K@/gone-cert.pub\n", mgManagedHeader)
	if err := os.Chmod(e.managed, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.main, 0o666); err != nil {
		t.Fatal(err)
	}
	drNoRule(t, e.run(t, true), drFileRules...)
	got := e.run(t, false)
	for _, r := range []string{RuleMissingIdentityFile, RuleMissingCertFile, RuleUnsafePermissions} {
		if len(drRule(got, r)) == 0 {
			t.Errorf("fixture error: the full run has no %q finding", r)
		}
	}
}
