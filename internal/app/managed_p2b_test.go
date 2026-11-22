package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Tests for the P2b fix round (review findings B1, B2, M1-M7 and minors).
// Same rules as managed_test.go: temp dirs only, ssh always with -F <temp
// main file>, absolute Include paths.

// countSSH wraps the sshRun seam and returns a counter of ssh invocations.
func countSSH(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	prev := sshRun
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		n.Add(1)
		return prev(ctx, args...)
	}
	t.Cleanup(func() { sshRun = prev })
	return &n
}

// mustUnchanged fails unless the managed file still has content want and no
// backup was made: the marks of a save that was refused before writing.
func (f *managedFixture) mustUnchanged(t *testing.T, want string) {
	t.Helper()
	if got := f.read(t); got != want {
		t.Errorf("managed file changed:\n%s", got)
	}
	if baks := f.backups(t); len(baks) != 0 {
		t.Errorf("a refused save made backups: %v", baks)
	}
}

// badWritePlan is the plan for a test edit that must reach the file and fail
// the verification AFTER the write (to exercise the rollback): the option may
// change, but the plan names no expected value. With an expected value ssh
// is asked about it before the write (predictExpect) and a value it rejects
// never gets that far.
func badWritePlan(host, key string) verifyPlan { return editPlan(host, key) }

func setUser(t *testing.T, f *managedFixture, user string) *config.Doc {
	t.Helper()
	d := f.doc(t)
	if err := d.SetOption("web-1", "User", user); err != nil {
		t.Fatal(err)
	}
	return d
}

// ---- Item 1 (B2): the managed file must really be read by ssh ----

func TestSaveManaged_NotIncludedIsRefused(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	f.writeMain(t, fixtureMainTail) // no Include at all
	calls := countSSH(t)

	_, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
	if err == nil {
		t.Fatal("saved a managed file that ssh never reads")
	}
	for _, want := range []string{"ssh does not read", f.managed, "sshm setup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	f.mustUnchanged(t, fixtureManaged)
	if calls.Load() != 0 {
		t.Errorf("ssh was run %d times for a save that can be refused without it", calls.Load())
	}
}

// The review's repro: the unread managed file would get a line that breaks
// every ssh call the moment the Include is added.
func TestSaveManaged_NotIncludedBadContentIsRefused(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "Host b\n  User u\n")
	f.writeMain(t, "Host a\n  User x\n")

	d := f.doc(t)
	d.Lines = append(d.Lines, "  NoSuchOpt 1")
	if _, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("b")); err == nil || !strings.Contains(err.Error(), "sshm setup") {
		t.Fatalf("err = %v", err)
	}
	f.mustUnchanged(t, "Host b\n  User u\n")
}

func TestSaveManaged_ConditionalIncludeIsRefused(t *testing.T) {
	requireSSH(t)
	for name, mainBody := range map[string]string{
		"after Host":  "Host first\n  User x\n\nInclude %s\n",
		"after Match": "Match host nothing\n  User x\n\nInclude %s\n",
		"inside Host": "Host first\n  Include %s\n  User x\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			f.writeMain(t, fmt.Sprintf(mainBody, f.managed))
			// ssh agrees: web-1 does not get the managed block.
			if got := f.resolved(t, "web-1", "hostname"); got != "web-1" {
				t.Fatalf("fixture: ssh applies the conditional include (hostname %q)", got)
			}

			_, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
			if err == nil {
				t.Fatal("saved through a conditional Include")
			}
			for _, want := range []string{"conditional", f.main, "sshm setup"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q: %v", want, err)
				}
			}
			f.mustUnchanged(t, fixtureManaged)
		})
	}
}

// Conditional is inherited: main includes a.conf at the top, a.conf includes
// the managed file below its own Host line.
func TestSaveManaged_NestedConditionalIncludeIsRefused(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	mid := filepath.Join(f.dir, "mid.conf")
	if err := os.WriteFile(mid, []byte("Host mid\n  User m\n\nInclude "+f.managed+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.writeMain(t, "Include "+mid+"\n"+fixtureMainTail)

	_, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
	if err == nil || !strings.Contains(err.Error(), "conditional") || !strings.Contains(err.Error(), mid) {
		t.Fatalf("err = %v", err)
	}
	f.mustUnchanged(t, fixtureManaged)
}

// Membership is decided after symlink resolution on both sides: the Include
// names a symlink, the save is given the real path.
func TestSaveManaged_IncludedThroughSymlinkIsAccepted(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	link := filepath.Join(f.dir, "link.conf")
	if err := os.Symlink(f.managed, link); err != nil {
		t.Fatal(err)
	}
	f.writeMain(t, "Include "+link+"\n"+fixtureMainTail)

	if _, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob")); err != nil {
		t.Fatal(err)
	}
	if got := f.resolved(t, "web-1", "user"); got != "bob" {
		t.Errorf("user = %q", got)
	}
}

// A managed file that does not exist yet cannot be looked up before the
// write; the check runs right after it and removes the file again.
func TestSaveManaged_NewFileNotIncludedIsRolledBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "")
	f.writeMain(t, fixtureMainTail)

	d := config.ParseDoc(nil)
	if err := d.AppendBlock(domain.Host{Name: "first", HostName: "10.0.0.7"}); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("first"))
	if err == nil || !strings.Contains(err.Error(), "sshm setup") || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(f.managed); !os.IsNotExist(serr) {
		t.Errorf("unread new file left behind: %v", serr)
	}
}

// With no concrete host name anywhere the sentinel is still resolved, so ssh
// parses the new content and its syntax error is caught.
func TestSaveManaged_SentinelCatchesSyntaxErrorWithoutAnyHost(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "# sshm managed\n")
	f.writeMain(t, "Include "+f.managed+"\n")
	calls := countSSH(t)

	d := f.doc(t)
	d.Lines = append(d.Lines, "NoSuchOpt 1")
	_, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan())
	if err == nil {
		t.Fatal("a managed file that breaks ssh was saved because there was no host to probe")
	}
	for _, want := range []string{"rolled back", "nosuchopt", probeSentinel, "ssh now OK"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if calls.Load() == 0 {
		t.Error("ssh was never run")
	}
	if got := f.read(t); got != "# sshm managed\n" {
		t.Errorf("not restored:\n%s", got)
	}

	// The sentinel also notices a change to what an unknown host gets.
	d = f.doc(t)
	d.Lines = append(d.Lines, "User everybody")
	_, err = f.a.saveManagedDoc(f.managed, d, anyChangePlan())
	if err == nil || !strings.Contains(err.Error(), "ssh -G "+probeSentinel+" must not change") || !strings.Contains(err.Error(), "+ user everybody") {
		t.Fatalf("err = %v", err)
	}
}

// ---- Item 2 (B1): refuse when Load could not follow an Include ----

func TestSaveManaged_UnfollowableIncludeIsRefusedWithoutRunningSSH(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	marker := filepath.Join(f.dir, "exec-ran")
	hidden := filepath.Join(f.dir, "x.conf")
	if err := os.WriteFile(hidden, []byte("Match exec \"touch "+marker+"\"\n  User matched\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// ssh expands ${VAR} in Include; sshm does not follow it.
	t.Setenv("SSHM_TEST_INC", f.dir)
	f.writeMain(t, "Include ${SSHM_TEST_INC}/x.conf\nInclude "+f.managed+"\n"+fixtureMainTail)
	calls := countSSH(t)

	_, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
	if err == nil {
		t.Fatal("saved although ssh reads a file sshm could not follow")
	}
	for _, want := range []string{"cannot follow", "${SSHM_TEST_INC}/x.conf", f.main + ":1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	f.mustUnchanged(t, fixtureManaged)
	if calls.Load() != 0 {
		t.Errorf("ssh -G was run %d times", calls.Load())
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("the Match exec command of the unseen file was run")
	}

	// Control: the refusal matters. ssh does read that file and does run the
	// command (the marker lands in this test's temp dir).
	if got := f.resolved(t, "web-1", "user"); got != "matched" {
		t.Errorf("control: ssh did not apply the unseen file (user %q)", got)
	}
	if _, serr := os.Stat(marker); serr != nil {
		t.Errorf("control: ssh -G did not run the Match exec command: %v", serr)
	}
}

func TestSaveManaged_EveryBlindWarningIsRefused(t *testing.T) {
	requireSSH(t)
	cases := map[string]func(t *testing.T, f *managedFixture) (mainHead, want string){
		"percent token": func(t *testing.T, f *managedFixture) (string, string) {
			return "Include " + f.dir + "/%h.conf\n", "tokens are not supported"
		},
		"tilde user": func(t *testing.T, f *managedFixture) (string, string) {
			return "Include ~sshm-no-such-user/x.conf\n", "~user paths"
		},
		"unparsable": func(t *testing.T, f *managedFixture) (string, string) {
			p := filepath.Join(f.dir, "broken.conf")
			writeTemp(t, p, domain.DisabledMarkerStart("g")+"\n# Host x\n")
			return "Include " + p + "\n", "cannot parse include"
		},
		"cycle": func(t *testing.T, f *managedFixture) (string, string) {
			p := filepath.Join(f.dir, "loop.conf")
			writeTemp(t, p, "Include "+f.main+"\n")
			return "Include " + p + "\n", "include cycle"
		},
		"unreadable": func(t *testing.T, f *managedFixture) (string, string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads everything")
			}
			p := filepath.Join(f.dir, "secret.conf")
			writeTemp(t, p, "Host s\n")
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			return "Include " + p + "\n", "cannot read include"
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			head, want := setup(t, f)
			f.writeMain(t, "Include "+f.managed+"\n"+head+fixtureMainTail)
			calls := countSSH(t)

			_, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
			if err == nil || !strings.Contains(err.Error(), "cannot follow") || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want a refusal naming %q", err, want)
			}
			f.mustUnchanged(t, fixtureManaged)
			if calls.Load() != 0 {
				t.Errorf("ssh -G was run %d times", calls.Load())
			}
		})
	}
}

// A second Include of a file that was already read is a warning but hides
// nothing from sshm: saves keep working.
func TestSaveManaged_RepeatedIncludeIsNotBlind(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	f.writeMain(t, "Include "+f.managed+"\n"+fixtureMainTail+"\nInclude "+f.managed+"\n")
	if _, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob")); err != nil {
		t.Fatal(err)
	}
}

// An unfollowable Include that only the NEW content brings in is caught
// after the write and rolled back before ssh sees it.
func TestSaveManaged_NewContentWithUnfollowableIncludeIsRolledBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	marker := filepath.Join(f.dir, "exec-ran")
	writeTemp(t, filepath.Join(f.dir, "y.conf"), "Match exec \"touch "+marker+"\"\n  User matched\n")
	t.Setenv("SSHM_TEST_INC", f.dir)

	d := f.doc(t)
	d.Lines = append([]string{"Include ${SSHM_TEST_INC}/y.conf"}, d.Lines...)
	_, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan())
	if err == nil || !strings.Contains(err.Error(), "cannot follow") || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != fixtureManaged {
		t.Error("file not restored")
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("ssh was run while the unfollowable Include was on disk")
	}
}

// ---- Item 3 (M1): the requested effect is verified ----

const shadowedManaged = `Host web*
  User deploy

Host web1
  User me
`

func TestSaveManaged_ShadowedEditHasNoEffectAndRollsBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, shadowedManaged)
	if got := f.resolved(t, "web1", "user"); got != "deploy" {
		t.Fatalf("fixture: user = %q", got)
	}

	d := f.doc(t)
	if err := d.SetOption("web1", "User", "x"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web1", "User", "x"))
	if err == nil {
		t.Fatal("an edit that ssh never sees was reported as saved")
	}
	for _, want := range []string{"rolled back", "no effect", "ssh -G web1", "user", "deploy", `"x"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if f.read(t) != shadowedManaged {
		t.Errorf("file not restored:\n%s", f.read(t))
	}

	// Setting the value the shadowing block already gives is in effect.
	d = f.doc(t)
	if err := d.SetOption("web1", "User", "deploy"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("web1", "User", "deploy")); err != nil {
		t.Fatalf("value that IS in effect refused: %v", err)
	}

	// A list value added to a block is in effect even next to a pattern block.
	d = f.doc(t)
	if err := d.AddOptionValue("web1", "IdentityFile", "/keys/new"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, addValuePlan("web1", "IdentityFile", "/keys/new")); err != nil {
		t.Fatal(err)
	}
}

// An option ssh ignores (IgnoreUnknown) has no effect either. Since P2d the
// save does not get as far as writing it: ssh is asked how it prints the
// expected value first, and it does not know the option there.
func TestSaveManaged_IgnoredUnknownOptionHasNoEffect(t *testing.T) {
	requireSSH(t)
	body := "IgnoreUnknown Usre\n\n" + fixtureManaged
	f := newManagedFixture(t, body)
	d := f.doc(t)
	if err := d.SetOption("web-1", "Usre", "bob"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "Usre", "bob"))
	if err == nil || !strings.Contains(err.Error(), "not writing") || !strings.Contains(err.Error(), "usre=bob") {
		t.Fatalf("err = %v", err)
	}
	f.mustUnchanged(t, body)
}

// ssh prints many values in its own form; an edit that took effect must not
// be rolled back because the literal text differs.
func TestSaveManaged_ExpectAcceptsSSHRendering(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	steps := []struct{ key, value, resolved string }{
		{"StrictHostKeyChecking", "yes", "true"},
		{"LogLevel", "debug", "DEBUG"},
		{"ControlPersist", "10m", "600"},
		{"HostName", "Web1.Example.COM", "web1.example.com"},
		{"ForwardAgent", "yes", "yes"},
	}
	for _, s := range steps {
		d := f.doc(t)
		if err := d.SetOption("web-1", s.key, s.value); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", s.key, s.value)); err != nil {
			t.Fatalf("%s %s: %v", s.key, s.value, err)
		}
		if got := f.resolved(t, "web-1", strings.ToLower(s.key)); got != s.resolved {
			t.Errorf("%s resolved %q, want %q", s.key, got, s.resolved)
		}
	}
	d := f.doc(t)
	if err := d.AddOptionValue("web-1", "LocalForward", "8080 localhost:80"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, addValuePlan("web-1", "LocalForward", "8080 localhost:80")); err != nil {
		t.Fatalf("LocalForward: %v", err)
	}
}

func TestCheckExpect(t *testing.T) {
	// one checks a single host "h": before / after are its `ssh -G` output,
	// rendered is what predictExpect got from ssh for the expected options.
	one := func(plan verifyPlan, before, after string, rendered map[string][]string) error {
		return checkExpect(map[string]string{"h": before}, map[string]string{"h": after},
			map[string]map[string][]string{"h": rendered}, plan)
	}
	r := func(kv ...string) map[string][]string {
		m := map[string][]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = append(m[kv[i]], kv[i+1])
		}
		return m
	}
	plan := setPlan("h", "User", "x")

	// The rendering is in effect (it was already, or it is now).
	if err := one(plan, "user x", "user x", r("user", "x")); err != nil {
		t.Errorf("value already in effect: %v", err)
	}
	if err := one(plan, "user old", "user x", r("user", "x")); err != nil {
		t.Errorf("value now in effect: %v", err)
	}
	// ssh prints the value in its own form: that form is what must appear.
	sp := setPlan("h", "StrictHostKeyChecking", "yes")
	if err := one(sp, "stricthostkeychecking ask", "stricthostkeychecking true", r("stricthostkeychecking", "true")); err != nil {
		t.Errorf("ssh's rendering: %v", err)
	}
	// The option changed, but not to the expected value: no free pass. The
	// error names the actual and the expected value.
	err := one(plan, "user old", "user dave", r("user", "x"))
	if err == nil || strings.Contains(err.Error(), "no effect") {
		t.Fatalf("a wrong value was accepted or misreported: %v", err)
	}
	for _, want := range []string{"ssh -G h", "user", "dave", `"x"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	// Even when the literal text of the expected value is what ssh shows for
	// another reason: the rendering decides, not the text.
	if err := one(sp, "stricthostkeychecking ask", "stricthostkeychecking yes", r("stricthostkeychecking", "true")); err == nil {
		t.Error("the literal text was accepted although ssh renders the value differently")
	}
	// Unchanged and different: no effect.
	if err := one(plan, "user deploy", "user deploy", r("user", "x")); err == nil ||
		!strings.Contains(err.Error(), "no effect") || !strings.Contains(err.Error(), "deploy") {
		t.Errorf("shadowed: %v", err)
	}
	// An option the after output does not show at all.
	if err := one(plan, "port 22", "port 22", r("user", "x")); err == nil || !strings.Contains(err.Error(), "unset") {
		t.Errorf("ignored option: %v", err)
	}
	// No prediction for an expected option: refused, never waved through.
	if err := one(plan, "user old", "user x", nil); err == nil || !strings.Contains(err.Error(), "no prediction") {
		t.Errorf("missing prediction: %v", err)
	}

	// A token-derived option next to a source edit in the same plan: the
	// prediction (made with both values) is exact, so a ControlPath that only
	// followed the HostName edit is not what the plan expects...
	tp := setPlan("h", "HostName", "new", "ControlPath", "/mine")
	bt := "hostname old\ncontrolpath /cm-old"
	if err := one(tp, bt, "hostname new\ncontrolpath /cm-new", r("hostname", "new", "controlpath", "/mine")); err == nil ||
		!strings.Contains(err.Error(), "controlpath") {
		t.Errorf("shadowed ControlPath next to a HostName edit: %v", err)
	}
	// ...and the expected one is.
	if err := one(tp, bt, "hostname new\ncontrolpath /mine", r("hostname", "new", "controlpath", "/mine")); err != nil {
		t.Errorf("controlpath in effect: %v", err)
	}
	// A value with tokens: ssh's expansion is the expected line.
	tk := setPlan("h", "HostName", "new", "ControlPath", "/cm-%h")
	if err := one(tk, bt, "hostname new\ncontrolpath /cm-new", r("hostname", "new", "controlpath", "/cm-new")); err != nil {
		t.Errorf("token value: %v", err)
	}
	if err := one(tk, bt, "hostname new\ncontrolpath /cm-old", r("hostname", "new", "controlpath", "/cm-new")); err == nil {
		t.Error("an unexpanded-as-expected token value was accepted")
	}

	// List options: the added value only has to be in the list (ssh puts an
	// -o value first, the file has it in block order).
	lp := addValuePlan("h", "LocalForward", "1 2")
	if err := one(lp, "localforward 9 [h]:9", "localforward 9 [h]:9\nlocalforward 1 [h]:2",
		r("localforward", "1 [h]:2", "localforward", "9 [h]:9")); err != nil {
		t.Errorf("list contains the added value: %v", err)
	}
	if err := one(lp, "localforward 9 [h]:9", "localforward 9 [h]:9\nlocalforward 1 [h]:3",
		r("localforward", "1 [h]:2", "localforward", "9 [h]:9")); err == nil {
		t.Error("another forward than the expected one was accepted")
	}
	// Adding a value that is already there adds nothing: still in effect.
	if err := one(lp, "localforward 1 [h]:2", "localforward 1 [h]:2", r("localforward", "1 [h]:2")); err != nil {
		t.Errorf("list value already present: %v", err)
	}
	// A value that takes the line away ("ProxyCommand none"): gone afterwards.
	np := setPlan("h", "ProxyCommand", "none")
	if err := one(np, "proxycommand /bin/echo", "user x", map[string][]string{"proxycommand": nil}); err != nil {
		t.Errorf("none removes the line: %v", err)
	}
	if err := one(np, "proxycommand /bin/echo", "proxycommand /bin/echo", map[string][]string{"proxycommand": nil}); err == nil ||
		!strings.Contains(err.Error(), "no effect") {
		t.Errorf("a shadowed 'none': %v", err)
	}
}

func TestMultisetMinus(t *testing.T) {
	for _, c := range []struct{ a, b, want []string }{
		{nil, nil, nil},
		{[]string{"x"}, nil, []string{"x"}},
		{[]string{"x"}, []string{"x"}, nil},
		{[]string{"n", "a", "b"}, []string{"a", "b"}, []string{"n"}},
		{[]string{"a", "a", "b"}, []string{"a"}, []string{"a", "b"}},
		{[]string{"a"}, []string{"a", "a"}, nil},
	} {
		if got := multisetMinus(c.a, c.b); !reflect.DeepEqual(got, c.want) {
			t.Errorf("multisetMinus(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// An expectation on a name ssh cannot resolve is a plan error, before any
// write.
func TestSaveManaged_ExpectOnPatternIsAPlanError(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := f.doc(t)
	if err := d.SetOption("web-*", "User", "shared"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-*", "User", "shared"))
	if err == nil || !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("err = %v", err)
	}
	f.mustUnchanged(t, fixtureManaged)
}

// ---- M2 (scoped): the probe field ----

func TestSaveManaged_ProbeNamesVerifyPatternBlocks(t *testing.T) {
	requireSSH(t)
	body := "Host app-z*\n  User early\n\nHost app-*\n  User shared\n  Port 2222\n"
	f := newManagedFixture(t, body)

	edit := func() *config.Doc {
		d := f.doc(t)
		if err := d.SetOption("app-*", "User", "x"); err != nil {
			t.Fatal(err)
		}
		return d
	}
	plan := func(probe string) verifyPlan {
		p := editPlan("app-*", "user").withProbe(probe)
		p.expect = map[string]map[string][]string{probe: {"user": {"x"}}}
		return p
	}

	// app-zz hits the earlier pattern block: the edit has no effect there.
	_, err := f.a.saveManagedDoc(f.managed, edit(), plan("app-zz"))
	if err == nil || !strings.Contains(err.Error(), "no effect") || !strings.Contains(err.Error(), "ssh -G app-zz") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != body {
		t.Fatal("file not restored")
	}

	// app-1 hits only the edited block: verified, and the probe name may
	// change in the keys the pattern entry allows.
	if _, err := f.a.saveManagedDoc(f.managed, edit(), plan("app-1")); err != nil {
		t.Fatal(err)
	}
	if got := f.resolved(t, "app-1", "user"); got != "x" {
		t.Errorf("user = %q", got)
	}

	// ...but not in other keys: a Port change under a user-only plan fails
	// on the probe name.
	d := f.doc(t)
	if err := d.SetOption("app-*", "Port", "2299"); err != nil {
		t.Fatal(err)
	}
	_, err = f.a.saveManagedDoc(f.managed, d, editPlan("app-*", "user").withProbe("app-1"))
	if err == nil || !strings.Contains(err.Error(), "ssh -G app-1 changed beyond the edited options") || !strings.Contains(err.Error(), "+ port 2299") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyPlanAllowed(t *testing.T) {
	p := editPlan("web-*", "user").withProbe("web-9")
	for name, want := range map[string]bool{"web-*": true, "web-9": true, probeSentinel: true, "db-1": false} {
		may, keys := p.allowed(name)
		if may != want || (may && !keys["user"]) {
			t.Errorf("allowed(%q) = %v %v", name, may, keys)
		}
	}
	// No pattern entry: the sentinel and probes may not change at all.
	if may, _ := editPlan("web-1", "user").withProbe("x").allowed(probeSentinel); may {
		t.Error("sentinel may change under a plain host plan")
	}
	if may, _ := editPlan("web-1", "user").withProbe("x").allowed("x"); may {
		t.Error("probe name may change under a plain host plan")
	}
	// A pattern that may change entirely.
	if may, keys := anyChangePlan("*").allowed(probeSentinel); !may || keys != nil {
		t.Errorf("anyChangePlan(*): %v %v", may, keys)
	}
}

// A block the plan does not declare is noticed even when its name is new.
func TestSaveManaged_UndeclaredNewBlockRollsBack(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := f.doc(t)
	for _, n := range []string{"first", "second"} {
		if err := d.AppendBlock(domain.Host{Name: n, HostName: "10.0.0.7"}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.a.saveManagedDoc(f.managed, d, anyChangePlan("first"))
	if err == nil || !strings.Contains(err.Error(), "ssh -G second must not change") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != fixtureManaged {
		t.Error("file not restored")
	}
}

// ---- Item 4 (M3): options ssh derives through tokens ----

func tokenFixture(t *testing.T) *managedFixture {
	t.Helper()
	f := newManagedFixture(t, fixtureManaged)
	// The path is only printed by ssh -G, never created. (A temp-dir path
	// instead of ~/.ssh/cm-%C so not even the string points at the real home.)
	f.writeMain(t, "Include "+f.managed+"\n"+fixtureMainTail+"  ControlPath "+f.dir+"/cm-%C\n  IdentityAgent "+f.dir+"/agent-%r\n")
	return f
}

func TestSaveManaged_TokenDerivedOptionsMayFollowTheEdit(t *testing.T) {
	requireSSH(t)
	f := tokenFixture(t)
	for _, s := range []struct{ key, value string }{
		{"User", "bob"}, {"HostName", "10.0.0.77"}, {"Port", "2244"}, {"ProxyJump", "jump.example.com"},
	} {
		cpBefore := f.resolved(t, "web-1", "controlpath")
		d := f.doc(t)
		if err := d.SetOption("web-1", s.key, s.value); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", s.key, s.value)); err != nil {
			t.Fatalf("%s edit rolled back because of a token-derived option: %v", s.key, err)
		}
		if cpAfter := f.resolved(t, "web-1", "controlpath"); cpAfter == cpBefore {
			t.Errorf("fixture: controlpath did not follow the %s edit (%s)", s.key, cpAfter)
		}
	}
	if got := f.resolved(t, "web-1", "identityagent"); got != f.dir+"/agent-bob" {
		t.Errorf("identityagent = %q", got)
	}
}

func TestSaveManaged_UnrelatedEditMayNotChangeControlPath(t *testing.T) {
	requireSSH(t)
	f := tokenFixture(t)
	orig := f.read(t)
	d := f.doc(t)
	if err := d.SetOption("web-1", "ForwardAgent", "yes"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetOption("web-1", "ControlPath", f.dir+"/other-%C"); err != nil { // not declared
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "ForwardAgent", "yes"))
	if err == nil || !strings.Contains(err.Error(), "changed beyond the edited options") || !strings.Contains(err.Error(), "controlpath") {
		t.Fatalf("err = %v", err)
	}
	if f.read(t) != orig {
		t.Error("file not restored")
	}
}

// TestComparePlanDerivedOptions replaces TestKeyMayChange, which asserted the
// hole of review R2 (any token-derived option could change whenever a source
// option was in the plan). The rule now: a derived option must be exactly
// what ssh predicted for the expected source values; without a prediction it
// must not change at all.
func TestComparePlanDerivedOptions(t *testing.T) {
	const b = "user a\ncontrolpath /cm-1\nidentityfile /k1\nidentityfile /k2\nforwardagent no"
	before := map[string]string{"h": b}
	pred := map[string]map[string][]string{"h": optionValues("user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent no")}
	plan := setPlan("h", "user", "b")

	for _, c := range []struct {
		name, after string
		pred        map[string]map[string][]string
		plan        verifyPlan
		wantErr     string // "" = accepted
	}{
		{"predicted controlpath", "user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent no", pred, plan, ""},
		{"controlpath not the predicted one", "user b\ncontrolpath /cm-3\nidentityfile /k1\nidentityfile /k2\nforwardagent no", pred, plan, "controlpath"},
		{"controlpath stayed although ssh predicts a change", "user b\ncontrolpath /cm-1\nidentityfile /k1\nidentityfile /k2\nforwardagent no", pred, plan, "controlpath stayed"},
		{"undeclared identityfile add", "user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nidentityfile /k3\nforwardagent no", pred, plan, "+ identityfile /k3"},
		{"identityfile reorder", "user b\ncontrolpath /cm-2\nidentityfile /k2\nidentityfile /k1\nforwardagent no", pred, plan, "identityfile order changed"},
		{"undeclared localforward", "user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent no\nlocalforward 8080 [h]:80", pred, plan, "+ localforward"},
		{"undeclared proxycommand", "user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent no\nproxycommand evil", pred, plan, "+ proxycommand evil"},
		{"unrelated option", "user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent yes", pred, plan, "forwardagent"},
		// No prediction (a plan without expected values, e.g. an unset): a
		// derived option may not move at all.
		{"no prediction, controlpath moves", "user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent no", nil, editPlan("h", "user"), "controlpath"},
		{"no prediction, nothing derived moves", "user b\ncontrolpath /cm-1\nidentityfile /k1\nidentityfile /k2\nforwardagent no", nil, editPlan("h", "user"), ""},
		// A prediction for a host the plan does not allow to change is ignored.
		{"prediction without permission", "user b\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent no", pred, anyChangePlan("other"), "must not change"},
		// A source option that is not in the plan never lets a derived one move.
		{"unrelated edit", "user a\ncontrolpath /cm-2\nidentityfile /k1\nidentityfile /k2\nforwardagent yes", nil, editPlan("h", "forwardagent"), "controlpath"},
	} {
		err := comparePlan(before, map[string]string{"h": c.after}, c.pred, c.plan)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: err = %v, want one naming %q", c.name, err, c.wantErr)
		}
	}
}

// sourceOverrides: only the token source options of the plan's expectations,
// in a fixed order, every expected value.
func TestSourceOverrides(t *testing.T) {
	v := setPlan("h", "User", "bob", "ForwardAgent", "yes", "HostName", "10.0.0.7", "Port", "2200", "IdentityFile", "/k")
	if got, want := sourceOverrides(v, "h"), []string{"hostname=10.0.0.7", "port=2200", "user=bob"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sourceOverrides = %q, want %q", got, want)
	}
	if got := sourceOverrides(v, "other"); got != nil {
		t.Errorf("another host gets overrides: %q", got)
	}
	if got := sourceOverrides(editPlan("h", "user"), "h"); got != nil {
		t.Errorf("a plan without expected values gives overrides: %q", got)
	}
}

// ---- Item 5 (M4): odd Host lines ----

const oddHostsManaged = `Host "quoted-1"
  User q

Host commented # c
  User c

Host a@b
  User at

Host x|y
  User pipe

Host -lead
  User lead

Host $(x) semi;colon
  User dollar

Host a/b
  User slash
`

func TestProbeable(t *testing.T) {
	for name, want := range map[string]bool{
		"web-1": true, "10.0.0.1": true, "a_b.example.com": true, "v6:host": true, "x#y": true, "[x]": true, probeSentinel: true,
		"": false, "web-*": false, "w?b": false, "!web": false, "a@b": false, "ssh://h": false, "a/b": false,
		"x|y": false, "x;y": false, "$(x)": false, "x(y": false, "x)y": false, "-lead": false, "a b": false, "a\tb": false,
		`"foo"`: false, "x'y": false, "x`y": false, `x\y`: false, "x&y": false, "x<y": false, "x>y": false, "x{y": false, "x}y": false, "x,y": false,
	} {
		if got := probeable(name); got != want {
			t.Errorf("probeable(%q) = %v, want %v", name, got, want)
		}
	}
}

// Every probeable name really is accepted by ssh, and the names the filter
// drops for being invalid really are refused (so the filter is not just
// throwing coverage away).
func TestProbeableAgreesWithSSH(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	for _, n := range []string{"web-1", "v6:host", "x#y", "[x]", "a_b", probeSentinel} {
		if _, err := f.a.sshG(n); err != nil {
			t.Errorf("probeable name %q refused by ssh: %v", n, err)
		}
	}
	for _, n := range []string{"x|y", "x;y", "$(x)", "-lead", `"foo"`, "x'y", `x\y`, "x&y", "x<y", "x>y", "x{y", "x}y", "x,y", "x`y", "x(y", "x)y", "a b"} {
		if _, err := f.a.sshG(n); err == nil {
			t.Errorf("ssh accepts %q; the filter drops it for nothing", n)
		}
	}
	// "a@b" is accepted but probes host b as user a: not what the line means.
	out, err := f.a.sshG("a@b")
	if err != nil || !strings.Contains(out, "hostname b\n") || !strings.Contains(out, "user a\n") {
		t.Errorf("ssh -G a@b: %v\n%.200s", err, out)
	}
}

func TestSaveManaged_OddHostNamesDoNotBlockSaves(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged+"\n"+oddHostsManaged)

	l, err := f.a.loadAll()
	if err != nil {
		t.Fatal(err)
	}
	names, err := probeNames(l, f.doc(t), anyChangePlan("a@b", "web-*"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"commented", "db-1", "main-1", "quoted-1", probeSentinel, "web-1"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("probe names = %q\nwant         %q", names, want)
	}
	// ssh reads those two Host lines the same way.
	if q, c := f.resolved(t, "quoted-1", "user"), f.resolved(t, "commented", "user"); q != "q" || c != "c" {
		t.Errorf("ssh: quoted-1 user %q, commented user %q", q, c)
	}

	if _, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob")); err != nil {
		t.Fatalf("a save was refused because of an unprobeable Host name: %v", err)
	}
	if got := f.resolved(t, "web-1", "user"); got != "bob" {
		t.Errorf("user = %q", got)
	}
	// The quoted host is editable under its real name and verified.
	d := f.doc(t)
	if err := d.SetOption("quoted-1", "User", "qq"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("quoted-1", "User", "qq")); err != nil {
		t.Fatal(err)
	}
}

// ---- Item 7 (M6): KnownHostsCommand takes the rest of the line ----

func TestSaveManaged_KnownHostsCommandKeepsNoStaleTail(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, "Host kh-1\n  HostName 10.0.0.4\n  KnownHostsCommand /bin/echo old # c\n")
	if got := f.resolved(t, "kh-1", "knownhostscommand"); got != "/bin/echo old # c" {
		t.Fatalf("fixture: ssh reads %q", got)
	}
	d := f.doc(t)
	if err := d.SetOption("kh-1", "KnownHostsCommand", "/bin/echo new"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("kh-1", "KnownHostsCommand", "/bin/echo new")); err != nil {
		t.Fatal(err)
	}
	if got := f.resolved(t, "kh-1", "knownhostscommand"); got != "/bin/echo new" {
		t.Errorf("ssh now runs %q, want exactly the new command", got)
	}
}

// ---- Item 8 (M7): lost updates and concurrency ----

func TestSaveManaged_LostUpdateIsAConflict(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)

	// A and B both read the file; B saves first.
	dA := setUser(t, f, "from-a")
	dB := f.doc(t)
	if err := dB.SetOption("db-1", "User", "from-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.saveManagedDoc(f.managed, dB, setPlan("db-1", "User", "from-b")); err != nil {
		t.Fatal(err)
	}
	afterB := f.read(t)
	nBaks := len(f.backups(t))
	calls := countSSH(t)

	_, err := f.a.saveManagedDoc(f.managed, dA, setPlan("web-1", "User", "from-a"))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("A overwrote B's save: err = %v", err)
	}
	if !strings.Contains(err.Error(), "re-read and retry") {
		t.Errorf("error text: %v", err)
	}
	if f.read(t) != afterB {
		t.Errorf("B's content was lost:\n%s", f.read(t))
	}
	if len(f.backups(t)) != nBaks || calls.Load() != 0 {
		t.Errorf("a conflicting save did work: backups %d -> %d, ssh calls %d", nBaks, len(f.backups(t)), calls.Load())
	}

	// Changes ssh -G cannot see (a comment) are protected the same way.
	dA = setUser(t, f, "from-a")
	f.writeManaged(t, afterB+"# a note somebody added by hand\n")
	if _, err := f.a.saveManagedDoc(f.managed, dA, setPlan("web-1", "User", "from-a")); !errors.Is(err, ErrConflict) {
		t.Fatalf("hand edit overwritten: %v", err)
	}
	// A file that appeared since an empty Doc was made is a conflict too.
	if _, err := f.a.saveManagedDoc(f.managed, config.ParseDoc(nil), anyChangePlan()); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty Doc overwrote an existing file: %v", err)
	}
	// Re-reading resolves it.
	if _, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "from-a"), setPlan("web-1", "User", "from-a")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.read(t), "by hand") || !strings.Contains(f.read(t), "User from-b") {
		t.Error("the retry lost somebody else's change")
	}
}

// Several writers that all read the same content and then save at once:
// exactly one wins each round, the others get ErrConflict and retry on fresh
// content. Nothing is lost.
func TestSaveManaged_ConcurrentWritersLoseNothing(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	edits := []struct{ key, value string }{
		{"ConnectTimeout", "11"}, {"ServerAliveCountMax", "7"}, {"ConnectionAttempts", "4"}, {"NumberOfPasswordPrompts", "2"},
	}
	mk := func(i int) (*config.Doc, error) {
		raw, err := os.ReadFile(f.managed)
		if err != nil {
			return nil, err
		}
		d := config.ParseDoc(raw)
		return d, d.SetOption("web-1", edits[i].key, edits[i].value)
	}

	var conflicts atomic.Int32
	start := make(chan struct{})
	errs := make(chan error, len(edits))
	var wg sync.WaitGroup
	for i := range edits {
		d, err := mk(i) // every writer starts from the SAME content
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(i int, d *config.Doc) {
			defer wg.Done()
			<-start
			for try := 0; try < 20; try++ {
				_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", edits[i].key, edits[i].value))
				if err == nil {
					return
				}
				if !errors.Is(err, ErrConflict) {
					errs <- fmt.Errorf("writer %d: %w", i, err)
					return
				}
				conflicts.Add(1)
				if d, err = mk(i); err != nil {
					errs <- err
					return
				}
			}
			errs <- fmt.Errorf("writer %d never got through", i)
		}(i, d)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := int(conflicts.Load()); got < len(edits)-1 {
		t.Errorf("only %d conflicts: writers with a stale base were let through", got)
	}
	for _, e := range edits {
		if got := f.resolved(t, "web-1", strings.ToLower(e.key)); got != e.value {
			t.Errorf("%s = %q, want %q (update lost)\n%s", e.key, got, e.value, f.read(t))
		}
	}
}

// The lock is held for the whole save, the verification and the rollback
// included, and released afterwards.
func TestSaveManaged_LockHeldThroughVerificationAndRollback(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	lock := filepath.Join(filepath.Dir(f.managed), managedLockName)

	var calls, acquired atomic.Int32
	prev := sshRun
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		calls.Add(1)
		if unlock, err := config.LockFile(lock, 0); err == nil {
			acquired.Add(1)
			unlock()
		}
		return prev(ctx, args...)
	}
	t.Cleanup(func() { sshRun = prev })

	d := f.doc(t)
	if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, badWritePlan("web-1", "KexAlgorithms"))
	if err == nil || !strings.Contains(err.Error(), "ssh now OK") {
		t.Fatalf("err = %v", err)
	}
	// before probes + the failing after probe + the probes after the restore
	if calls.Load() < 3 {
		t.Fatalf("only %d ssh calls", calls.Load())
	}
	if acquired.Load() != 0 {
		t.Errorf("the lock was free during %d of %d ssh calls", acquired.Load(), calls.Load())
	}
	unlock, lerr := config.LockFile(lock, 0)
	if lerr != nil {
		t.Fatalf("lock not released after the save: %v", lerr)
	}
	unlock()
}

func TestSaveManaged_LockTimeout(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	unlock, err := config.LockFile(filepath.Join(filepath.Dir(f.managed), managedLockName), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	prev := managedLockTimeout
	managedLockTimeout = 80 * time.Millisecond
	t.Cleanup(func() { managedLockTimeout = prev })

	_, err = f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
	if !errors.Is(err, config.ErrLockTimeout) {
		t.Fatalf("err = %v", err)
	}
	f.mustUnchanged(t, fixtureManaged)
}

// ---- Item 9: minors ----

// (a) + (b): what happens to a permission repair when the edit fails, and
// the error says what ssh makes of the restored file.
// P2c item 7: a permission repair is NOT undone when the edit fails. The old
// mode (group/world-writable) is one ssh refuses, so restoring it would break
// ssh again on purpose; the content is rolled back, the mode stays 0600 and
// the error says so.
func TestSaveManaged_ModeRepairStaysWhenTheEditFails(t *testing.T) {
	requireSSH(t)
	for _, old := range []os.FileMode{0o664, 0o666, 0o620} {
		f := newManagedFixture(t, fixtureManaged)
		if err := os.Chmod(f.managed, old); err != nil {
			t.Fatal(err)
		}
		d := f.doc(t)
		if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
			t.Fatal(err)
		}
		note, err := f.a.saveManagedDoc(f.managed, d, badWritePlan("web-1", "KexAlgorithms"))
		if err == nil {
			t.Fatal("invalid option accepted")
		}
		if note != "" {
			t.Errorf("%04o: a failed save returned a note: %q", old, note)
		}
		if m := f.mode(t); m != 0o600 {
			t.Errorf("mode after the failed save = %04o, want 0600 (ssh refuses %04o)", m, old)
		}
		if f.read(t) != fixtureManaged {
			t.Errorf("%04o: content not restored", old)
		}
		// With the mode kept, ssh works after the rollback, and the error
		// names the mode change instead of hiding it.
		for _, want := range []string{"rolled back", "permissions stay 0600", fmt.Sprintf("%04o", old), "ssh now OK", "KexAlgorithms"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%04o: error lacks %q: %v", old, want, err)
			}
		}
		if _, gerr := f.a.sshG("web-1"); gerr != nil {
			t.Errorf("%04o: ssh fails after the rollback: %v", old, gerr)
		}
	}
}

// A mode ssh accepts (not group/world-writable) is none of this save's
// business: it comes back with the content on a rollback.
func TestSaveManaged_RollbackRestoresAnAcceptableMode(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	if err := os.Chmod(f.managed, 0o644); err != nil {
		t.Fatal(err)
	}
	d := f.doc(t)
	if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, badWritePlan("web-1", "KexAlgorithms"))
	if err == nil || strings.Contains(err.Error(), "permissions stay") {
		t.Fatalf("err = %v", err)
	}
	if m := f.mode(t); m != 0o644 {
		t.Errorf("mode after the rollback = %04o, want the previous 0644", m)
	}
}

// The repair also stays when the save stops before writing anything.
func TestSaveManaged_ModeRepairStaysWhenTheConfigStaysBroken(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	f.writeMain(t, "Include "+f.managed+"\n\nHost *\n  KexAlgorithms no-such-kex-algorithm\n")
	if err := os.Chmod(f.managed, 0o664); err != nil {
		t.Fatal(err)
	}
	note, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
	if err == nil || !strings.Contains(err.Error(), "already broken") || note != "" {
		t.Fatalf("note=%q err=%v", note, err)
	}
	for _, want := range []string{"from 0664 to 0600", "they stay 0600"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if m := f.mode(t); m != 0o600 {
		t.Errorf("mode = %04o, want 0600: a mode ssh refuses must not come back", m)
	}
	f.mustUnchanged(t, fixtureManaged)
}

func TestFixWritableModeNeverFollowsASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(victim, []byte("x"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o664); err != nil { // not subject to umask
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	note, err := fixWritableMode(link)
	if note != "" || err != nil {
		t.Errorf("fixWritableMode(symlink) = %q, %v; want no repair", note, err)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o664 {
		t.Errorf("the link's target was chmodded to %o", fi.Mode().Perm())
	}

	// The real file: repaired, the note names the previous mode.
	note, err = fixWritableMode(victim)
	if err != nil || !strings.Contains(note, "0664") {
		t.Fatalf("note=%q err=%v", note, err)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o", fi.Mode().Perm())
	}
	// Nothing to repair: no note.
	if note, err = fixWritableMode(victim); note != "" || err != nil {
		t.Errorf("second call = %q, %v", note, err)
	}
}

// (b) the normal rollback says ssh works again.
func TestSaveManaged_RollbackReportsSSHState(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	d := f.doc(t)
	if err := d.SetOption("web-1", "KexAlgorithms", "no-such-kex-algorithm"); err != nil {
		t.Fatal(err)
	}
	_, err := f.a.saveManagedDoc(f.managed, d, badWritePlan("web-1", "KexAlgorithms"))
	if err == nil || !strings.Contains(err.Error(), "file restored; ssh now OK") {
		t.Fatalf("err = %v", err)
	}
}

// (c) the order of IdentityFile lines is significant and is compared.
func TestSaveManaged_IdentityFileReorderIsAChange(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	swapped := func() *config.Doc {
		d := f.doc(t)
		var idx []int
		for i, l := range d.Lines {
			if strings.Contains(l, "IdentityFile /keys/web1_") {
				idx = append(idx, i)
			}
		}
		if len(idx) != 2 {
			t.Fatalf("fixture: %d IdentityFile lines", len(idx))
		}
		d.Lines[idx[0]], d.Lines[idx[1]] = d.Lines[idx[1]], d.Lines[idx[0]]
		return d
	}

	// (The same next to a User edit: TestSaveManaged_UndeclaredChangeNextToASourceEditRollsBack.)
	_, err := f.a.saveManagedDoc(f.managed, swapped(), editPlan("web-1", "forwardagent"))
	if err == nil || !strings.Contains(err.Error(), "identityfile order changed") {
		t.Fatalf("a reordered IdentityFile list went unnoticed: %v", err)
	}
	if f.read(t) != fixtureManaged {
		t.Error("file not restored")
	}
	if _, err := f.a.saveManagedDoc(f.managed, swapped(), editPlan("web-1", "identityfile")); err != nil {
		t.Fatalf("declared reorder refused: %v", err)
	}
	if got := f.resolved(t, "web-1", "identityfile"); got != "/keys/web1_b,/keys/web1_a" {
		t.Errorf("identityfile = %q", got)
	}
}

func TestComparePlanOrder(t *testing.T) {
	before := map[string]string{"h": "user a\nidentityfile /1\nidentityfile /2"}
	after := map[string]string{"h": "user a\nidentityfile /2\nidentityfile /1"}
	if err := comparePlan(before, after, nil, anyChangePlan("other")); err == nil ||
		!strings.Contains(err.Error(), "~ identityfile order changed: [/1, /2] -> [/2, /1]") {
		t.Errorf("err = %v", err)
	}
	if err := comparePlan(before, before, nil, anyChangePlan("other")); err != nil {
		t.Errorf("identical: %v", err)
	}
}

// (f) Extra keys are case-insensitive; modeled options never land in Extra.
func TestApplyChangeExtraIsCaseInsensitive(t *testing.T) {
	h := domain.Host{Name: "x", Extra: map[string]string{"ServerAliveInterval": "30"}}
	applyChange(&h, "serveraliveinterval", "60")
	if len(h.Extra) != 1 || h.Extra["ServerAliveInterval"] != "60" {
		t.Errorf("Extra = %v, want the one existing key updated", h.Extra)
	}
	applyChange(&h, "Compression", "yes")
	applyChange(&h, "COMPRESSION", "no")
	if len(h.Extra) != 2 || h.Extra["Compression"] != "no" {
		t.Errorf("Extra = %v", h.Extra)
	}
	// Stale case duplicates (from an older sshm) are merged.
	h = domain.Host{Name: "x", Extra: map[string]string{"ServerAliveInterval": "30", "serveraliveinterval": "40"}}
	applyChange(&h, "SERVERALIVEINTERVAL", "50")
	if len(h.Extra) != 1 || h.Extra["ServerAliveInterval"] != "50" {
		t.Errorf("Extra = %v", h.Extra)
	}
	// The block writer emits exactly one line.
	lines, err := config.BlockLines(h)
	if out := strings.Join(lines, "\n"); err != nil || strings.Count(strings.ToLower(out), "serveraliveinterval") != 1 {
		t.Errorf("written:\n%s (%v)", out, err)
	}

	h = domain.Host{Name: "x", Ciphers: "aes128-ctr", MACs: "old", KexAlgorithms: "old", HostKeyAlgorithms: "old", PubkeyAcceptedAlgorithms: "old"}
	for _, k := range []string{"ciphers", "MACs", "KexAlgorithms", "hostkeyalgorithms", "PubkeyAcceptedKeyTypes"} {
		applyChange(&h, k, "new")
	}
	if len(h.Extra) != 0 || h.Ciphers != "new" || h.MACs != "new" || h.KexAlgorithms != "new" ||
		h.HostKeyAlgorithms != "new" || h.PubkeyAcceptedAlgorithms != "new" {
		t.Errorf("modeled options went to Extra: %+v", h)
	}
}
