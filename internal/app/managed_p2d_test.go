package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Tests for the P2d fix round. Same rules as managed_test.go: temp dirs only,
// ssh always with -F <temp main file>, absolute Include paths; a "Match exec"
// command only ever touches a file inside the test's temp dir.

// ---- Item 1: files behind an Include glob are seen the way ssh sees them ----

// The consequence of the glob finding: with "Include conf.d/[!_]*" ssh reads
// conf.d/a.conf, and a "Match exec" in it runs on every `ssh -G`. The save
// must find that line and skip verification; reading the pattern like Go's
// filepath.Glob (which takes "[!_]" for "! or _") it never loaded the file and
// ran the command. Same for "[^_]*", where "^" is an ordinary member for ssh.
func TestSaveManaged_ExecGateSeesFilesBehindASetGlob(t *testing.T) {
	requireSSH(t)
	for _, c := range []struct{ pattern, file string }{
		{"[!_]*", "a.conf"},
		{"[^_]*", "_u.conf"},
		{"[!a-c]*", "x.conf"},
		{"?[!]x].conf", "ab.conf"},
	} {
		t.Run(c.pattern, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			marker := filepath.Join(f.dir, "exec-ran")
			if err := os.MkdirAll(filepath.Join(f.dir, "conf.d"), 0o700); err != nil {
				t.Fatal(err)
			}
			writeTemp(t, filepath.Join(f.dir, "conf.d", c.file), "Match exec \"touch "+marker+"\"\n  Compression no\n")
			f.writeMain(t, "Include "+f.managed+"\nInclude "+f.dir+"/conf.d/"+c.pattern+"\n"+fixtureMainTail)

			// Fixture check, without running anything: the loaded view has the file.
			l, err := config.Load(f.main)
			if err != nil || len(l.Unfollowed) != 0 {
				t.Fatalf("Load: %v, unfollowed %v", err, l.Unfollowed)
			}
			if _, ok := l.Lookup(filepath.Join(f.dir, "conf.d", c.file)); !ok {
				t.Fatalf("Include %s: %s is not loaded, so nothing looks for a Match exec in it", c.pattern, c.file)
			}

			calls := countSSH(t)
			note, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
			if err != nil || !strings.Contains(note, "verification skipped") {
				t.Fatalf("note=%q err=%v", note, err)
			}
			if _, serr := os.Stat(marker); serr == nil || calls.Load() != 0 {
				t.Fatalf("ssh was run (%d calls) or the Match exec command ran", calls.Load())
			}
		})
	}
}

// A glob sshm does not reproduce is an Include it cannot follow: nothing is
// written and ssh is not run (it could run a Match exec nobody saw).
func TestSaveManaged_UnfollowableGlobIsRefused(t *testing.T) {
	requireSSH(t)
	for _, pattern := range []string{"[[:alpha:]]*", "[a/b]", "*a*b*c*d*e*f*g*h*i*"} {
		f := newManagedFixture(t, fixtureManaged)
		marker := filepath.Join(f.dir, "exec-ran")
		if err := os.MkdirAll(filepath.Join(f.dir, "conf.d"), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTemp(t, filepath.Join(f.dir, "conf.d", "a.conf"), "Match exec \"touch "+marker+"\"\n  Compression no\n")
		f.writeMain(t, "Include "+f.managed+"\nInclude "+f.dir+"/conf.d/"+pattern+"\n"+fixtureMainTail)
		calls := countSSH(t)
		_, err := f.a.saveManagedDoc(f.managed, setUser(t, f, "bob"), setPlan("web-1", "User", "bob"))
		if err == nil || !strings.Contains(err.Error(), "cannot follow") {
			t.Fatalf("%s: err = %v", pattern, err)
		}
		if _, serr := os.Stat(marker); serr == nil || calls.Load() != 0 {
			t.Fatalf("%s: ssh was run (%d calls)", pattern, calls.Load())
		}
		f.mustUnchanged(t, fixtureManaged)
	}
}

// ---- Item 2: an identity / certificate edit replaces every line ----

const twoFilesFixture = `Host other
  HostName 10.0.0.9
  IdentityFile /keys/o1
  IdentityFile /keys/o2
  CertificateFile /keys/o1-cert.pub
  CertificateFile /keys/o2-cert.pub

Host h
  HostName 10.0.0.1
  IdentityFile /keys/a
  IdentityFile /keys/b
  CertificateFile /keys/a-cert.pub
  CertificateFile /keys/b-cert.pub

Host last
  HostName 10.0.0.3
  IdentityFile /keys/l1
  IdentityFile /keys/l2
`

// optionLines returns the "Key value" lines of key in the block of host,
// read from the file text itself (not through the parser under test).
func optionLines(t *testing.T, text, host, key string) []string {
	t.Helper()
	var out []string
	in := false
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "Host" {
			in = f[1] == host
			continue
		}
		if in && len(f) >= 2 && strings.EqualFold(f[0], key) {
			out = append(out, strings.Join(f[1:], " "))
		}
	}
	return out
}

func TestEditHostFileOptionReplacesEveryLine(t *testing.T) {
	a := newSetUpTestApp(t, twoFilesFixture)
	check := func(step, host, key string, want ...string) {
		t.Helper()
		if got := optionLines(t, configAfter(t, a), host, key); !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("%s: %s lines of host %s = %q, want %q\n%s", step, key, host, got, want, configAfter(t, a))
		}
	}
	untouched := func(step string) {
		t.Helper()
		check(step, "other", "IdentityFile", "/keys/o1", "/keys/o2")
		check(step, "other", "CertificateFile", "/keys/o1-cert.pub", "/keys/o2-cert.pub")
		check(step, "last", "IdentityFile", "/keys/l1", "/keys/l2")
	}

	// identityfile=new: exactly one line, the certificate lines stay.
	if err := a.EditHost("h", map[string]string{"identityfile": "/keys/new"}); err != nil {
		t.Fatal(err)
	}
	check("identity edit", "h", "IdentityFile", "/keys/new")
	check("identity edit", "h", "CertificateFile", "/keys/a-cert.pub", "/keys/b-cert.pub")
	untouched("identity edit")
	if _, err := exec.LookPath("ssh"); err == nil {
		out, err := a.sshG("h")
		if err != nil {
			t.Fatal(err)
		}
		if got := optionValues(out)["identityfile"]; !reflect.DeepEqual(got, []string{"/keys/new"}) {
			t.Errorf("ssh -G h: identityfile %q, want only /keys/new", got)
		}
	}

	// certificatefile=new: the same (this is what `sshm cert sign` does).
	if err := a.EditHost("h", map[string]string{"CertificateFile": "/keys/new-cert.pub"}); err != nil {
		t.Fatal(err)
	}
	check("certificate edit", "h", "CertificateFile", "/keys/new-cert.pub")
	check("certificate edit", "h", "IdentityFile", "/keys/new")
	untouched("certificate edit")

	// An unrelated edit keeps both lines of a two-line block.
	if err := a.EditHost("last", map[string]string{"user": "zed"}); err != nil {
		t.Fatal(err)
	}
	untouched("unrelated edit")

	// Clearing removes every line.
	if err := a.EditHost("last", map[string]string{"identityfile": ""}); err != nil {
		t.Fatal(err)
	}
	check("identity clear", "last", "IdentityFile")
	check("identity clear", "other", "IdentityFile", "/keys/o1", "/keys/o2")
	if err := a.ClearCertificateFile("other"); err != nil {
		t.Fatal(err)
	}
	check("certificate clear", "other", "CertificateFile")
	check("certificate clear", "other", "IdentityFile", "/keys/o1", "/keys/o2")
	check("certificate clear", "h", "CertificateFile", "/keys/new-cert.pub")
}

// The same on the Host value: whatever the lists held, an edit leaves the one
// new value in both the singular field and the list.
func TestApplyChangeFileOptionsSetTheWholeList(t *testing.T) {
	h := domain.Host{
		IdentityFile: "a", IdentityFiles: []string{"a", "b"},
		CertificateFile: "c1", CertificateFiles: []string{"c1", "c2", "c3"},
	}
	applyChange(&h, "IdentityFile", "new")
	applyChange(&h, "certificatefile", "newcert")
	if !reflect.DeepEqual(h.IdentityFileList(), []string{"new"}) || h.IdentityFile != "new" || !reflect.DeepEqual(h.IdentityFiles, []string{"new"}) {
		t.Errorf("identity: %q / %q / list %q", h.IdentityFile, h.IdentityFiles, h.IdentityFileList())
	}
	if !reflect.DeepEqual(h.CertificateFileList(), []string{"newcert"}) || !reflect.DeepEqual(h.CertificateFiles, []string{"newcert"}) {
		t.Errorf("certificate: %q / %q", h.CertificateFile, h.CertificateFiles)
	}
	applyChange(&h, "identityfile", "")
	applyChange(&h, "CERTIFICATEFILE", "")
	if h.IdentityFileList() != nil || h.CertificateFileList() != nil || h.IdentityFiles != nil || h.CertificateFiles != nil {
		t.Errorf("clear left values: %+v", h)
	}
}

// ---- Item 3: the host part of a remote path ----

func TestCopyRefusesRemoteHostPartThatLooksLikeAnOption(t *testing.T) {
	a := newTestApp(t, optionNameFixture)
	calls := captureExec(t)
	for _, c := range [][2]string{
		{"user@-oProxyCommand=x:path", "/tmp/y"},
		{"/tmp/y", "user@-oProxyCommand=x:/tmp/x"},
		{"user@[-oProxyCommand=x]:/tmp/x", "/tmp/y"},
		{"a@b@-v:/tmp/x", "/tmp/y"},
		{"alice@-:/tmp/x", "/tmp/y"},
		{"[-oProxyCommand=x]:/tmp/x", "/tmp/y"},
		// The second argument is checked too, even when the first is remote.
		{"web-1:/tmp/x", "user@-v:/tmp/y"},
	} {
		if err := a.Copy(c[0], c[1], "-a"); err == nil || !strings.Contains(err.Error(), "starts with '-'") {
			t.Errorf("Copy(%q, %q) = %v, want a refusal", c[0], c[1], err)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("rsync was started: %q", *calls)
	}
}

func TestRemoteHostOnly(t *testing.T) {
	for spec, want := range map[string]string{
		"host":                   "host",
		"user@host":              "host",
		"user@-oProxyCommand=x":  "-oProxyCommand=x",
		"a@b@host":               "host",
		"user@[2001:db8::1]":     "2001:db8::1]",
		"user@[-oProxyCommand=x": "-oProxyCommand=x",
		"[-v]":                   "-v]",
		"user-name@host-1":       "host-1",
		"-user@host":             "host",
		"":                       "",
	} {
		if got := remoteHostOnly(spec); got != want {
			t.Errorf("remoteHostOnly(%q) = %q, want %q", spec, got, want)
		}
	}
}

// Ordinary remotes still go to rsync exactly as before.
func TestCopyPassesOrdinaryRemotesThrough(t *testing.T) {
	if _, err := exec.LookPath("rsync"); err != nil {
		t.Skip("rsync not in PATH")
	}
	a := newTestApp(t, optionNameFixture)
	calls := captureExec(t)
	adhoc := []string{"-e", "ssh -i " + domain.DefaultIdentityFile}
	for _, c := range []struct {
		src, dst string
		adhoc    bool
	}{
		{"web-1:/tmp/x", "/tmp/y", false},
		{"/tmp/y", "web-1:/tmp/x", false},
		{"alice@files.example.com:/tmp/x", "/tmp/y", true},
		{"/tmp/y", "my-user@build-host.example.com:dir/a-b", true},
		{"bob@[2001:db8::1]:/tmp/x", "/tmp/y", true},
		{"unknown-host:/tmp/x", "/tmp/y", false},
	} {
		*calls = nil
		err := a.Copy(c.src, c.dst, "-a")
		if err == nil || !strings.Contains(err.Error(), "exec captured") {
			t.Errorf("Copy(%q, %q) = %v, want it to reach rsync", c.src, c.dst, err)
			continue
		}
		want := []string{"rsync", "rsync", "-a"}
		if c.adhoc {
			want = append(want, adhoc...)
		}
		want = append(want, c.src, c.dst)
		if len(*calls) != 1 || !reflect.DeepEqual((*calls)[0], want) {
			t.Errorf("Copy(%q, %q): argv %q, want %q", c.src, c.dst, *calls, want)
		}
	}
}

// ---- Item 4: the expected value is the value that appears ----

// The review's case: a plain configuration (no option with tokens anywhere),
// the plan expects one value and the document writes another. The "it
// changed" relaxation let that through.
func TestSaveManaged_WrongValueIsRolledBack(t *testing.T) {
	requireSSH(t)
	set := func(key, value string) func(*config.Doc) error {
		return func(d *config.Doc) error { return d.SetOption("web-1", key, value) }
	}
	for _, c := range []struct {
		name  string
		edit  func(*config.Doc) error
		plan  verifyPlan
		wants []string // in the error
	}{
		{"user", set("User", "dave"), setPlan("web-1", "User", "carol"), []string{"user", "dave", `"carol"`, "carol"}},
		{"hostname", set("HostName", "10.0.0.50"), setPlan("web-1", "HostName", "10.0.0.51"), []string{"hostname", "10.0.0.50", "10.0.0.51"}},
		{"port", set("Port", "2201"), setPlan("web-1", "Port", "2202"), []string{"port", "2201", "2202"}},
		{"rendered value", set("StrictHostKeyChecking", "no"), setPlan("web-1", "StrictHostKeyChecking", "yes"),
			[]string{"stricthostkeychecking", "false", `"yes"`, "true"}},
		{"same rendering class, other value", set("ControlPersist", "5m"), setPlan("web-1", "ControlPersist", "10m"),
			[]string{"controlpersist", "300", `"10m"`, "600"}},
		{"list value", func(d *config.Doc) error { return d.AddOptionValue("web-1", "IdentityFile", "/keys/x") },
			addValuePlan("web-1", "IdentityFile", "/keys/y"), []string{"identityfile", "/keys/x", "/keys/y"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newManagedFixture(t, fixtureManaged)
			d := f.doc(t)
			if err := c.edit(d); err != nil {
				t.Fatal(err)
			}
			_, err := f.a.saveManagedDoc(f.managed, d, c.plan)
			if err == nil {
				t.Fatalf("a value other than the expected one was saved:\n%s", f.read(t))
			}
			for _, want := range append([]string{"rolled back", "ssh -G web-1"}, c.wants...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q: %v", want, err)
				}
			}
			if strings.Contains(err.Error(), "no effect") {
				t.Errorf("a wrong value is reported as an edit without effect: %v", err)
			}
			if f.read(t) != fixtureManaged {
				t.Errorf("file not restored:\n%s", f.read(t))
			}
		})
	}
}

// Correct edits pass with whatever form ssh gives the value: the comparison
// is against ssh's own rendering, obtained before the write.
func TestSaveManaged_ExpectUsesSSHsOwnRendering(t *testing.T) {
	requireSSH(t)
	f := newManagedFixture(t, fixtureManaged)
	f.writeMain(t, "Include "+f.managed+"\n"+fixtureMainTail+"  ProxyCommand /bin/echo %h\n  ControlPath "+f.dir+"/cm-%r\n")
	for _, s := range []struct{ key, value, resolved string }{
		{"StrictHostKeyChecking", "yes", "true"},
		{"LogLevel", "debug", "DEBUG"},
		{"ControlPersist", "10m", "600"},
		{"HostName", "Web1.Example.COM", "web1.example.com"},
		{"HostName", "%h.Example.com", "web-1.example.com"},
		{"GlobalKnownHostsFile", f.dir + "/kh1  " + f.dir + "/kh2", f.dir + "/kh1 " + f.dir + "/kh2"},
		{"Ciphers", "+aes128-cbc", ""},
		{"SetEnv", "A=1", "A=1"},
		{"ProxyCommand", "none", ""},
		{"ControlPath", f.dir + "/own-%r-%p", f.dir + "/own-alice-2222"},
	} {
		d := f.doc(t)
		if err := d.SetOption("web-1", s.key, s.value); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", s.key, s.value)); err != nil {
			t.Fatalf("%s %s: %v", s.key, s.value, err)
		}
		got := f.resolved(t, "web-1", strings.ToLower(s.key))
		if s.key == "Ciphers" {
			if !strings.HasSuffix(got, ",aes128-cbc") {
				t.Errorf("ciphers resolved %q", got)
			}
			continue
		}
		if got != s.resolved {
			t.Errorf("%s resolved %q, want %q", s.key, got, s.resolved)
		}
	}
	// A source option and an option with a token of it in one save.
	d := f.doc(t)
	for _, kv := range [][2]string{{"User", "carol"}, {"ControlPath", f.dir + "/c-%r"}} {
		if err := d.SetOption("web-1", kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", "User", "carol", "ControlPath", f.dir+"/c-%r")); err != nil {
		t.Fatalf("User + ControlPath: %v", err)
	}
	if got := f.resolved(t, "web-1", "controlpath"); got != f.dir+"/c-carol" {
		t.Errorf("controlpath resolved %q", got)
	}
	// List values, also one with "~" and one that is already there.
	for _, add := range [][2]string{
		{"IdentityFile", "~/.ssh/id_p2d"}, {"LocalForward", "8080 localhost:80"}, {"IdentityFile", "/keys/web1_a"},
	} {
		d := f.doc(t)
		if err := d.AddOptionValue("web-1", add[0], add[1]); err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.saveManagedDoc(f.managed, d, addValuePlan("web-1", add[0], add[1])); err != nil {
			t.Fatalf("add %s %s: %v", add[0], add[1], err)
		}
	}
}

// What ssh rejects, or never shows, is refused before anything is written.
func TestSaveManaged_UnverifiableExpectedValueIsRefusedBeforeWriting(t *testing.T) {
	requireSSH(t)
	for _, c := range []struct{ key, value, want string }{
		{"KexAlgorithms", "no-such-kex-algorithm", "ssh does not accept the new values (kexalgorithms=no-such-kex-algorithm)"},
		{"StrictHostKeyChecking", "perhaps", "ssh does not accept the new values"},
		{"User", "two words", "ssh does not accept the new values"},
		// Deprecated: ssh takes the line and ignores it, -G never prints it.
		{"Protocol", "2", "not writing"},
		// "none" for an option that is not set: nothing to see either way.
		{"ProxyJump", "none", "cannot verify the change"},
	} {
		f := newManagedFixture(t, fixtureManaged)
		d := f.doc(t)
		if err := d.SetOption("web-1", c.key, c.value); err != nil {
			t.Fatal(err)
		}
		_, err := f.a.saveManagedDoc(f.managed, d, setPlan("web-1", c.key, c.value))
		if err == nil || !strings.Contains(err.Error(), "not writing") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: err = %v", c.key, c.value, err)
		}
		f.mustUnchanged(t, fixtureManaged)
	}
}

// The rendering is asked for with `-o key=value` for EVERY expected value of
// the host; when those are exactly the token-source values, the answer of
// predictDerived is reused instead of asking twice.
func TestPredictExpectArguments(t *testing.T) {
	f := newManagedFixture(t, fixtureManaged)
	var got [][]string
	reply := "user bob\nport 2244\nforwardagent yes\n"
	prev := sshRun
	sshRun = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		got = append(got, args)
		return []byte(reply), nil, nil
	}
	t.Cleanup(func() { sshRun = prev })
	before := map[string]string{"web-1": "user alice\nport 2222\nforwardagent no"}

	v := setPlan("web-1", "User", "bob", "Port", "2244", "ForwardAgent", "yes")
	rendered, err := f.a.predictExpect(before, nil, v)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := [][]string{{"-F", f.main, "-G", "-o", "forwardagent=yes", "-o", "port=2244", "-o", "user=bob", "--", "web-1"}}
	if !reflect.DeepEqual(got, wantArgs) {
		t.Errorf("ssh calls:\n got %q\nwant %q", got, wantArgs)
	}
	want := map[string]map[string][]string{"web-1": {"user": {"bob"}, "port": {"2244"}, "forwardagent": {"yes"}}}
	if !reflect.DeepEqual(rendered, want) {
		t.Errorf("rendered = %v, want %v", rendered, want)
	}

	// Only source values: the prediction made for the derived options is it.
	got = nil
	v = setPlan("web-1", "User", "bob", "Port", "2244")
	pred := map[string]map[string][]string{"web-1": {"user": {"bob"}, "port": {"2244"}, "controlpath": {"/x"}}}
	rendered, err = f.a.predictExpect(before, pred, v)
	if err != nil || len(got) != 0 {
		t.Errorf("err=%v, ssh calls %q; want the prediction reused", err, got)
	}
	if want := map[string]map[string][]string{"web-1": {"user": {"bob"}, "port": {"2244"}}}; !reflect.DeepEqual(rendered, want) {
		t.Errorf("rendered = %v, want %v", rendered, want)
	}

	// ssh shows no line for the option, before or with the value: refused.
	reply = "user alice\n"
	_, err = f.a.predictExpect(before, nil, setPlan("web-1", "Protocol", "2"))
	if err == nil || !strings.Contains(err.Error(), "cannot verify") || !strings.Contains(err.Error(), "protocol") {
		t.Errorf("invisible option: %v", err)
	}
	// A plan without expectations asks nothing.
	got = nil
	if rendered, err := f.a.predictExpect(before, nil, editPlan("web-1", "user")); err != nil || len(rendered) != 0 || len(got) != 0 {
		t.Errorf("no expectations: rendered=%v err=%v calls=%q", rendered, err, got)
	}
}
