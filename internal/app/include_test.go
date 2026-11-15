package app

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// incEnv is a main config that Includes a second file. Hosts:
//
//	main file:     main-1, deploy-main
//	included file: inc-a, deploy-inc
//
// "deploy" is therefore a group split across both files. All paths are
// absolute temp paths (see TestMain for the home override).
type incEnv struct {
	a        *App
	dir      string // holds the main file, its backups and the group sidecar
	incDir   string // holds the included file
	mainPath string
	incPath  string
}

const incFixture = `Host inc-a
  HostName 10.0.1.1
  User ia
  IdentityFile /example/id_inc_a

Host deploy-inc
  HostName 10.0.1.2
  User deploy
`

func newIncEnv(t *testing.T) incEnv {
	t.Helper()
	return newIncEnvWith(t, incFixture, "")
}

// newIncEnvWith writes the included file with incBody and a main file that
// Includes it first, followed by the standard main hosts plus mainExtra.
func newIncEnvWith(t *testing.T, incBody, mainExtra string) incEnv {
	t.Helper()
	dir := t.TempDir()
	incDir := filepath.Join(t.TempDir(), "inc")
	if err := os.MkdirAll(incDir, 0o700); err != nil {
		t.Fatal(err)
	}
	incPath := filepath.Join(incDir, "extra.conf")
	writeTemp(t, incPath, incBody)
	mainPath := filepath.Join(dir, "config")
	writeTemp(t, mainPath, "Include "+incPath+"\n\n"+
		"Host main-1\n  HostName 10.0.0.1\n  User m\n  IdentityFile /example/id_main\n\n"+
		"Host deploy-main\n  HostName 10.0.0.2\n  User deploy\n"+mainExtra)
	return incEnv{a: NewAppWithPath(mainPath), dir: dir, incDir: incDir, mainPath: mainPath, incPath: incPath}
}

func writeTemp(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

type fileState struct {
	data    string
	modTime time.Time
}

// snapshotDirs records bytes and mtime of every file in dirs, so a rejected
// write is detected whether it changed content, touched a file, or created a
// new one (backup, temp file, sidecar).
func snapshotDirs(t *testing.T, dirs ...string) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			out[p] = fileState{data: string(data), modTime: fi.ModTime()}
		}
	}
	return out
}

func (e incEnv) wantIncludedErr(name string) string {
	return fmt.Sprintf("host %q is defined in %s (included), which sshm cannot edit yet", name, e.incPath)
}

func hasHost(hosts []domain.Host, name string) bool {
	return slices.ContainsFunc(hosts, func(h domain.Host) bool { return h.Name == name })
}

// ---- read paths -----------------------------------------------------------

func TestReadPathsSeeIncludedHosts(t *testing.T) {
	e := newIncEnv(t)

	hosts, err := e.a.ListHosts("", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"inc-a", "deploy-inc", "main-1", "deploy-main"} {
		if !hasHost(hosts, n) {
			t.Errorf("ListHosts missing %q", n)
		}
	}
	for _, h := range hosts {
		if h.SourceFile == "" {
			t.Errorf("host %q has no SourceFile", h.Name)
		}
		if (h.Name == "inc-a" || h.Name == "deploy-inc") != (h.SourceFile == e.incPath) {
			t.Errorf("host %q SourceFile = %q", h.Name, h.SourceFile)
		}
	}

	byGroup, err := e.a.ListHosts("deploy", false)
	if err != nil || len(byGroup) != 2 {
		t.Errorf("ListHosts(deploy) = %v, %v; want both deploy hosts", byGroup, err)
	}

	groups, err := e.a.ListGroups()
	if err != nil || len(groups["deploy"]) != 2 {
		t.Errorf("ListGroups()[deploy] = %v, %v", groups["deploy"], err)
	}

	names, err := e.a.HostNamesForCompletion("inc-a")
	if err != nil || !slices.Contains(names, "inc-a") {
		t.Errorf("completion = %v, %v; want inc-a", names, err)
	}

	eff, err := e.a.Dump("inc-a")
	if err != nil || eff.HostName != "10.0.1.1" || eff.User != "ia" {
		t.Errorf("Dump(inc-a) = %+v, %v", eff, err)
	}

	states, err := e.a.ListGroupsState()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, gs := range states {
		if gs.Group == "deploy" {
			total = gs.Total
		}
	}
	if total != 2 {
		t.Errorf("ListGroupsState deploy total = %d, want 2", total)
	}

	fw, err := e.a.ListForwards("inc-a")
	if err != nil || fw.Name != "inc-a" {
		t.Errorf("ListForwards(inc-a) = %+v, %v", fw, err)
	}

	if err := e.a.CheckHostName("inc-a"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("CheckHostName(inc-a) = %v, want 'already exists'", err)
	}
}

func TestSnapshotMarksIncludedHosts(t *testing.T) {
	e := newIncEnv(t)
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range snap.Hosts {
		got[h.Name] = h.Included
	}
	want := map[string]bool{"inc-a": true, "deploy-inc": true, "main-1": false, "deploy-main": false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Included flags = %v, want %v", got, want)
	}
}

func TestValidateCoversIncludedFiles(t *testing.T) {
	// main-1 is defined in both files; the include also has a bad forward.
	// The Include line comes first, so the included block is the first
	// definition and the warning lands on the main file's later block.
	e := newIncEnvWith(t, incFixture+"\nHost main-1\n  HostName 10.0.5.5\n  LocalForward notaport\n", "")
	issues, err := e.a.Validate()
	if err != nil {
		t.Fatal(err)
	}
	var cross, badFwd bool
	for _, i := range issues {
		switch i.Rule {
		case "dup-host-cross-file":
			cross = true
			if i.Severity != domain.SeverityWarning || i.HostName != "main-1" || i.File != "" ||
				!strings.Contains(i.Message, e.incPath) {
				t.Errorf("cross-file issue = %+v", i)
			}
		case "duplicate-host":
			t.Errorf("cross-file duplicate must not be an error: %+v", i)
		case "invalid-forward":
			badFwd = true
			if i.File != e.incPath {
				t.Errorf("invalid-forward in included file has File %q, want %q", i.File, e.incPath)
			}
		}
		if i.HostName == "deploy-main" && i.File != "" {
			t.Errorf("main-file issue carries File %q", i.File)
		}
	}
	if !cross || !badFwd {
		t.Errorf("want dup-host-cross-file and invalid-forward issues, got %+v", issues)
	}
}

func TestValidateAndSnapshotReportIncludeWarnings(t *testing.T) {
	e := newIncEnvWith(t, incFixture, "\nInclude /example/%h.conf\n")
	issues, err := e.a.Validate()
	if err != nil {
		t.Fatal(err)
	}
	has := func(is []domain.Issue) bool {
		return slices.ContainsFunc(is, func(i domain.Issue) bool {
			return i.Rule == "include" && i.Severity == domain.SeverityWarning && strings.Contains(i.Message, "not supported")
		})
	}
	if !has(issues) {
		t.Errorf("Validate: no include warning in %+v", issues)
	}
	snap, err := e.a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !has(snap.Issues) {
		t.Errorf("Snapshot: no include warning in %+v", snap.Issues)
	}
}

func TestConnectAndCopyGateIncludedHosts(t *testing.T) {
	noExecPath(t)
	e := newIncEnv(t)

	// Not gated: lookup succeeds and Connect proceeds to the ssh lookup,
	// which fails because PATH is empty (it must NOT say "host not found").
	err := e.a.Connect("inc-a", nil)
	if err == nil || !strings.Contains(err.Error(), "ssh not found in PATH") {
		t.Errorf("Connect(inc-a) = %v, want to get as far as the ssh lookup", err)
	}
	remote, adHoc, err := e.a.resolveRemote("inc-a:/tmp/x", "/tmp/y")
	if err != nil || adHoc || remote != "inc-a:/tmp/x" {
		t.Errorf("resolveRemote(inc-a) = %q, adHoc=%v, %v; want a known host", remote, adHoc, err)
	}
	if err := e.a.Copy("inc-a:/tmp/x", "/tmp/y", "-a"); err == nil || !strings.Contains(err.Error(), "rsync not found") {
		t.Errorf("Copy(inc-a) = %v, want to get as far as the rsync lookup", err)
	}
	if err := e.a.RunForward("inc-a", domain.ForwardLocal, []string{"8080:localhost:80"}, false); err == nil || !strings.Contains(err.Error(), "ssh not found") {
		t.Errorf("RunForward(inc-a) = %v, want to get as far as the ssh lookup", err)
	}

	// Gated through the sidecar state file: the included member is refused.
	if err := writeGroupState(e.a.groupStatePath(), map[string]bool{"deploy": true}); err != nil {
		t.Fatal(err)
	}
	wantDisabledErr(t, "Connect(deploy-inc)", e.a.Connect("deploy-inc", nil))
	wantDisabledErr(t, "Copy(deploy-inc)", e.a.Copy("deploy-inc:/tmp/x", "/tmp/y", "-a"))
	wantDisabledErr(t, "RunForward(deploy-inc)",
		e.a.RunForward("deploy-inc", domain.ForwardLocal, []string{"8080:localhost:80"}, false))
	hosts, err := e.a.ListHosts("", false)
	if err != nil || hasHost(hosts, "deploy-inc") || hasHost(hosts, "deploy-main") {
		t.Errorf("gated included host still listed: %v %v", hosts, err)
	}
	if !hasHost(hosts, "inc-a") {
		t.Errorf("ungated included host vanished")
	}
	names, err := e.a.HostNamesForCompletion("")
	if err != nil || slices.Contains(names, "deploy-inc") {
		t.Errorf("completion offers gated included host: %v %v", names, err)
	}
}

func TestSignCertFindsIncludedHost(t *testing.T) {
	noExecPath(t)
	e := newIncEnv(t)
	ca := filepath.Join(e.dir, "ca")
	writeTemp(t, ca, "placeholder\n")
	// inc-a's IdentityFile (/example/id_inc_a) has no .pub: the error proves
	// the host was found in the included file and its IdentityFile used.
	_, err := e.a.SignCert(SignOpts{HostName: "inc-a", CAKey: ca})
	if err == nil || !strings.Contains(err.Error(), "/example/id_inc_a.pub") {
		t.Errorf("SignCert(inc-a) = %v", err)
	}
}

// Relative Include paths resolve against the passwd home's .ssh, which every
// test in this package overrides (TestMain).
func TestRelativeIncludeUsesOverriddenHome(t *testing.T) {
	if err := os.MkdirAll(filepath.Join(testHome, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, filepath.Join(testHome, ".ssh", "rel-test.conf"), "Host rel-host\n  HostName 10.0.7.7\n")
	t.Cleanup(func() { os.Remove(filepath.Join(testHome, ".ssh", "rel-test.conf")) })
	a := newTestApp(t, "Include rel-test.conf\n\nHost m\n  HostName 10.0.0.1\n")
	hosts, err := a.ListHosts("", true)
	if err != nil || !hasHost(hosts, "rel-host") {
		t.Fatalf("hosts = %v, %v", hosts, err)
	}
}

// ---- write guard ----------------------------------------------------------

func TestWritesRejectIncludedOnlyHosts(t *testing.T) {
	noExecPath(t)
	fwd := []string{"8080:localhost:80"}
	ops := []struct {
		name string
		host string // the included host the error must name
		run  func(a *App) error
	}{
		{"EditHost", "inc-a", func(a *App) error { return a.EditHost("inc-a", map[string]string{"user": "x"}) }},
		{"DeleteHost", "inc-a", func(a *App) error { return a.DeleteHost("inc-a") }},
		{"DuplicateHost source", "inc-a", func(a *App) error { return a.DuplicateHost("inc-a", "inc-copy") }},
		{"DuplicateHost new name", "inc-a", func(a *App) error { return a.DuplicateHost("main-1", "inc-a") }},
		{"AddHost existing name", "inc-a", func(a *App) error { return a.AddHost(domain.Host{Name: "inc-a", HostName: "10.9.9.9"}) }},
		{"AddForward", "inc-a", func(a *App) error { return a.AddForward("inc-a", domain.ForwardLocal, fwd) }},
		{"ClearForwards", "inc-a", func(a *App) error { return a.ClearForwards("inc-a") }},
		{"RunForward --save", "inc-a", func(a *App) error { return a.RunForward("inc-a", domain.ForwardLocal, fwd, true) }},
		{"ClearCertificateFile", "inc-a", func(a *App) error { return a.ClearCertificateFile("inc-a") }},
		{"CheckEdit", "inc-a", func(a *App) error { _, err := a.CheckEdit("inc-a", map[string]string{"user": "x"}); return err }},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			e := newIncEnv(t)
			before := snapshotDirs(t, e.dir, e.incDir)

			err := op.run(e.a)
			if err == nil || err.Error() != e.wantIncludedErr(op.host) {
				t.Fatalf("error = %v\nwant     %s", err, e.wantIncludedErr(op.host))
			}
			// Byte-stability: neither file changed, was touched, and no backup,
			// temp or sidecar file appeared next to either.
			if after := snapshotDirs(t, e.dir, e.incDir); !reflect.DeepEqual(before, after) {
				t.Fatalf("files changed after a rejected write:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// Unknown hosts keep their old "not found" behavior (no included file owns them).
func TestWriteGuardLeavesUnknownHostsAlone(t *testing.T) {
	e := newIncEnv(t)
	if err := e.a.EditHost("nope", map[string]string{"user": "x"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("EditHost(nope) = %v", err)
	}
}

func TestMainFileHostsStayEditableAndKeepInclude(t *testing.T) {
	e := newIncEnv(t)
	incBefore := snapshotDirs(t, e.incDir)

	if err := e.a.EditHost("main-1", map[string]string{"user": "changed"}); err != nil {
		t.Fatal(err)
	}
	if err := e.a.AddHost(domain.Host{Name: "new-host", HostName: "10.0.0.50", User: "u"}); err != nil {
		t.Fatal(err)
	}
	if err := e.a.DuplicateHost("main-1", "main-copy"); err != nil {
		t.Fatal(err)
	}
	if err := e.a.AddForward("main-1", domain.ForwardLocal, []string{"8080:localhost:80"}); err != nil {
		t.Fatal(err)
	}
	if err := e.a.DeleteHost("main-copy"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(e.mainPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Include "+e.incPath+"\n") {
		t.Errorf("Include line lost from the main file:\n%s", data)
	}
	if strings.Contains(string(data), "inc-a") {
		t.Errorf("included host was flattened into the main file:\n%s", data)
	}
	if after := snapshotDirs(t, e.incDir); !reflect.DeepEqual(incBefore, after) {
		t.Errorf("included file changed by writes to main-file hosts")
	}
	// Still readable through the merged view.
	h, err := e.a.Dump("main-1")
	if err != nil || h.User != "changed" {
		t.Errorf("Dump(main-1) = %+v, %v", h, err)
	}
	if hosts, _ := e.a.ListHosts("", true); !hasHost(hosts, "inc-a") || !hasHost(hosts, "new-host") {
		t.Errorf("hosts after writes: %v", hosts)
	}
}

// A name defined in both files is editable: the write targets the main block.
func TestHostInBothFilesIsEditable(t *testing.T) {
	e := newIncEnvWith(t, incFixture+"\nHost main-1\n  HostName 10.0.5.5\n", "")
	incBefore := snapshotDirs(t, e.incDir)
	if err := e.a.EditHost("main-1", map[string]string{"user": "changed"}); err != nil {
		t.Fatal(err)
	}
	if after := snapshotDirs(t, e.incDir); !reflect.DeepEqual(incBefore, after) {
		t.Errorf("included file changed")
	}
	if data, _ := os.ReadFile(e.mainPath); !strings.Contains(string(data), "User changed") {
		t.Errorf("main file not edited:\n%s", data)
	}
}

func TestGroupDisableEnableRefuseWithIncludedMembers(t *testing.T) {
	e := newIncEnv(t)
	before := snapshotDirs(t, e.dir, e.incDir)

	err := e.a.DisableGroup("deploy")
	if err == nil {
		t.Fatal("DisableGroup(deploy) succeeded although deploy-inc is in an included file")
	}
	wantMsg := fmt.Sprintf(`cannot disable group "deploy": host "deploy-inc" is defined in %s (included), which sshm cannot edit yet`, e.incPath)
	if err.Error() != wantMsg {
		t.Errorf("error = %q\nwant    %q", err, wantMsg)
	}
	if after := snapshotDirs(t, e.dir, e.incDir); !reflect.DeepEqual(before, after) {
		t.Errorf("files changed after refused DisableGroup (incl. sidecar):\nbefore %v\nafter  %v", before, after)
	}

	// EnableGroup refuses the same way, even with a recorded sidecar state.
	if err := writeGroupState(e.a.groupStatePath(), map[string]bool{"deploy": true}); err != nil {
		t.Fatal(err)
	}
	before = snapshotDirs(t, e.dir, e.incDir)
	err = e.a.EnableGroup("deploy")
	if err == nil || !strings.Contains(err.Error(), `cannot enable group "deploy"`) || !strings.Contains(err.Error(), e.incPath) {
		t.Errorf("EnableGroup error = %v", err)
	}
	if after := snapshotDirs(t, e.dir, e.incDir); !reflect.DeepEqual(before, after) {
		t.Errorf("files changed after refused EnableGroup")
	}
}

// A group that lives entirely in the main file still disables and enables,
// and the Include line survives the rewrite.
func TestGroupDisableStillWorksForMainOnlyGroup(t *testing.T) {
	e := newIncEnv(t)
	incBefore := snapshotDirs(t, e.incDir)
	if err := e.a.DisableGroup("main"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(e.mainPath)
	if !strings.Contains(string(data), domain.DisabledMarkerStart("main")) || !strings.Contains(string(data), "Include "+e.incPath) {
		t.Errorf("unexpected main file after disable:\n%s", data)
	}
	if err := e.a.EnableGroup("main"); err != nil {
		t.Fatal(err)
	}
	if after := snapshotDirs(t, e.incDir); !reflect.DeepEqual(incBefore, after) {
		t.Errorf("included file changed")
	}
}
