package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestMain points the passwd-home lookup at an empty temp dir for every test
// in this package, so nothing here can ever read the real ~/.ssh. Tests that
// need a specific fake home call setHome.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sshm-config-home-")
	if err != nil {
		panic(err)
	}
	homeDir = func() string { return dir }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// setHome overrides the passwd home for one test.
func setHome(t *testing.T, dir string) {
	t.Helper()
	prev := homeDir
	homeDir = func() string { return dir }
	t.Cleanup(func() { homeDir = prev })
}

// write creates path (and parents) with content, mode 0600.
func write(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// hostNames returns "name@basename(file)" for each merged host.
func loadedHosts(l *Loaded) []string {
	var out []string
	for _, h := range l.Hosts {
		out = append(out, h.Name+"@"+filepath.Base(h.SourceFile))
	}
	return out
}

func TestExpandInclude(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	abs := t.TempDir()

	write(t, filepath.Join(home, "tilde.conf"), "")
	write(t, filepath.Join(home, ".ssh", "rel.conf"), "")
	write(t, filepath.Join(home, ".ssh", "conf.d", "b.conf"), "")
	write(t, filepath.Join(home, ".ssh", "conf.d", "a.conf"), "")
	write(t, filepath.Join(home, ".ssh", "conf.d", "c.conf"), "")
	write(t, filepath.Join(home, ".ssh", "conf.d", "skip.txt"), "")
	if err := os.MkdirAll(filepath.Join(home, ".ssh", "conf.d", "dir.conf"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(abs, "abs.conf"), "")

	j := filepath.Join
	tests := []struct {
		name     string
		pattern  string
		want     []string
		wantWarn string // substring; "" means no warning
	}{
		{"tilde slash uses passwd home", "~/tilde.conf", []string{j(home, "tilde.conf")}, ""},
		{"relative is under home/.ssh", "rel.conf", []string{j(home, ".ssh", "rel.conf")}, ""},
		{"absolute", j(abs, "abs.conf"), []string{j(abs, "abs.conf")}, ""},
		{"glob is sorted, dirs and non-matches dropped", "conf.d/*.conf",
			[]string{j(home, ".ssh", "conf.d", "a.conf"), j(home, ".ssh", "conf.d", "b.conf"), j(home, ".ssh", "conf.d", "c.conf")}, ""},
		{"tilde glob", "~/.ssh/conf.d/[ab].conf",
			[]string{j(home, ".ssh", "conf.d", "a.conf"), j(home, ".ssh", "conf.d", "b.conf")}, ""},
		{"missing file is silent", "nope.conf", nil, ""},
		{"empty glob is silent", "~/.ssh/nothing/*.conf", nil, ""},
		{"percent token skipped with warning", "~/.ssh/%h.conf", nil, "not supported"},
		{"dollar token skipped with warning", "$HOME/.ssh/x.conf", nil, "not supported"},
		{"braced env skipped with warning", "${HOME}/x", nil, "not supported"},
		{"~user skipped with warning", "~bob/x.conf", nil, "~user"},
		{"negated set, as ssh reads it", "conf.d/[!ab].conf", []string{j(home, ".ssh", "conf.d", "c.conf")}, ""},
		{"caret is an ordinary set member", "conf.d/[^ab].conf",
			[]string{j(home, ".ssh", "conf.d", "a.conf"), j(home, ".ssh", "conf.d", "b.conf")}, ""},
		{"unbalanced bracket is a literal, as for ssh", "conf.d/[", nil, ""},
		{"character class is not followed", "conf.d/[[:alpha:]].conf", nil, "character class"},
		{"relative .. is not resolved lexically", "nodir/../rel.conf", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warn := ExpandInclude(tt.pattern)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("paths = %v, want %v", got, tt.want)
			}
			if tt.wantWarn == "" && warn != "" {
				t.Errorf("unexpected warning %q", warn)
			}
			if tt.wantWarn != "" && !strings.Contains(warn, tt.wantWarn) {
				t.Errorf("warning = %q, want it to contain %q", warn, tt.wantWarn)
			}
		})
	}
}

// "~" must resolve through the passwd-home lookup, never through $HOME.
func TestExpandIncludeIgnoresHOMEEnv(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("HOME", t.TempDir())
	write(t, filepath.Join(home, "x.conf"), "")
	got, _ := ExpandInclude("~/x.conf")
	if len(got) != 1 || got[0] != filepath.Join(home, "x.conf") {
		t.Fatalf("got %v, want the file under the overridden passwd home", got)
	}
}

func TestParseIncludeLine(t *testing.T) {
	tests := []struct {
		line string
		want []string
		ok   bool
	}{
		{"Include /a/b.conf", []string{"/a/b.conf"}, true},
		{"include /a/b.conf", []string{"/a/b.conf"}, true},
		{"INCLUDE\t/a/b.conf", []string{"/a/b.conf"}, true},
		{"Include /a /b /c", []string{"/a", "/b", "/c"}, true},
		{"Include=/a/b.conf", []string{"/a/b.conf"}, true},
		{"Include = /a/b.conf", []string{"/a/b.conf"}, true},
		{`Include "/a b/c.conf"`, []string{"/a b/c.conf"}, true},
		{`Include "/a b/c.conf" '/d e/f' /g`, []string{"/a b/c.conf", "/d e/f", "/g"}, true},
		{"Include /a # trailing comment", []string{"/a"}, true},
		{"Include", nil, false},
		{"Include   ", nil, false},
		{"IncludeFoo /a", nil, false},
		{"# Include /a", nil, false},
		{"Host include", nil, false},
		{"HostName include", nil, false},
	}
	for _, tt := range tests {
		got, ok := parseIncludeLine(strings.TrimSpace(tt.line))
		if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseIncludeLine(%q) = %v, %v; want %v, %v", tt.line, got, ok, tt.want, tt.ok)
		}
	}
}

func TestLoadIncludeAtTop(t *testing.T) {
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.1\n")
	main := write(t, filepath.Join(dir, "config"), "Include "+inc+"\n\nHost main-1\n  HostName 10.0.0.2\n")

	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"inc-1@inc.conf", "main-1@config"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
	if len(l.Files) != 2 || l.Files[0].Path != main || l.Files[1].Path != inc {
		t.Fatalf("files = %+v", l.Files)
	}
	if l.MainPath() != main {
		t.Fatalf("MainPath = %q", l.MainPath())
	}
	if len(l.Warnings) != 0 {
		t.Fatalf("warnings: %v", l.Warnings)
	}
	for _, h := range l.Hosts {
		if !filepath.IsAbs(h.SourceFile) {
			t.Errorf("host %s: SourceFile %q is not absolute", h.Name, h.SourceFile)
		}
	}
}

func TestLoadIncludeAfterHostStar(t *testing.T) {
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.1\n")
	main := write(t, filepath.Join(dir, "config"),
		"Host *\n  User fallback\n\nInclude "+inc+"\n\nHost main-1\n  HostName 10.0.0.2\n")

	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	// The included host is inlined at the Include line: after Host *, before main-1.
	if want := []string{"*@config", "inc-1@inc.conf", "main-1@config"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
}

func TestLoadIncludeAtEnd(t *testing.T) {
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.1\n")
	main := write(t, filepath.Join(dir, "config"), "Host main-1\n  HostName 10.0.0.2\n\nInclude "+inc+"\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"main-1@config", "inc-1@inc.conf"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
}

// An Include inside a Host block is conditional in ssh; the read model still
// follows it (documented in Load).
func TestLoadIncludeInsideHostBlockIsFollowed(t *testing.T) {
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.1\n")
	main := write(t, filepath.Join(dir, "config"),
		"Host main-1\n  HostName 10.0.0.2\n  Include "+inc+"\n\nHost main-2\n  HostName 10.0.0.3\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"main-1@config", "inc-1@inc.conf", "main-2@config"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
}

func TestLoadNestedInclude(t *testing.T) {
	dir := t.TempDir()
	nested := write(t, filepath.Join(dir, "nested.conf"), "Host nested-1\n  HostName 10.0.0.3\n")
	inc := write(t, filepath.Join(dir, "inc.conf"),
		"Include "+nested+"\n\nHost inc-1\n  HostName 10.0.0.1\n")
	main := write(t, filepath.Join(dir, "config"), "Include "+inc+"\n\nHost main-1\n  HostName 10.0.0.2\n")

	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nested-1@nested.conf", "inc-1@inc.conf", "main-1@config"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
	if len(l.Files) != 3 || l.Files[1].Path != inc || l.Files[2].Path != nested {
		t.Fatalf("files not in evaluation order: %+v", l.Files)
	}
}

func TestLoadCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.conf")
	b := filepath.Join(dir, "b.conf")
	main := filepath.Join(dir, "config")
	write(t, a, "Include "+b+"\nHost a-1\n  HostName 10.0.0.1\n")
	write(t, b, "Include "+a+"\nInclude "+main+"\nHost b-1\n  HostName 10.0.0.2\n")
	write(t, main, "Include "+a+"\n\nHost main-1\n  HostName 10.0.0.3\n")

	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"b-1@b.conf", "a-1@a.conf", "main-1@config"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
	cycles := 0
	for _, w := range l.Warnings {
		if strings.Contains(w, "cycle") {
			cycles++
		}
	}
	if cycles != 2 {
		t.Fatalf("want 2 cycle warnings (b->a, b->main), got %v", l.Warnings)
	}
}

func TestLoadSelfInclude(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "config")
	write(t, main, "Include "+main+"\nHost main-1\n  HostName 10.0.0.1\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Hosts) != 1 || len(l.Warnings) != 1 || !strings.Contains(l.Warnings[0], "cycle") {
		t.Fatalf("hosts=%v warnings=%v", loadedHosts(l), l.Warnings)
	}
}

func TestLoadDepthLimit(t *testing.T) {
	dir := t.TempDir()
	const n = 20
	main := filepath.Join(dir, "f0.conf")
	for i := 0; i < n; i++ {
		body := fmt.Sprintf("Host h%d\n  HostName 10.0.0.1\n", i)
		if i+1 < n {
			body = fmt.Sprintf("Include %s\n\n", filepath.Join(dir, fmt.Sprintf("f%d.conf", i+1))) + body
		}
		write(t, filepath.Join(dir, fmt.Sprintf("f%d.conf", i)), body)
	}
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	// Main is depth 0; files up to depth 16 are read (f0..f16 = 17 files).
	if len(l.Files) != maxIncludeDepth+1 {
		t.Fatalf("read %d files, want %d", len(l.Files), maxIncludeDepth+1)
	}
	if len(l.Warnings) != 1 || !strings.Contains(l.Warnings[0], "depth") {
		t.Fatalf("warnings = %v, want one depth warning", l.Warnings)
	}
}

func TestLoadMissingIncludeIsSilent(t *testing.T) {
	dir := t.TempDir()
	main := write(t, filepath.Join(dir, "config"),
		"Include "+filepath.Join(dir, "does-not-exist.conf")+"\nInclude "+filepath.Join(dir, "nothing", "*.conf")+"\n\nHost main-1\n  HostName 10.0.0.1\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Hosts) != 1 || len(l.Warnings) != 0 {
		t.Fatalf("hosts=%v warnings=%v", loadedHosts(l), l.Warnings)
	}
}

func TestLoadMainMissingIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent")); err == nil || !strings.Contains(err.Error(), "read config") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadMainUnparsableIsError(t *testing.T) {
	main := write(t, filepath.Join(t.TempDir(), "config"),
		"# sshm disabled group=x start\n# Host a\n")
	if _, err := Load(main); err == nil || !strings.Contains(err.Error(), "parse config") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadUnparsableIncludeIsWarning(t *testing.T) {
	dir := t.TempDir()
	bad := write(t, filepath.Join(dir, "bad.conf"), "# sshm disabled group=x start\n# Host a\n")
	main := write(t, filepath.Join(dir, "config"), "Include "+bad+"\n\nHost main-1\n  HostName 10.0.0.1\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Hosts) != 1 || len(l.Warnings) != 1 || !strings.Contains(l.Warnings[0], "cannot parse") {
		t.Fatalf("hosts=%v warnings=%v", loadedHosts(l), l.Warnings)
	}
}

func TestLoadQuotedAndMultiplePatterns(t *testing.T) {
	dir := t.TempDir()
	spaced := write(t, filepath.Join(dir, "with space", "s.conf"), "Host spaced\n  HostName 10.0.0.1\n")
	one := write(t, filepath.Join(dir, "one.conf"), "Host one\n  HostName 10.0.0.2\n")
	write(t, filepath.Join(dir, "conf.d", "2-b.conf"), "Host glob-b\n  HostName 10.0.0.4\n")
	write(t, filepath.Join(dir, "conf.d", "1-a.conf"), "Host glob-a\n  HostName 10.0.0.3\n")
	main := write(t, filepath.Join(dir, "config"),
		fmt.Sprintf("Include %q %s %s\n\nHost main-1\n  HostName 10.0.0.9\n", spaced, one, filepath.Join(dir, "conf.d", "*.conf")))

	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"spaced@s.conf", "one@one.conf", "glob-a@1-a.conf", "glob-b@2-b.conf", "main-1@config"}
	if !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
}

func TestLoadKeywordForms(t *testing.T) {
	dir := t.TempDir()
	a := write(t, filepath.Join(dir, "a.conf"), "Host a\n  HostName 10.0.0.1\n")
	b := write(t, filepath.Join(dir, "b.conf"), "Host b\n  HostName 10.0.0.2\n")
	c := write(t, filepath.Join(dir, "c.conf"), "Host c\n  HostName 10.0.0.3\n")
	main := write(t, filepath.Join(dir, "config"),
		"include "+a+"\nInclude="+b+"\nINCLUDE = \""+c+"\"\n\nHost m\n  HostName 10.0.0.9\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a@a.conf", "b@b.conf", "c@c.conf", "m@config"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
}

func TestLoadRelativeIncludeResolvesUnderPasswdHomeSSH(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	write(t, filepath.Join(home, ".ssh", "rel.conf"), "Host rel-1\n  HostName 10.0.0.1\n")
	write(t, filepath.Join(home, "tilde.conf"), "Host tilde-1\n  HostName 10.0.0.2\n")
	// The main file lives elsewhere: relative means <home>/.ssh, not its own dir.
	dir := t.TempDir()
	write(t, filepath.Join(dir, "rel.conf"), "Host decoy\n  HostName 10.0.0.9\n")
	main := write(t, filepath.Join(dir, "config"), "Include rel.conf ~/tilde.conf\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"rel-1@rel.conf", "tilde-1@tilde.conf"}; !reflect.DeepEqual(loadedHosts(l), want) {
		t.Fatalf("hosts = %v, want %v", loadedHosts(l), want)
	}
}

func TestLoadTokenIncludeWarns(t *testing.T) {
	dir := t.TempDir()
	main := write(t, filepath.Join(dir, "config"), "Include /etc/%h.conf ${X}/y\n\nHost m\n  HostName 10.0.0.1\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Warnings) != 2 || !strings.Contains(l.Warnings[0], "config:1:") {
		t.Fatalf("warnings = %v", l.Warnings)
	}
}

func TestLoadRepeatedIncludeIsReadOnce(t *testing.T) {
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.1\n")
	main := write(t, filepath.Join(dir, "config"), "Include "+inc+"\nInclude "+inc+"\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Hosts) != 1 || len(l.Warnings) != 1 || !strings.Contains(l.Warnings[0], "already included") {
		t.Fatalf("hosts=%v warnings=%v", loadedHosts(l), l.Warnings)
	}
}

// An Include line inside a disabled-group region is commented-out text and
// must never be followed.
func TestLoadIgnoresIncludeInsideDisabledRegion(t *testing.T) {
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "Host inc-1\n  HostName 10.0.0.1\n")
	main := write(t, filepath.Join(dir, "config"),
		"# sshm disabled group=g start\n# Host g-1\n#   HostName 10.0.0.5\nInclude "+inc+"\n# sshm disabled group=g end\n\nHost m\n  HostName 10.0.0.9\n")
	l, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range l.Hosts {
		if h.Name == "inc-1" {
			t.Fatalf("followed an Include inside a disabled region: %v", loadedHosts(l))
		}
	}
}
