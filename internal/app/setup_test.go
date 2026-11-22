package app

// Black-box tests for `sshm setup` (PLAN-p3-p4.md section 3, clauses S1-S10)
// and for the managed-mode predicate (section 1). Every fixture lives in a temp
// dir with absolute Include paths; `ssh -F <main> -G` is the oracle.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

const sxMain = `# my ssh config
Host web-1
  HostName 10.0.0.1
  User alice

Host db-1
  HostName 10.0.0.2
  Port 2222

Host *
  User fallback
  ServerAliveInterval 30
`

var sxHosts = []string{"web-1", "db-1"}

// sxActions is the full action list of a first setup on a fresh directory.
func sxActions(e *mgEnv) []string {
	return []string{
		"create " + filepath.Dir(e.managed) + " (0700)",
		"create " + e.managed + " (0600)",
		"insert Include line at line 1 of " + e.main,
	}
}

func sxInclude(managed string) string { return "Include " + managed + "\n" }

// ---- ManagedPath / ManagedActive (section 1) --------------------------------

// Characterization: already true for the skeleton.
func TestManagedPath_IsConfigDSshmConf(t *testing.T) {
	t.Parallel()
	a := NewAppWithPath("/some/dir/config")
	if got, want := a.ManagedPath(), "/some/dir/config.d/sshm.conf"; got != want {
		t.Errorf("ManagedPath = %q, want %q", got, want)
	}
}

func TestManagedActive(t *testing.T) {
	t.Parallel()
	const managedBody = mgManagedHeader + "Host keep-1\n  HostName 10.0.0.60\n"
	cases := []struct {
		name, main, managed string
		want                bool
	}{
		{"no include at all", sxMain, managedBody, false},
		{"unconditional include above the first Host", "Include @M@\n" + sxMain, managedBody, true},
		{"include after comments", "# c\n\nInclude @M@\n\n" + sxMain, managedBody, true},
		{"include below a Host line", "Host web-1\n  HostName 10.0.0.1\nInclude @M@\n", managedBody, false},
		{"include below a Match line", "Match host x.example.com\n  User m\nInclude @M@\n", managedBody, false},
		{"directly after a bare Host *", "Host *\n  Include @M@\n\nHost web-1\n  HostName 10.0.0.1\n", managedBody, true},
		{"directly after Match all", "Match all\n  Include @M@\n\nHost web-1\n  HostName 10.0.0.1\n", managedBody, true},
		{"include of another file", "Include @D@/other.conf\n" + sxMain, managedBody, false},
		{"include of the managed file, file missing", "Include @M@\n" + sxMain, mgAbsent, false},
		{"glob that reaches the managed file", "Include @D@/config.d/*\n" + sxMain, managedBody, true},
		{"quoted lowercase include", "include \"@M@\"\n" + sxMain, managedBody, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, c.main, c.managed)
			mgWrite(t, filepath.Join(e.dir, "other.conf"), "Host other-1\n  HostName 10.0.0.61\n", 0o600)
			got, err := e.a.ManagedActive()
			mgRequireNoErr(t, err)
			if got != c.want {
				t.Errorf("ManagedActive = %v, want %v", got, c.want)
			}
		})
	}
}

// The "~/.ssh/config.d/sshm.conf" spelling counts when the main file is
// <home>/.ssh/config. Not parallel: it swaps the package-wide home lookup.
func TestManagedActive_TildeSpelling(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(config.SetHomeDirForTest(home))
	mgNoSSHOnPath(t)
	main := filepath.Join(home, ".ssh", "config")
	managed := filepath.Join(home, ".ssh", "config.d", "sshm.conf")
	mgWrite(t, main, "Include ~/.ssh/config.d/sshm.conf\n"+sxMain, 0o600)
	mgWrite(t, managed, mgManagedHeader, 0o600)
	got, err := NewAppWithPath(main).ManagedActive()
	mgRequireNoErr(t, err)
	if !got {
		t.Error("ManagedActive = false for an unconditional ~/ Include of the managed file")
	}
}

// ---- S1, S2, S3 (absolute form) ----------------------------------------------

func TestSetup_CreatesLayoutAndInsertsIncludeAtLineOne(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, sxMain, mgAbsent)
	res, err := e.a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if res.AlreadySetUp {
		t.Error("AlreadySetUp on a first run")
	}
	if !reflect.DeepEqual(res.Actions, sxActions(e)) {
		t.Errorf("Actions = %q\nwant      %q", res.Actions, sxActions(e))
	}

	// S1: layout and header.
	if fi, err := os.Stat(filepath.Dir(e.managed)); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("config.d: %v %v, want a directory with mode 0700", fi, err)
	}
	if m := mgMode(t, e.managed); m != 0o600 {
		t.Errorf("sshm.conf mode = %o, want 0600", m)
	}
	hdr := strings.Split(strings.TrimSpace(e.readManaged(t)), "\n")
	if len(hdr) != 2 || !strings.HasPrefix(hdr[0], "# Managed by sshm") || !strings.HasPrefix(hdr[1], "#") {
		t.Errorf("sshm.conf = %q, want a two-line comment header starting with '# Managed by sshm'", e.readManaged(t))
	}

	// S2/S3: exactly one new first line, absolute path (the main file is not <home>/.ssh/config).
	if got, want := e.readMain(t), sxInclude(e.managed)+sxMain; got != want {
		t.Errorf("main file:\n%s\nwant:\n%s", got, want)
	}
	if m := mgMode(t, e.main); m != 0o600 {
		t.Errorf("main mode = %o, want 0600 (unchanged)", m)
	}

	// S2: one backup of the main file, none of the new managed file.
	baks := mgBackupFiles(t, e.dir)
	if len(baks) != 1 || len(mgBackupWith(t, e.dir, sxMain)) != 1 {
		t.Errorf("backups = %v, want exactly one holding the original main bytes", baks)
	}

	active, err := e.a.ManagedActive()
	mgRequireNoErr(t, err)
	if !active {
		t.Error("ManagedActive = false after setup")
	}
}

func TestSetup_ExistingManagedFileIsNeverRewritten(t *testing.T) {
	t.Parallel()
	const own = "# my own header, not the sshm one\nHost keep-1\n  HostName 10.0.0.60\n  User keeper\n"
	t.Run("file exists", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, sxMain, own)
		before := e.snap(t)
		res, err := e.a.Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		if want := []string{"insert Include line at line 1 of " + e.main}; !reflect.DeepEqual(res.Actions, want) {
			t.Errorf("Actions = %q, want %q", res.Actions, want)
		}
		after := e.snap(t)
		if d := mgDiff(before, after, true); !reflect.DeepEqual(d, []string{"changed " + e.main}) {
			t.Errorf("diff = %v, want only the main file changed", d)
		}
		if got := e.readManaged(t); got != own {
			t.Errorf("sshm.conf was rewritten:\n%s", got)
		}
		if got := e.readMain(t); got != sxInclude(e.managed)+sxMain {
			t.Errorf("main file:\n%s", got)
		}
	})
	t.Run("config.d exists, sshm.conf does not", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, sxMain, mgAbsent)
		if err := os.MkdirAll(filepath.Dir(e.managed), 0o700); err != nil {
			t.Fatal(err)
		}
		res, err := e.a.Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		want := []string{"create " + e.managed + " (0600)", "insert Include line at line 1 of " + e.main}
		if !reflect.DeepEqual(res.Actions, want) {
			t.Errorf("Actions = %q, want %q", res.Actions, want)
		}
		if m := mgMode(t, e.managed); m != 0o600 {
			t.Errorf("sshm.conf mode = %o", m)
		}
	})
}

// S2: the Include line is the only change, whatever the main file looks like.
func TestSetup_OnlyTheIncludeLineIsAdded(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"no trailing newline":     "Host web-1\n  HostName 10.0.0.1",
		"leading comment":         "# first line is a comment\nHost web-1\n  HostName 10.0.0.1\n",
		"only comments":           "# nothing here\n# at all\n",
		"leading blank lines":     "\n\nHost web-1\n  HostName 10.0.0.1\n",
		"another Include":         "Include @D@/other.conf\nHost web-1\n  HostName 10.0.0.1\n",
		"tabs and odd spacing":    "Host\tweb-1\n\tHostName   10.0.0.1  \n\n\n\nHost *\n  User x\n",
		"trailing blank lines":    "Host web-1\n  HostName 10.0.0.1\n\n\n",
		"keyword=value form":      "Host web-1\n  HostName=10.0.0.1\n  User = alice\n",
		"non-ASCII in a comment":  "# café ☃\nHost web-1\n  HostName 10.0.0.1\n",
		"Host with inline remark": "Host web-1 # prod\n  HostName 10.0.0.1\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, body, mgAbsent)
			mgWrite(t, filepath.Join(e.dir, "other.conf"), "", 0o600)
			orig := e.readMain(t)
			_, err := e.a.Setup(SetupOptions{})
			mgRequireNoErr(t, err)
			if got, want := e.readMain(t), sxInclude(e.managed)+orig; got != want {
				t.Errorf("main file:\n%q\nwant:\n%q", got, want)
			}
			if baks := mgBackupWith(t, e.dir, orig); len(baks) != 1 {
				t.Errorf("backups holding the original: %v, want 1", baks)
			}
		})
	}
}

func TestSetup_KeepsMainFileModeAndSymlink(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o600, 0o644, 0o640} {
		t.Run(mode.String(), func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, sxMain, mgAbsent)
			if err := os.Chmod(e.main, mode); err != nil {
				t.Fatal(err)
			}
			_, err := e.a.Setup(SetupOptions{})
			mgRequireNoErr(t, err)
			if m := mgMode(t, e.main); m != mode {
				t.Errorf("main mode = %o, want %o", m, mode)
			}
			if got := e.readMain(t); got != sxInclude(e.managed)+sxMain {
				t.Errorf("main file:\n%s", got)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, mgAbsent, mgAbsent)
		real := filepath.Join(e.dir, "dotfiles", "config.real")
		mgWrite(t, real, sxMain, 0o640)
		if err := os.Symlink(real, e.main); err != nil {
			t.Fatal(err)
		}
		_, err := e.a.Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		fi, lerr := os.Lstat(e.main)
		if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("the main file is no longer a symlink: %v %v", fi, lerr)
		}
		if dest, _ := os.Readlink(e.main); dest != real {
			t.Errorf("symlink now points to %q, want %q", dest, real)
		}
		if got := mgRead(t, real); got != sxInclude(e.managed)+sxMain {
			t.Errorf("link target:\n%s", got)
		}
		if m := mgMode(t, real); m != 0o640 {
			t.Errorf("target mode = %o, want 0640", m)
		}
		if baks := mgBackupWith(t, e.dir, sxMain); len(baks) != 1 {
			t.Errorf("backups with the original bytes: %v", baks)
		}
	})
}

// ---- S3: the include text -----------------------------------------------------

// Not parallel: the home lookup is package-wide, and ssh is taken off PATH
// because ssh itself would resolve "~" to the real passwd home.
func TestSetup_IncludeTextIsTildeFormForTheHomeConfig(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(config.SetHomeDirForTest(home))
	mgNoSSHOnPath(t)
	main := filepath.Join(home, ".ssh", "config")
	mgWrite(t, main, sxMain, 0o600)
	a := NewAppWithPath(main)

	res, err := a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if res.AlreadySetUp {
		t.Error("AlreadySetUp on a first run")
	}
	want := "Include ~/.ssh/config.d/sshm.conf\n" + sxMain
	if got := mgRead(t, main); got != want {
		t.Errorf("main file:\n%s\nwant:\n%s", got, want)
	}
	if !mgExists(filepath.Join(home, ".ssh", "config.d", "sshm.conf")) {
		t.Error("managed file not created next to the main file")
	}
	if active, err := a.ManagedActive(); err != nil || !active {
		t.Errorf("ManagedActive = %v, %v after setup", active, err)
	}
	// A second run recognises the ~ spelling it wrote itself.
	res, err = a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if !res.AlreadySetUp || len(res.Actions) != 0 {
		t.Errorf("second run: %+v", res)
	}
}

func TestSetup_IncludeTextIsAbsoluteUnlessMainIsTheHomeConfig(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(config.SetHomeDirForTest(home))
	mgNoSSHOnPath(t)
	for _, rel := range []string{".ssh/conf", "other/.ssh/config", ".ssh/sub/config", "config", ".ssh/config.alt"} {
		t.Run(rel, func(t *testing.T) {
			main := filepath.Join(home, rel)
			mgWrite(t, main, sxMain, 0o600)
			managed := filepath.Join(filepath.Dir(main), "config.d", "sshm.conf")
			_, err := NewAppWithPath(main).Setup(SetupOptions{})
			mgRequireNoErr(t, err)
			if got, want := mgRead(t, main), "Include "+managed+"\n"+sxMain; got != want {
				t.Errorf("main file:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// ---- S4: idempotent -----------------------------------------------------------

func TestSetup_SecondRunChangesNothing(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, sxMain, mgAbsent)
	res, err := e.a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if res.AlreadySetUp {
		t.Fatal("first run reported AlreadySetUp")
	}
	e.backdate(t) // any later rewrite, even with identical bytes, shows up as an mtime change
	before := e.snap(t)
	for run := 2; run <= 3; run++ {
		res, err := e.a.Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		if !res.AlreadySetUp {
			t.Errorf("run %d: AlreadySetUp = false", run)
		}
		if len(res.Actions) != 0 {
			t.Errorf("run %d: Actions = %q, want none", run, res.Actions)
		}
		mgRequireUnchanged(t, before, e.snap(t))
	}
}

// ---- S5: existing includes --------------------------------------------------------

func TestSetup_ExistingUnconditionalIncludeCountsAsSetUp(t *testing.T) {
	t.Parallel()
	const managed = mgManagedHeader + "Host keep-1\n  HostName 10.0.0.60\n"
	cases := map[string]string{
		"absolute path above the first Host": "Include @M@\n" + sxMain,
		"after comments and blank lines":     "# top\n\n# more\nInclude @M@\n\n" + sxMain,
		"lowercase keyword, quoted path":     "include \"@M@\"\n" + sxMain,
		"glob that reaches the file":         "Include @D@/config.d/*\n" + sxMain,
		"directly after a bare Host *":       "Host *\n  Include @M@\n\nHost web-1\n  HostName 10.0.0.1\n",
		"directly after Match all":           "Match all\n  Include @M@\n\nHost web-1\n  HostName 10.0.0.1\n",
	}
	for name, body := range cases {
		for _, dry := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "", true: " (dry run)"}[dry], func(t *testing.T) {
				t.Parallel()
				e := newMgEnv(t, body, managed)
				before := e.snap(t)
				res, err := e.a.Setup(SetupOptions{DryRun: dry})
				mgRequireNoErr(t, err)
				if !res.AlreadySetUp || len(res.Actions) != 0 {
					t.Errorf("result = %+v, want AlreadySetUp and no actions", res)
				}
				mgRequireUnchanged(t, before, e.snap(t))
			})
		}
	}
}

func TestSetup_ExistingTildeIncludeCountsAsSetUp(t *testing.T) {
	home := t.TempDir()
	t.Cleanup(config.SetHomeDirForTest(home))
	mgNoSSHOnPath(t)
	main := filepath.Join(home, ".ssh", "config")
	managed := filepath.Join(home, ".ssh", "config.d", "sshm.conf")
	mgWrite(t, main, "Include ~/.ssh/config.d/sshm.conf\n"+sxMain, 0o600)
	mgWrite(t, managed, mgManagedHeader, 0o600)
	before := mgSnap(t, home)
	res, err := NewAppWithPath(main).Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if !res.AlreadySetUp || len(res.Actions) != 0 {
		t.Errorf("result = %+v", res)
	}
	mgRequireUnchanged(t, before, mgSnap(t, home))
}

func TestSetup_ConditionalIncludeIsAnErrorNamingTheLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, main string
		line       string
	}{
		{"below a Host line", "Host web-1\n  HostName 10.0.0.1\nInclude @M@\n", "3"},
		{"below two Host blocks", "# c\nHost a\n  User a\n\nHost b\n  User b\n\nInclude @M@\n", "8"},
		{"below a Match line", "Match host x.example.com\n  User m\nInclude @M@\n", "3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, c.main, mgManagedHeader+"Host keep-1\n  HostName 10.0.0.60\n")
			for _, dry := range []bool{false, true} {
				before := e.snap(t)
				_, err := e.a.Setup(SetupOptions{DryRun: dry})
				mgRequireErr(t, err)
				if !regexp.MustCompile(`(?i)(line |:)` + c.line + `\b`).MatchString(err.Error()) {
					t.Errorf("error %q does not name line %s", err, c.line)
				}
				if !strings.Contains(err.Error(), "above the first Host/Match") {
					t.Errorf("error %q does not say to move the Include above the first Host/Match", err)
				}
				mgRequireUnchanged(t, before, e.snap(t))
			}
		})
	}
}

// ---- S6: missing main file / directory --------------------------------------------

func TestSetup_MissingMainFileIsCreatedWithOnlyTheIncludeLine(t *testing.T) {
	t.Parallel()
	t.Run("directory exists", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, mgAbsent, mgAbsent)
		_, err := e.a.Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		if got := e.readMain(t); got != sxInclude(e.managed) {
			t.Errorf("main file = %q, want only the Include line", got)
		}
		if m := mgMode(t, e.main); m != 0o600 {
			t.Errorf("main mode = %o, want 0600", m)
		}
		if m := mgMode(t, e.managed); m != 0o600 {
			t.Errorf("managed mode = %o, want 0600", m)
		}
	})
	t.Run("directory missing too", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, mgAbsent, mgAbsent)
		fresh := filepath.Join(e.dir, "fresh-ssh")
		main := filepath.Join(fresh, "config")
		managed := filepath.Join(fresh, "config.d", "sshm.conf")
		res, err := NewAppWithPath(main).Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		for _, want := range []string{
			"create " + fresh + " (0700)",
			"create " + filepath.Dir(managed) + " (0700)",
			"create " + managed + " (0600)",
		} {
			found := false
			for _, a := range res.Actions {
				found = found || a == want
			}
			if !found {
				t.Errorf("Actions %q lack %q", res.Actions, want)
			}
		}
		for _, d := range []string{fresh, filepath.Dir(managed)} {
			if fi, err := os.Stat(d); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
				t.Errorf("%s: %v %v, want a directory with mode 0700", d, fi, err)
			}
		}
		if got := mgRead(t, main); got != sxInclude(managed) {
			t.Errorf("main file = %q, want only the Include line", got)
		}
		if m := mgMode(t, main); m != 0o600 {
			t.Errorf("main mode = %o, want 0600", m)
		}
	})
}

// ---- S7: verification --------------------------------------------------------------

// An existing sshm.conf with a Host * default changes what a main-file host
// resolves once it is included first: ssh -G differs, so setup must undo itself.
func TestSetup_RestoresMainWhenSSHResolvesDifferently(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, sxMain, mgManagedHeader+"Host *\n  User managedwide\n")
	if got := mgVal(mgSSHG(t, e.main, "db-1"), "user"); got != "fallback" {
		t.Fatalf("fixture: db-1 user = %q", got)
	}
	before := e.snap(t)
	_, err := e.a.Setup(SetupOptions{})
	mgRequireErr(t, err)
	mgRequireRestored(t, before, e.snap(t), e.main)
	if got := e.readMain(t); got != sxMain {
		t.Errorf("main file not restored byte-for-byte:\n%s", got)
	}
	if m := mgMode(t, e.main); m != 0o600 {
		t.Errorf("main mode = %o", m)
	}
	if got := mgVal(mgSSHG(t, e.main, "db-1"), "user"); got != "fallback" {
		t.Errorf("db-1 user = %q after the failed setup", got)
	}
}

// ssh already fails on the main file: setup returns an error and leaves nothing
// behind (no config.d, no sshm.conf, main unchanged).
func TestSetup_SSHErrorReturnsErrorAndLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	broken := "Host web-1\n  HostName 10.0.0.1\n\nHost *\n  KexAlgorithms no-such-kex-algorithm\n"
	e := newMgEnv(t, broken, mgAbsent)
	before := e.snap(t)
	_, err := e.a.Setup(SetupOptions{})
	mgRequireErr(t, err)
	mgRequireRestored(t, before, e.snap(t), e.main)
	if got := e.readMain(t); got != broken {
		t.Errorf("main file changed:\n%s", got)
	}
	if mgExists(filepath.Dir(e.managed)) {
		t.Error("config.d was left behind")
	}
}

// Extra robustness: config.d is a regular file, so the layout cannot be made.
func TestSetup_ConfigDBeingAFileIsAnErrorWithNoChange(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, sxMain, mgAbsent)
	mgWrite(t, filepath.Dir(e.managed), "i am a file\n", 0o600)
	before := e.snap(t)
	_, err := e.a.Setup(SetupOptions{})
	mgRequireErr(t, err)
	mgRequireRestored(t, before, e.snap(t), e.main)
	if got := e.readMain(t); got != sxMain {
		t.Errorf("main file changed:\n%s", got)
	}
}

func TestSetup_SkipsVerificationWhenSSHIsMissing(t *testing.T) {
	mgNoSSHOnPath(t)
	e := newMgEnv(t, sxMain, mgAbsent)
	res, err := e.a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if !mgNoteHas(res.Notes, "ssh") {
		t.Errorf("Notes = %q, want a note that verification was skipped because ssh is missing", res.Notes)
	}
	if got := e.readMain(t); got != sxInclude(e.managed)+sxMain {
		t.Errorf("main file:\n%s", got)
	}
	if m := mgMode(t, e.managed); m != 0o600 {
		t.Errorf("managed mode = %o", m)
	}
}

func TestSetup_SkipsVerificationAndNeverRunsMatchExec(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	t.Run("Match exec in the main file", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, sxMain+"\nMatch exec \"touch @D@/exec-ran\"\n  Compression no\n", mgAbsent)
		orig := e.readMain(t)
		res, err := e.a.Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		if !mgNoteHas(res.Notes, "exec") {
			t.Errorf("Notes = %q, want a note naming the Match exec line", res.Notes)
		}
		if mgExists(filepath.Join(e.dir, "exec-ran")) {
			t.Fatal("the Match exec command was run")
		}
		if got := e.readMain(t); got != sxInclude(e.managed)+orig {
			t.Errorf("main file:\n%s", got)
		}
	})
	t.Run("Match exec in an included file", func(t *testing.T) {
		t.Parallel()
		e := newMgEnv(t, "Include @D@/other.conf\n"+sxMain, mgAbsent)
		mgWrite(t, filepath.Join(e.dir, "other.conf"), strings.ReplaceAll("Match exec \"touch @D@/exec-ran\"\n  Compression no\n", "@D@", e.dir), 0o600)
		orig := e.readMain(t)
		res, err := e.a.Setup(SetupOptions{})
		mgRequireNoErr(t, err)
		if !mgNoteHas(res.Notes, "exec") {
			t.Errorf("Notes = %q, want a note naming the Match exec line", res.Notes)
		}
		if mgExists(filepath.Join(e.dir, "exec-ran")) {
			t.Fatal("the Match exec command was run")
		}
		if got := e.readMain(t); got != sxInclude(e.managed)+orig {
			t.Errorf("main file:\n%s", got)
		}
	})
}

// ---- S8 ---------------------------------------------------------------------------

func TestSetup_RefusesWhenAnIncludeCannotBeFollowed(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"% token":        "Include @D@/%h.conf\n" + sxMain,
		"~user path":     "Include ~nobody/x.conf\n" + sxMain,
		"token below it": sxMain + "\nInclude @D@/%h.conf\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newMgEnv(t, body, mgAbsent)
			before := e.snap(t)
			for _, dry := range []bool{false, true} {
				_, err := e.a.Setup(SetupOptions{DryRun: dry})
				mgRequireErr(t, err)
				if !strings.Contains(strings.ToLower(err.Error()), "include") {
					t.Errorf("error %q does not mention the Include", err)
				}
				mgRequireUnchanged(t, before, e.snap(t))
			}
		})
	}
}

// ---- S9 ---------------------------------------------------------------------------

func TestSetup_DryRunListsActionsAndChangesNothing(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, sxMain, mgAbsent)
	before := e.snap(t)
	dry, err := e.a.Setup(SetupOptions{DryRun: true})
	mgRequireNoErr(t, err)
	if dry.AlreadySetUp {
		t.Error("dry run reported AlreadySetUp")
	}
	if !reflect.DeepEqual(dry.Actions, sxActions(e)) {
		t.Errorf("dry-run Actions = %q, want %q", dry.Actions, sxActions(e))
	}
	mgRequireUnchanged(t, before, e.snap(t))
	if mgExists(filepath.Dir(e.managed)) || mgExists(e.backupDir()) {
		t.Error("dry run created config.d or sshm-backups")
	}

	// The real run does exactly what the dry run announced.
	real, err := e.a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	if !reflect.DeepEqual(real.Actions, dry.Actions) {
		t.Errorf("real Actions = %q, dry-run Actions = %q", real.Actions, dry.Actions)
	}
}

func TestSetup_DryRunOnMissingMainFileChangesNothing(t *testing.T) {
	t.Parallel()
	e := newMgEnv(t, mgAbsent, mgAbsent)
	before := e.snap(t)
	res, err := e.a.Setup(SetupOptions{DryRun: true})
	mgRequireNoErr(t, err)
	if len(res.Actions) == 0 {
		t.Error("dry run listed no actions for a missing main file")
	}
	mgRequireUnchanged(t, before, e.snap(t))
}

// ---- S10 --------------------------------------------------------------------------

func TestSetup_EndToEndManagedHostResolves(t *testing.T) {
	t.Parallel()
	mgNeedSSH(t)
	e := newMgEnv(t, sxMain, mgAbsent)
	before := mgSSHAll(t, e.main, sxHosts)

	_, err := e.a.Setup(SetupOptions{})
	mgRequireNoErr(t, err)
	// S7's promise, seen from outside: every existing host resolves as before.
	mgRequireSameResolution(t, e.main, before)

	f, ferr := os.OpenFile(e.managed, os.O_APPEND|os.O_WRONLY, 0)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if _, werr := f.WriteString("\nHost e2e-1\n  HostName 10.0.0.77\n  User e2e\n"); werr != nil {
		t.Fatal(werr)
	}
	f.Close()

	out := mgSSHG(t, e.main, "e2e-1")
	if got := mgVal(out, "hostname"); got != "10.0.0.77" {
		t.Errorf("hostname = %q, want 10.0.0.77 (managed host not found by ssh)", got)
	}
	// Managed values beat the main file's Host * default (the Include is first).
	if got := mgVal(out, "user"); got != "e2e" {
		t.Errorf("user = %q, want e2e", got)
	}
	// Defaults of the main file still fill what the managed host leaves open.
	if got := mgVal(out, "serveraliveinterval"); got != "30" {
		t.Errorf("serveraliveinterval = %q, want 30 from Host *", got)
	}
}
