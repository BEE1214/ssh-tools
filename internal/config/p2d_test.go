package config

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Tests for the P2d fix round. Same rules as the other test files: temp dirs
// only, ssh always with -F <temp file>, absolute Include paths.

// ---- Item 1: Include patterns are matched like ssh's glob(3) ----

// globFixture is a temp dir with a directory "d" of config files and a main
// file that Includes one pattern below d. File number i defines
//
//	Host gf-<i> glob-probe
//	  LocalForward <10000+i> localhost:1
//
// so one `ssh -G glob-probe` lists every file ssh read (LocalForward
// accumulates), and each file is also reachable through its own host name.
type globFixture struct {
	dir, main string
	files     []string
}

func newGlobFixture(t *testing.T, files []string) *globFixture {
	t.Helper()
	g := &globFixture{dir: t.TempDir(), files: files}
	g.main = filepath.Join(g.dir, "config")
	for i, f := range files {
		write(t, filepath.Join(g.dir, "d", f), fmt.Sprintf("Host gf-%d glob-probe\n  LocalForward %d localhost:1\n", i, 10000+i))
	}
	return g
}

// include makes the main file "Include <dir>/d/<pattern>".
func (g *globFixture) include(t *testing.T, pattern string) {
	t.Helper()
	write(t, g.main, "Include "+g.dir+"/d/"+pattern+"\n")
}

// sshReads returns the files (relative to d, sorted) that ssh reads for the
// current main file.
func (g *globFixture) sshReads(t *testing.T) ([]string, error) {
	t.Helper()
	out, err := exec.Command("ssh", "-F", g.main, "-G", "--", "glob-probe").Output()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		v, ok := strings.CutPrefix(l, "localforward ")
		if !ok {
			continue
		}
		port, _, _ := strings.Cut(v, " ")
		n, err := strconv.Atoi(port)
		if err != nil || n < 10000 || n-10000 >= len(g.files) {
			t.Fatalf("unexpected line in ssh -G: %q", l)
		}
		seen[g.files[n-10000]] = true
	}
	return sortedNames(seen), nil
}

// sshmReads returns the files (relative to d, sorted) that Load read through
// the Include, and what it could not follow.
func (g *globFixture) sshmReads(t *testing.T) (files, unfollowed []string) {
	t.Helper()
	l, err := Load(g.main)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range l.Files[1:] {
		rel, err := filepath.Rel(filepath.Join(g.dir, "d"), f.Path)
		if err != nil {
			t.Fatal(err)
		}
		seen[rel] = true
	}
	// Every loaded file brought its host into the merged view.
	hosts := map[string]bool{}
	for _, h := range l.Hosts {
		hosts[h.SourceFile] = true
	}
	for _, f := range l.Files[1:] {
		if !hosts[f.Path] {
			t.Errorf("file %s is loaded but its host is not in the merged view", f.Path)
		}
	}
	return sortedNames(seen), l.Unfollowed
}

func sortedNames(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// globTableFiles are the files of the table test. "é" is two bytes.
var globTableFiles = []string{
	"a.conf", "_u.conf", "a", "b", "c", "d", "x", "A", "1",
	"]", "!", "^", "-", "[", "[x", "!x", "^x", "]x", "-x", "[]", "a]", "ab",
	"{a,b}.conf", ".hid", "é", "sub/in", ".dot/in",
}

// only returns names sorted; except returns every visible top-level file of
// globTableFiles but names.
func only(names ...string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	return out
}

func except(names ...string) []string {
	out := []string{}
	for _, f := range globTableFiles {
		if !strings.Contains(f, "/") && !strings.HasPrefix(f, ".") && !contains(names, f) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// includeGlobCases: Include patterns (below <dir>/d/) and the files ssh reads
// for them, as measured with OpenSSH 10.6. blind: sshm does not reproduce the
// pattern and must say so instead of reading anything.
var includeGlobCases = []struct {
	pattern string
	want    []string
	blind   bool
	// sshRuns: also run ssh on a blind pattern, to record what ssh does.
	sshRuns bool
}{
	// The finding: "!" negates, "^" is an ordinary member.
	{pattern: "[!_]*", want: except("_u.conf")},
	{pattern: "[^_]*", want: only("^", "^x", "_u.conf")},
	{pattern: "[_]*", want: only("_u.conf")},
	{pattern: "[!^]x", want: only("!x", "-x", "[x", "]x")},
	{pattern: "[^^]x", want: only("^x")},
	{pattern: "[a^]", want: only("^", "a")},
	{pattern: "[!!]", want: only("-", "1", "A", "[", "]", "^", "a", "b", "c", "d", "x")},
	// Ranges.
	{pattern: "[a-c]", want: only("a", "b", "c")},
	{pattern: "[!a-c]", want: only("!", "-", "1", "A", "[", "]", "^", "d", "x")},
	{pattern: "[c-a]", want: only()},
	{pattern: "[a-]", want: only("-", "a")},
	{pattern: "[-a]", want: only("-", "a")},
	{pattern: "[!-]x", want: only("!x", "[x", "]x", "^x")},
	{pattern: "[--a]", want: only("-", "1", "A", "[", "]", "^", "a")},
	{pattern: "[a-c-x]", want: only("-", "a", "b", "c", "x")},
	// "]" as the first member.
	{pattern: "[]x]", want: only("]", "x")},
	{pattern: "[!]x]", want: only("!", "-", "1", "A", "[", "^", "a", "b", "c", "d")},
	{pattern: "[]]", want: only("]")},
	{pattern: "[]-a]", want: only("]", "^", "a")},
	// No "]" after the first member: the "[" is literal.
	{pattern: "[", want: only("[")},
	{pattern: "[x", want: only("[x")},
	{pattern: "[]", want: only("[]")},
	{pattern: "[!", want: only()},
	{pattern: "[!]", want: only()},
	{pattern: "a[", want: only()},
	// Backslash escapes.
	{pattern: `\[x`, want: only("[x")},
	{pattern: `[\]]x`, want: only("]x")},
	{pattern: `[\!]x`, want: only("!x")},
	{pattern: `[a\-c]`, want: only("-", "a", "c")},
	{pattern: `\*`, want: only()},
	{pattern: `\a`, want: only("a")},
	{pattern: `\\a`, want: only("a")}, // ssh's word splitting turns \\ into \ first
	{pattern: `[\]`, want: only("[]")},
	// "?" and sets are bytes, not characters.
	{pattern: "?", want: only("!", "-", "1", "A", "[", "]", "^", "a", "b", "c", "d", "x")},
	{pattern: "??", want: only("!x", "-x", "[]", "[x", "]x", "^x", "a]", "ab", "é")},
	{pattern: "é", want: only("é")},
	{pattern: "[é]", want: only()},
	{pattern: "?.conf", want: only("a.conf")},
	// Other wildcards.
	{pattern: "*", want: except()},
	{pattern: "*.conf", want: only("_u.conf", "a.conf", "{a,b}.conf")},
	{pattern: "[[]x", want: only("[x")},
	{pattern: "[*]", want: only()},
	{pattern: "[a]]", want: only("a]")},
	// No brace expansion.
	{pattern: "{a,b}.conf", want: only("{a,b}.conf")},
	{pattern: "{a,_u}.conf", want: only()},
	// Dot files and directories.
	{pattern: "[.]hid", want: only()},
	{pattern: "[!a]hid", want: only()},
	{pattern: "?hid", want: only()},
	{pattern: ".h*", want: only(".hid")},
	{pattern: `\.hi?`, want: only(".hid")},
	{pattern: "*/in", want: only("sub/in")},
	{pattern: ".*/in", want: only(".dot/in")},
	{pattern: "s[!x]b/[h-j]n", want: only("sub/in")},
	{pattern: "sub/./in", want: only("sub/in")},
	{pattern: "s*//in", want: only("sub/in")},
	{pattern: "s*/../a.con?", want: only("a.conf")},
	{pattern: "nodir/../a.con?", want: only()},
	{pattern: "*/", want: only()},

	// Not reproduced: reported as unfollowable, nothing is read.
	{pattern: "[[:alpha:]]", blind: true, sshRuns: true},
	{pattern: "[![:digit:]]*", blind: true, sshRuns: true},
	{pattern: "[a[:digit:]]", blind: true, sshRuns: true},
	{pattern: "[[:alpha:]", blind: true}, // ssh 10.6 crashes on this one: never run
	{pattern: "[a/b]", blind: true, sshRuns: true},
	{pattern: `sub\/in`, blind: true, sshRuns: true},
	{pattern: "*a*a*a*a*a*a*a*a*a*", blind: true, sshRuns: true},
}

// TestExpandIncludeGlobSemantics runs without ssh: the table says what ssh
// reads, sshm must read exactly that or declare the pattern unfollowable.
func TestExpandIncludeGlobSemantics(t *testing.T) {
	g := newGlobFixture(t, globTableFiles)
	for _, c := range includeGlobCases {
		g.include(t, c.pattern)
		got, unfollowed := g.sshmReads(t)
		if c.blind {
			if len(unfollowed) != 1 || len(got) != 0 {
				t.Errorf("Include %s: read %q, unfollowed %q; want nothing read and one unfollowed entry", c.pattern, got, unfollowed)
			}
			continue
		}
		if len(unfollowed) != 0 || !reflect.DeepEqual(got, c.want) {
			t.Errorf("Include %s:\n  sshm reads %q (unfollowed %q)\n  ssh reads  %q", c.pattern, got, unfollowed, c.want)
		}
	}
}

// TestIncludeGlobAgreesWithSSH is the same table against the real ssh: for
// every pattern sshm follows, the files Load reads are exactly the files ssh
// reads (found by resolving the probe host every file defines).
func TestIncludeGlobAgreesWithSSH(t *testing.T) {
	needSSH(t)
	g := newGlobFixture(t, globTableFiles)
	for _, c := range includeGlobCases {
		g.include(t, c.pattern)
		got, unfollowed := g.sshmReads(t)
		if c.blind {
			if len(unfollowed) == 0 {
				t.Errorf("Include %s: not reported as unfollowable", c.pattern)
			}
			if c.sshRuns {
				reads, err := g.sshReads(t)
				t.Logf("Include %s (sshm does not follow it): ssh reads %q (err %v)", c.pattern, reads, err)
			}
			continue
		}
		reads, err := g.sshReads(t)
		if err != nil {
			t.Errorf("Include %s: ssh fails: %v", c.pattern, err)
			continue
		}
		if !reflect.DeepEqual(reads, c.want) {
			t.Errorf("Include %s: ssh reads %q, the table says %q", c.pattern, reads, c.want)
		}
		if len(unfollowed) != 0 || !reflect.DeepEqual(got, reads) {
			t.Errorf("Include %s:\n  sshm reads %q (unfollowed %q)\n  ssh reads  %q", c.pattern, got, unfollowed, reads)
		}
	}
	// ssh does support character classes; sshm declines them (locale, and the
	// crash above). If this ever changes the table needs another look.
	g.include(t, "[[:alpha:]]")
	if reads, err := g.sshReads(t); err != nil || !reflect.DeepEqual(reads, only("A", "a", "b", "c", "d", "x")) {
		t.Errorf("Include [[:alpha:]]: ssh reads %q (err %v); the test expects the one-letter files", reads, err)
	}
}

// The review's scenario with the hosts themselves: a.conf and _u.conf in one
// directory, one Include with a set. A host is visible to sshm exactly when
// ssh applies its file.
func TestIncludeNegatedSetAgreesWithSSH(t *testing.T) {
	needSSH(t)
	dir := t.TempDir()
	write(t, filepath.Join(dir, "d", "a.conf"), "Host a\n  User u-a\n")
	write(t, filepath.Join(dir, "d", "_u.conf"), "Host u\n  User u-u\n")
	for pattern, want := range map[string][]string{
		"[!_]*": {"a"},
		"[^_]*": {"u"},
		"[_]*":  {"u"},
		"[!a]*": {"u"},
		"[a_]*": {"a", "u"},
	} {
		main := write(t, filepath.Join(dir, "config"), "Include "+dir+"/d/"+pattern+"\n")
		l, err := Load(main)
		if err != nil || len(l.Warnings) != 0 {
			t.Fatalf("%s: err=%v warnings=%v", pattern, err, l.Warnings)
		}
		var loaded, applied []string
		for _, h := range l.Hosts {
			loaded = append(loaded, h.Name)
		}
		for _, name := range []string{"a", "u"} {
			if sshUser(t, main, name) == "u-"+name {
				applied = append(applied, name)
			}
		}
		sort.Strings(loaded)
		if !reflect.DeepEqual(loaded, applied) || !reflect.DeepEqual(applied, want) {
			t.Errorf("Include d/%s: sshm sees hosts %q, ssh applies %q, want %q", pattern, loaded, applied, want)
		}
	}
}

// globSeed is the seed of the random differential: SSHM_PROP_SEED when set
// (the same variable as TestDocProperty), else a fixed one.
func globSeed(t *testing.T) int64 {
	t.Helper()
	seed := int64(propFixedSeed)
	if s := os.Getenv("SSHM_PROP_SEED"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("SSHM_PROP_SEED=%q: %v", s, err)
		}
		seed = n
	}
	return seed
}

// TestIncludeGlobRandomAgreesWithSSH throws random patterns, heavy on
// brackets, at a directory holding every one- and two-byte name over a small
// alphabet of special characters. Whatever sshm follows must be exactly what
// ssh reads.
func TestIncludeGlobRandomAgreesWithSSH(t *testing.T) {
	needSSH(t)
	alpha := []string{"a", "b", "c", "_", "!", "^", "]", "[", "-", `\`, ".", ":", "*", "?"}
	var files []string
	for _, x := range alpha {
		if x != "." {
			files = append(files, x)
		}
		for _, y := range alpha {
			if x+y != ".." {
				files = append(files, x+y)
			}
		}
	}
	files = append(files, "abc", "a.b", ".ab", "_a_", "[a]", "[!a]", "a-c", "é", "\xe9", "ccd/in", "..b/in", "ccd/a", "ccd/[a")
	g := newGlobFixture(t, files)

	seed := globSeed(t)
	t.Logf("seed %d", seed)
	r := rand.New(rand.NewSource(seed))
	pick := func(xs ...string) string { return xs[r.Intn(len(xs))] }
	member := func() string {
		return pick("a", "b", "c", "_", "!", "^", "]", "[", "-", `\]`, `\-`, ".", ":", "*", "?", "a-c", "!-_", "]-c", "é")
	}
	gen := func() string {
		if r.Intn(3) == 0 { // free-form
			var sb strings.Builder
			for i, n := 0, 1+r.Intn(7); i < n; i++ {
				sb.WriteString(pick("a", "b", "c", "_", "!", "^", "]", "[", "-", `\`, ".", ":", "*", "?", "[", "]", "!", "/", "[!", "[^", "[]", "[:", ":]", `\\`, "é"))
			}
			return sb.String()
		}
		// prefix, one set, suffix
		p := pick("", "", "", "a", "_", "?", "*", "c*/", ".") + "[" + pick("", "", "!", "!", "^")
		for i, n := 0, 1+r.Intn(3); i < n; i++ {
			p += member()
		}
		return p + pick("]", "]", "]", "]", "") + pick("", "", "*", "?", "a", "]", "*a")
	}

	const n = 300
	followed, blind, nonEmpty, goDiffers := 0, 0, 0, 0
	for i := 0; i < n; i++ {
		p := gen()
		if strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
			continue
		}
		g.include(t, p)
		got, unfollowed := g.sshmReads(t)
		if len(unfollowed) > 0 {
			// Never run: ssh 10.6 crashes on some unterminated classes.
			blind++
			if len(got) != 0 {
				t.Errorf("Include %s: unfollowable, but %q was read", p, got)
			}
			continue
		}
		followed++
		reads, err := g.sshReads(t)
		if err != nil {
			t.Errorf("Include %s: sshm follows it, ssh fails: %v", p, err)
			continue
		}
		if !reflect.DeepEqual(got, reads) {
			t.Errorf("Include %s:\n  sshm reads %q\n  ssh reads  %q", p, got, reads)
		}
		if len(reads) > 0 {
			nonEmpty++
		}
		// How the same pattern comes out of Go's filepath.Glob (what
		// ExpandInclude used before): counted to show the patterns matter.
		var viaGo []string
		if ms, err := filepath.Glob(g.dir + "/d/" + p); err == nil {
			for _, m := range ms {
				if fi, serr := os.Stat(m); serr == nil && fi.Mode().IsRegular() {
					rel, _ := filepath.Rel(filepath.Join(g.dir, "d"), m)
					viaGo = append(viaGo, rel)
				}
			}
		}
		sort.Strings(viaGo)
		if !reflect.DeepEqual(append([]string{}, viaGo...), reads) {
			goDiffers++
		}
	}
	t.Logf("%d patterns followed (%d match files, %d differ from filepath.Glob), %d unfollowable", followed, nonEmpty, goDiffers, blind)
	if nonEmpty < 60 || goDiffers < 30 {
		t.Errorf("the random patterns prove too little: %d match files, %d differ from filepath.Glob", nonEmpty, goDiffers)
	}
}

// ".." in a pattern is resolved by the kernel, as for ssh, not lexically:
// behind a symlinked directory that is another file.
func TestExpandIncludeDotDotBehindSymlink(t *testing.T) {
	dir := t.TempDir()
	realX := write(t, filepath.Join(dir, "real", "x.conf"), "Host viareal\n  User u-real\n")
	write(t, filepath.Join(dir, "x.conf"), "Host lexical\n  User u-lexical\n")
	if err := os.MkdirAll(filepath.Join(dir, "real", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real", "sub"), filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	for _, pattern := range []string{dir + "/link/../x.conf", dir + "/link/../x.c*", dir + "/l*/../x.conf"} {
		got, warn := ExpandInclude(pattern)
		if warn != "" || len(got) != 1 {
			t.Fatalf("ExpandInclude(%s) = %v, %q", pattern, got, warn)
		}
		a, err1 := os.Stat(got[0])
		b, err2 := os.Stat(realX)
		if err1 != nil || err2 != nil || !os.SameFile(a, b) {
			t.Errorf("ExpandInclude(%s) = %s: not the file the kernel reaches (%s)", pattern, got[0], realX)
		}
		main := write(t, filepath.Join(dir, "config"), "Include "+pattern+"\n")
		l, err := Load(main)
		if err != nil || len(l.Warnings) != 0 {
			t.Fatalf("%s: err=%v warnings=%v", pattern, err, l.Warnings)
		}
		if names := loadedHostNames(l); !reflect.DeepEqual(names, []string{"viareal"}) {
			t.Errorf("Include %s: loaded hosts %q, want viareal", pattern, names)
		}
		if f, ok := l.Lookup(realX); !ok || f.IncludedFrom != main {
			t.Errorf("Include %s: Lookup does not find the file under its real path", pattern)
		}
		if _, err := exec.LookPath("ssh"); err == nil {
			if u := sshUser(t, main, "viareal"); u != "u-real" {
				t.Errorf("Include %s: ssh does not read real/x.conf (user %q)", pattern, u)
			}
		}
	}
	// A plain ".." still comes back cleaned.
	if got, _ := ExpandInclude(dir + "/real/../x.conf"); !reflect.DeepEqual(got, []string{filepath.Join(dir, "x.conf")}) {
		t.Errorf("ExpandInclude(real/../x.conf) = %v", got)
	}
}

func loadedHostNames(l *Loaded) []string {
	var out []string
	for _, h := range l.Hosts {
		out = append(out, h.Name)
	}
	return out
}

// ---- Item 5a: the legacy Write(Parse()) keeps what ssh resolves ----

// Repeated ForwardAgent lines in one block. For ssh the flag (yes/no) and
// the agent socket path are two settings: the first flag-or-path line decides
// whether forwarding is on, the first PATH line sets the path, wherever it
// stands. The parser keeps the one value that says the same (found by the
// property test: "yes" then a path must read as the path).
func TestForwardAgentRepeatFollowsSSH(t *testing.T) {
	for _, c := range []struct {
		lines []string
		want  string
		sshG  string // "" = same as want
	}{
		{[]string{"yes", "/run/agent.sock"}, "/run/agent.sock", ""},
		{[]string{"YES # note", "/run/agent.sock"}, "/run/agent.sock", ""},
		{[]string{"true", "/run/agent.sock", "/run/other.sock"}, "/run/agent.sock", ""},
		{[]string{"yes", "no", "/run/agent.sock"}, "/run/agent.sock", ""},
		{[]string{"/run/agent.sock", "yes"}, "/run/agent.sock", ""},
		{[]string{"/run/agent.sock", "no"}, "/run/agent.sock", ""},
		{[]string{"/run/agent.sock", "/run/other.sock"}, "/run/agent.sock", ""},
		{[]string{"yes", "no"}, "yes", ""},
		{[]string{"no", "yes"}, "no", ""},
		{[]string{"yes"}, "yes", ""},
		// Forwarding stays off; ssh still prints the path. Kept as "no".
		{[]string{"no", "/run/agent.sock"}, "no", "/run/agent.sock"},
	} {
		text := "Host h\n"
		for _, l := range c.lines {
			text += "  ForwardAgent " + l + "\n"
		}
		cfg, err := Parse([]byte(text))
		if err != nil || len(cfg.Hosts) != 1 {
			t.Fatalf("%q: %v", c.lines, err)
		}
		if got := cfg.Hosts[0].ForwardAgent; got != c.want && got != c.want+" # note" && !strings.HasPrefix(got, c.want) {
			t.Errorf("%q: ForwardAgent = %q, want %q", c.lines, got, c.want)
		}
		if words := SplitWords(cfg.Hosts[0].ForwardAgent); len(words) != 1 || !strings.EqualFold(words[0], c.want) {
			t.Errorf("%q: ForwardAgent = %q, want %q", c.lines, cfg.Hosts[0].ForwardAgent, c.want)
		}
		if _, err := exec.LookPath("ssh"); err != nil {
			continue
		}
		dir := t.TempDir()
		before := sshG(t, write(t, filepath.Join(dir, "before"), text), "h")["forwardagent"]
		wantG := c.sshG
		if wantG == "" {
			wantG = strings.ToLower(c.want)
			if wantG == "true" {
				wantG = "yes"
			}
		}
		if !reflect.DeepEqual(before, []string{wantG}) {
			t.Errorf("%q: ssh resolves forwardagent %q, the test expects %q", c.lines, before, wantG)
		}
	}
}

// compileGlob refuses what it does not reproduce and never panics on odd
// input; globMatch works on bytes.
func TestCompileGlob(t *testing.T) {
	for _, p := range []string{"[[:alpha:]]", "[x[:digit:]]", "[[:x]", "[a[:]", "[a/b]", "[!/]", "[a-/]", `a\/b`, "a\x00b",
		strings.Repeat("*a", maxGlobStars+1), strings.Repeat("a", maxGlobPattern+1)} {
		if toks, why := compileGlob(p); why == "" {
			t.Errorf("compileGlob(%q) = %v: accepted", p, toks)
		}
	}
	for _, p := range []string{"", "[", "[!", "[!]", "[]", `\`, `[\`, `[a\`, "[a-", "[a-]", "[-", "[--", "[]-", "[!]-", "a[b-", "[:alpha:]", "[[", "[[]", "[:]", "[[:x",
		strings.Repeat("*", 50), strings.Repeat("*a", maxGlobStars), strings.Repeat("*/", 40)} {
		if _, why := compileGlob(p); why != "" {
			t.Errorf("compileGlob(%q) refused: %s", p, why)
		}
	}
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"[!a]", "b", true}, {"[!a]", "a", false}, {"[^a]", "^", true}, {"[^a]", "b", false},
		{"?", "é", false}, {"??", "é", true}, {"[\xc3][\xa9]", "é", true},
		{"*", "", true}, {"a*", "a", true}, {"*a*b", "xaxb", true}, {"*a*b", "xbxa", false},
		{"[]]", "]", true}, {"[]a]", "a", true}, {"[a-]", "-", true}, {"[", "[", true}, {"[a", "[a", true},
		{"[a-c]", "b", true}, {"[c-a]", "b", false}, {`[\]]`, "]", true}, {`\*`, "*", true}, {`\*`, "a", false},
	} {
		toks, why := compileGlob(c.pattern)
		if why != "" {
			t.Errorf("compileGlob(%q) refused: %s", c.pattern, why)
			continue
		}
		if got := globMatch(toks, c.name); got != c.want {
			t.Errorf("match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}
