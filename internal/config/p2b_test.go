package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Tests for the P2b fix round (review findings M4, M5, M6, minors d/e and
// the Load metadata that the managed-file save relies on).

func needSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}
}

// sshUser returns the user `ssh -F cfg -G host` resolves.
func sshUser(t *testing.T, cfg, host string) string {
	t.Helper()
	out, err := exec.Command("ssh", "-F", cfg, "-G", "--", host).Output()
	if err != nil {
		t.Fatalf("ssh -G %s: %v", host, err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(l, "user "); ok {
			return v
		}
	}
	return ""
}

// ---- M4: one word splitter ----

func TestSplitWords(t *testing.T) {
	for in, want := range map[string][]string{
		``:                    nil,
		`foo`:                 {"foo"},
		`  a   b	c  `:         {"a", "b", "c"},
		`"foo"`:               {"foo"},
		`'foo' "bar baz"`:     {"foo", "bar baz"},
		`a"b"c`:               {"abc"},
		`""`:                  {""},
		`bar # c`:             {"bar"},
		`bar #c d`:            {"bar"},
		`# only a comment`:    nil,
		`a#b`:                 {"a#b"},
		`"a # b" c`:           {"a # b", "c"},
		`a\"b`:                {`a"b`},
		`a\ b c`:              {"a b", "c"},
		`"a\"b"`:              {`a"b`},
		`a\\b`:                {`a\b`},
		`a\b`:                 {`a\b`},
		`"unterminated quote`: {"unterminated quote"},
		`*.example.com !bad`:  {"*.example.com", "!bad"},
	} {
		if got := SplitWords(in); !reflect.DeepEqual(got, want) {
			t.Errorf("SplitWords(%q) = %q, want %q", in, got, want)
		}
	}
}

// hostLineCases: a Host line, the names ssh takes from it, and words that
// appear on the line but are NOT names.
var hostLineCases = []struct {
	line     string
	names    []string
	notNames []string
}{
	{`Host "foo"`, []string{"foo"}, nil},
	{`Host bar # c`, []string{"bar"}, []string{"c", "#"}},
	{`Host 'q1' "q2"`, []string{"q1", "q2"}, nil},
	{`Host a"b"c`, []string{"abc"}, []string{"a", "b"}},
	{`Host=eq1`, []string{"eq1"}, nil},
	{`Host = eq2   eq3`, []string{"eq2", "eq3"}, nil},
	{`HOST up1`, []string{"up1"}, nil},
	{"host\ttab1\ttab2", []string{"tab1", "tab2"}, nil},
	{`Host x#y`, []string{"x#y"}, []string{"x"}},
	{`Host plain9 #trailing`, []string{"plain9"}, []string{"trailing", "#trailing"}},
	{`Host # nothing`, nil, []string{"nothing"}},
}

// Parse and Doc take the same names from every Host line, enabled or inside a
// disabled region.
func TestHostNamesParseAndDocAgree(t *testing.T) {
	for i, c := range hostLineCases {
		text := fmt.Sprintf("%s\n  User u%d\n", c.line, i)
		cfg, err := Parse([]byte(text))
		if err != nil || len(cfg.Hosts) != 1 {
			t.Errorf("%q: Parse hosts=%v err=%v", c.line, cfg.Hosts, err)
			continue
		}
		// The names are Host.Patterns; Host.Name stays the raw argument
		// text for the legacy writer (P2c, review R1).
		if got := cfg.Hosts[0].Patterns; got == nil || !reflect.DeepEqual(append([]string(nil), got...), c.names) {
			t.Errorf("%q: Parse patterns %q, want %q (non-nil)", c.line, got, c.names)
		}
		if cfg.Hosts[0].User != fmt.Sprintf("u%d", i) {
			t.Errorf("%q: options not attached: %+v", c.line, cfg.Hosts[0])
		}
		blocks := ParseDoc([]byte(text)).Blocks()
		if len(blocks) != 1 || !reflect.DeepEqual(blocks[0].Names, c.names) {
			t.Errorf("%q: Doc blocks %+v, want names %q", c.line, blocks, c.names)
		}

		// The same line inside a disabled region.
		dis := domain.DisabledMarkerStart("g") + "\n# " + c.line + "\n#   User u\n" + domain.DisabledMarkerEnd("g") + "\n"
		blocks = ParseDoc([]byte(dis)).Blocks()
		if len(blocks) != 1 || !blocks[0].Disabled || !reflect.DeepEqual(blocks[0].Names, c.names) {
			t.Errorf("disabled %q: Doc blocks %+v, want names %q", c.line, blocks, c.names)
		}
		cfg, err = Parse([]byte(dis))
		if err != nil {
			t.Errorf("disabled %q: %v", c.line, err)
			continue
		}
		var got []string
		for _, h := range cfg.Hosts {
			got = append(got, h.Patterns...)
		}
		if !reflect.DeepEqual(got, c.names) {
			t.Errorf("disabled %q: Parse names %q, want %q", c.line, got, c.names)
		}
	}
}

// ssh takes the same names: each name resolves to its block's User, each
// non-name does not.
func TestHostNamesAgreeWithSSH(t *testing.T) {
	needSSH(t)
	var text strings.Builder
	for i, c := range hostLineCases {
		fmt.Fprintf(&text, "%s\n  User u%d\n", c.line, i)
	}
	text.WriteString("Host *\n  User nobody\n")
	cfg := write(t, filepath.Join(t.TempDir(), "config"), text.String())
	for i, c := range hostLineCases {
		for _, n := range c.names {
			if got := sshUser(t, cfg, n); got != fmt.Sprintf("u%d", i) {
				t.Errorf("%q: ssh -G %s resolves user %q, want u%d", c.line, n, got, i)
			}
		}
		for _, n := range c.notNames {
			if got := sshUser(t, cfg, n); got != "nobody" {
				t.Errorf("%q: ssh -G %s resolves user %q: ssh treats it as a name of the block", c.line, n, got)
			}
		}
	}
}

// Include arguments go through the same splitter: quotes and "\ ".
func TestIncludeSplittingAgreesWithSSH(t *testing.T) {
	needSSH(t)
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a b.conf"), "Host esc-1\n  User escuser\n")
	write(t, filepath.Join(dir, "c d.conf"), "Host quo-1\n  User quouser\n")
	main := write(t, filepath.Join(dir, "config"),
		"Include "+dir+`/a\ b.conf "`+dir+`/c d.conf" # both`+"\n")
	l, err := Load(main)
	if err != nil || len(l.Warnings) != 0 {
		t.Fatalf("err=%v warnings=%v", err, l.Warnings)
	}
	if got := loadedHosts(l); !reflect.DeepEqual(got, []string{"esc-1@a b.conf", "quo-1@c d.conf"}) {
		t.Errorf("Load hosts = %v", got)
	}
	if e, q := sshUser(t, main, "esc-1"), sshUser(t, main, "quo-1"); e != "escuser" || q != "quouser" {
		t.Errorf("ssh: esc-1 user %q, quo-1 user %q", e, q)
	}
}

// A normal config still round-trips through the legacy writer unchanged.
func TestParseWriteNormalConfigUnchangedBySplitter(t *testing.T) {
	in := "Host web-1\n  HostName 10.0.0.1\n  User alice\n\nHost a b\n  User multi\n\nHost *\n  User fallback\n"
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Write(cfg)
	if err != nil || string(out) != in {
		t.Errorf("Write output changed:\n%s(%v)", out, err)
	}
}

// ---- M5: Doc and Parse agree on disabled regions ----

func TestDoc_DisableWithoutBlankLineAgreesWithParse(t *testing.T) {
	const in = "Host a\n  User x\nHost b\n  User y\nHost c\n  User z\n"
	d := ParseDoc([]byte(in))
	mustOK(t, d.DisableBlocks([]string{"b"}, "g"))

	cfg, err := Parse(d.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, d.Bytes())
	}
	type rec struct {
		name     string
		disabled bool
		group    string
		user     string
	}
	var got []rec
	for _, h := range cfg.Hosts {
		g := ""
		if h.Disabled {
			g = h.Group
		}
		got = append(got, rec{h.Name, h.Disabled, g, h.User})
	}
	want := []rec{{"a", false, "", "x"}, {"b", true, "g", "y"}, {"c", false, "", "z"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse sees %+v\nwant       %+v\n%s", got, want, d.Bytes())
	}
	if err := docVsParse(d); err != nil {
		t.Error(err)
	}

	// The legacy writer keeps all three and the round trip is stable.
	out, err := Write(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := Parse(out)
	if err != nil || len(cfg2.Hosts) != 3 || !cfg2.Hosts[1].Disabled || cfg2.Hosts[1].Name != "b" {
		t.Errorf("after Write: %v %v\n%s", hostNames(cfg2), err, out)
	}

	mustOK(t, d.EnableGroup("g"))
	if string(d.Bytes()) != in {
		t.Errorf("enable did not restore the file:\n%s", d.Bytes())
	}
}

// ---- M6: rest-of-line options and reserved keywords ----

func TestDoc_KnownHostsCommandTakesTheRestOfTheLine(t *testing.T) {
	d := ParseDoc([]byte("Host h\n  KnownHostsCommand /bin/echo x # c\n  User u # real comment\n"))
	o, ok := parseOptLine(d.Lines[1])
	if !ok || o.value != "/bin/echo x # c" || o.tail != "" {
		t.Fatalf("parseOptLine: %+v", o)
	}
	mustOK(t, d.SetOption("h", "KnownHostsCommand", "/bin/new"))
	if d.Lines[1] != "  KnownHostsCommand /bin/new" {
		t.Errorf("stale tail kept: %q", d.Lines[1])
	}
	// A "#" in the value is legitimate for these options, in any key casing.
	for _, k := range []string{"KnownHostsCommand", "knownhostscommand", "ProxyCommand", "LocalCommand", "RemoteCommand"} {
		if err := d.SetOption("h", k, "/bin/sh -c 'x # y'"); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	// ...but not for ordinary options, where ssh would cut the value.
	for _, k := range []string{"User", "PKCS11Provider", "SecurityKeyProvider"} {
		if err := d.SetOption("h", k, "/x # y"); !errors.Is(err, ErrBadValue) {
			t.Errorf("%s with a comment start: %v", k, err)
		}
	}
	if d.Lines[2] != "  User u # real comment" {
		t.Errorf("User line: %q", d.Lines[2])
	}
}

// ssh agrees on which options take the rest of the line.
func TestRestOfLineKeysAgreeWithSSH(t *testing.T) {
	needSSH(t)
	cfg := write(t, filepath.Join(t.TempDir(), "config"),
		"Host k\n  KnownHostsCommand /bin/echo k # c\n  ProxyCommand /bin/echo p # c\n  RemoteCommand /bin/echo r # c\n"+
			"  PermitLocalCommand yes\n  LocalCommand /bin/echo l # c\n  PKCS11Provider /x/p.so # c\n  SecurityKeyProvider /x/s.so # c\n")
	res := sshG(t, cfg, "k")
	for key, want := range map[string]string{
		"knownhostscommand": "/bin/echo k # c", "proxycommand": "/bin/echo p # c",
		"remotecommand": "/bin/echo r # c", "localcommand": "/bin/echo l # c",
		"pkcs11provider": "/x/p.so", "securitykeyprovider": "/x/s.so",
	} {
		if got := strings.Join(res[key], "|"); got != want {
			t.Errorf("ssh -G %s = %q, want %q", key, got, want)
		}
		if strings.HasSuffix(want, "# c") != restOfLineKeys[key] {
			t.Errorf("restOfLineKeys[%s] = %v disagrees with ssh", key, restOfLineKeys[key])
		}
	}
}

func TestDoc_ReservedKeywordsAreNotOptions(t *testing.T) {
	const in = "Host h\n  User u\n  Include /x/y.conf\n"
	for _, k := range []string{"Host", "host", "HOST", "Match", "match", "Include", "include"} {
		d := ParseDoc([]byte(in))
		if err := d.SetOption("h", k, "value"); !errors.Is(err, ErrReservedKey) {
			t.Errorf("SetOption(%s): %v", k, err)
		}
		if err := d.UnsetOption("h", k); !errors.Is(err, ErrReservedKey) {
			t.Errorf("UnsetOption(%s): %v", k, err)
		}
		if err := d.AddOptionValue("h", k, "value"); err == nil {
			t.Errorf("AddOptionValue(%s) accepted", k)
		}
		if string(d.Bytes()) != in {
			t.Errorf("%s: a refused operation changed the doc", k)
		}
	}
	// Quotes in a key would let "Host" through ssh's keyword parser.
	d := ParseDoc([]byte(in))
	if err := d.SetOption("h", `"Host"`, "x"); !errors.Is(err, ErrBadValue) {
		t.Errorf("quoted key: %v", err)
	}
}

// ---- M7: the Doc remembers what it was parsed from ----

func TestDoc_Base(t *testing.T) {
	raw := []byte("Host a\n  User x") // no final newline: Base is the exact input
	d := ParseDoc(raw)
	raw[0] = 'X' // the Doc keeps its own copy
	if string(d.Base()) != "Host a\n  User x" {
		t.Errorf("Base = %q", d.Base())
	}
	mustOK(t, d.SetOption("a", "User", "y"))
	if string(d.Base()) != "Host a\n  User x" || string(d.Bytes()) != "Host a\n  User y\n" {
		t.Errorf("Base %q Bytes %q", d.Base(), d.Bytes())
	}
	if len(ParseDoc(nil).Base()) != 0 || len((&Doc{}).Base()) != 0 {
		t.Error("an empty Doc has a non-empty Base")
	}
}

// ---- Load metadata: Unfollowed, Conditional, Lookup ----

func TestLoadUnfollowedIsTheBlindSubsetOfWarnings(t *testing.T) {
	dir := t.TempDir()
	inc := write(t, filepath.Join(dir, "inc.conf"), "Host i\n")
	broken := write(t, filepath.Join(dir, "broken.conf"), domain.DisabledMarkerStart("g")+"\n# Host x\n")
	loop := write(t, filepath.Join(dir, "loop.conf"), "Include "+filepath.Join(dir, "config")+"\n")

	for name, c := range map[string]struct {
		main          string
		warn, unfollo int
	}{
		"clean":          {"Include " + inc + "\n", 0, 0},
		"repeat":         {"Include " + inc + "\nInclude " + inc + "\n", 1, 0},
		"env token":      {"Include ${SOMEWHERE}/x.conf\n", 1, 1},
		"percent token":  {"Include " + dir + "/%h.conf\n", 1, 1},
		"tilde user":     {"Include ~somebody/x.conf\n", 1, 1},
		"unbalanced [":   {"Include " + dir + "/[\n", 0, 0}, // a literal "[" for ssh
		"glob class":     {"Include " + dir + "/[[:alpha:]]*\n", 1, 1},
		"slash in a set": {"Include " + dir + "/[a/b]\n", 1, 1},
		"unparsable":     {"Include " + broken + "\n", 1, 1},
		"cycle":          {"Include " + loop + "\n", 1, 1},
		"mixed":          {"Include " + inc + " " + inc + " ~somebody/x.conf\n", 2, 1},
		"missing (none)": {"Include " + dir + "/nope.conf\n", 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			l, err := Load(write(t, filepath.Join(dir, "config"), c.main))
			if err != nil {
				t.Fatal(err)
			}
			if len(l.Warnings) != c.warn || len(l.Unfollowed) != c.unfollo {
				t.Errorf("warnings %d %v, unfollowed %d %v; want %d and %d",
					len(l.Warnings), l.Warnings, len(l.Unfollowed), l.Unfollowed, c.warn, c.unfollo)
			}
			for _, u := range l.Unfollowed {
				if !contains(l.Warnings, u) {
					t.Errorf("unfollowed entry %q is not a warning", u)
				}
			}
		})
	}

	t.Run("depth", func(t *testing.T) {
		d := t.TempDir()
		for i := 0; i <= maxIncludeDepth+1; i++ {
			write(t, filepath.Join(d, fmt.Sprintf("f%d", i)), fmt.Sprintf("Include %s\n", filepath.Join(d, fmt.Sprintf("f%d", i+1))))
		}
		l, err := Load(filepath.Join(d, "f0"))
		if err != nil || len(l.Unfollowed) != 1 || !strings.Contains(l.Unfollowed[0], "depth") {
			t.Errorf("err=%v unfollowed=%v", err, l.Unfollowed)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads everything")
		}
		d := t.TempDir()
		secret := write(t, filepath.Join(d, "secret.conf"), "Host s\n")
		if err := os.Chmod(secret, 0); err != nil {
			t.Fatal(err)
		}
		l, err := Load(write(t, filepath.Join(d, "config"), "Include "+secret+"\n"))
		if err != nil || len(l.Unfollowed) != 1 || !strings.Contains(l.Unfollowed[0], "cannot read") {
			t.Errorf("err=%v unfollowed=%v", err, l.Unfollowed)
		}
	})
}

// conditionalScenario: which included files ssh applies unconditionally.
// Every file defines one host with its own User, so ssh can be asked.
func conditionalScenario(t *testing.T) (main string, files map[string]bool) {
	t.Helper()
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	write(t, p("top.conf"), "Include "+p("nested.conf")+"\n\nHost top\n  User u-top\n\nInclude "+p("deep.conf")+"\n")
	write(t, p("nested.conf"), "Host nested\n  User u-nested\n")
	write(t, p("deep.conf"), "Host deep\n  User u-deep\n")
	write(t, p("region.conf"), "Host region\n  User u-region\n")
	write(t, p("after.conf"), "Host after\n  User u-after\n\nInclude "+p("chained.conf")+"\n")
	write(t, p("chained.conf"), "Host chained\n  User u-chained\n")
	write(t, p("match.conf"), "Host match\n  User u-match\n")
	main = write(t, p("config"),
		"Include "+p("top.conf")+"\n"+
			// a disabled region is commented out: no Host line for ssh
			domain.DisabledMarkerStart("g")+"\n# Host off\n#   User x\n"+domain.DisabledMarkerEnd("g")+"\n"+
			"Include "+p("region.conf")+"\n"+
			"\nHost first\n  User u-first\n\n"+
			"Include "+p("after.conf")+"\n"+
			"\nMatch host nothing\n  Include "+p("match.conf")+"\n"+
			// P2c item 9: the nearest Host/Match line above the Include
			// decides. "Host *" (one pattern) and "Match all" match every
			// host, so ssh applies what is below them unconditionally...
			"\nHost *\n  Port 2200\nInclude "+p("star.conf")+"\n"+
			"\nHost later-block\n  Include "+p("later.conf")+"\n"+ // ...conditional again...
			"\nMatch all\n\nInclude "+p("all.conf")+"\n"+ // ...and not (a blank line ends no block for ssh)
			"\nHost never\n  User x\n"+
			"\nmatch ALL # c\n  Include "+p("allc.conf")+"\n"+
			"\nHost never2\n  User x\n"+
			"\nHost=\"*\" # quoted, with =\nInclude "+p("qstar.conf")+"\n")
	for _, n := range []string{"star", "later", "all", "allc", "qstar"} {
		write(t, p(n+".conf"), "Host "+n+"\n  User u-"+n+"\n")
	}
	// A file included from an unconditional place stays unconditional through
	// its own "Host *" too.
	write(t, p("star.conf"), "Host star\n  User u-star\n\nHost *\nInclude "+p("starsub.conf")+"\n")
	write(t, p("starsub.conf"), "Host starsub\n  User u-starsub\n")
	return main, map[string]bool{
		"top": false, "nested": false, "deep": true, "region": false,
		"after": true, "chained": true, "match": true,
		"star": false, "starsub": false, "later": true, "all": false, "allc": false, "qstar": false,
	}
}

func TestLoadMarksConditionalIncludes(t *testing.T) {
	main, want := conditionalScenario(t)
	l, err := Load(main)
	if err != nil || len(l.Warnings) != 0 {
		t.Fatalf("err=%v warnings=%v", err, l.Warnings)
	}
	if f := l.Files[0]; f.Conditional || f.IncludedFrom != "" || f.IncludeLine != 0 {
		t.Errorf("main file: %+v", f)
	}
	seen := 0
	for _, f := range l.Files[1:] {
		name := strings.TrimSuffix(filepath.Base(f.Path), ".conf")
		cond, ok := want[name]
		if !ok {
			t.Errorf("unexpected file %s", f.Path)
			continue
		}
		seen++
		if f.Conditional != cond {
			t.Errorf("%s: Conditional = %v, want %v (included from %s:%d)", name, f.Conditional, cond, f.IncludedFrom, f.IncludeLine)
		}
		if f.IncludedFrom == "" || f.IncludeLine == 0 {
			t.Errorf("%s: no provenance: %+v", name, f)
		}
	}
	if seen != len(want) {
		t.Errorf("loaded %d included files, want %d", seen, len(want))
	}
	top, _ := l.Lookup(filepath.Join(filepath.Dir(main), "top.conf"))
	if top.IncludedFrom != main || top.IncludeLine != 1 {
		t.Errorf("top.conf provenance: %s:%d", top.IncludedFrom, top.IncludeLine)
	}
}

// ssh applies exactly the files Load calls unconditional.
func TestLoadConditionalAgreesWithSSH(t *testing.T) {
	needSSH(t)
	main, want := conditionalScenario(t)
	for name, cond := range want {
		applied := sshUser(t, main, name) == "u-"+name
		if applied == cond {
			t.Errorf("%s: ssh applies it = %v, Load says conditional = %v", name, applied, cond)
		}
	}
}

func TestLoadedLookupResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := write(t, filepath.Join(dir, "real", "m.conf"), "Host m\n")
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// Included through the link, looked up by the real path, and vice versa.
	l, err := Load(write(t, filepath.Join(dir, "config"), "Include "+link+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{real, link} {
		if f, ok := l.Lookup(p); !ok || f.Conditional || filepath.Base(f.Path) != "link.conf" {
			t.Errorf("Lookup(%s) = %+v, %v", p, f, ok)
		}
	}
	if _, ok := l.Lookup(filepath.Join(dir, "other.conf")); ok {
		t.Error("Lookup found a file that was never loaded")
	}
	l, err = Load(write(t, filepath.Join(dir, "config"), "Include "+real+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Lookup(link); !ok {
		t.Error("Lookup(link) missed the file loaded by its real path")
	}
}

// ---- minor (d): glob and dot files ----

func dotfileScenario(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	write(t, filepath.Join(dir, "d", "vis.conf"), "Host vis\n  User u-vis\n")
	write(t, filepath.Join(dir, "d", ".hid.conf"), "Host hid\n  User u-hid\n")
	write(t, filepath.Join(dir, "d", ".config.tmp.123"), "Host tmp\n  User u-tmp\n")
	write(t, filepath.Join(dir, "d", ".sshm.lock"), "")
	write(t, filepath.Join(dir, ".dotdir", "in.conf"), "Host indot\n  User u-indot\n")
	write(t, filepath.Join(dir, "e", ".explicit.conf"), "Host explicit\n  User u-explicit\n")
	return dir
}

func TestExpandIncludeSkipsDotFilesLikeGlob3(t *testing.T) {
	dir := dotfileScenario(t)
	j := filepath.Join
	for pat, want := range map[string][]string{
		j(dir, "d", "*"):              {j(dir, "d", "vis.conf")},
		j(dir, "d", "*.conf"):         {j(dir, "d", "vis.conf")},
		j(dir, "d", "?hid.conf"):      nil,
		j(dir, "d", "[.]hid.conf"):    nil,
		j(dir, "d", ".*.conf"):        {j(dir, "d", ".hid.conf")},
		j(dir, "d", ".hid.conf"):      {j(dir, "d", ".hid.conf")},
		j(dir, "*", "in.conf"):        nil,
		j(dir, ".*", "in.conf"):       {j(dir, ".dotdir", "in.conf")},
		j(dir, ".dotdir", "*"):        {j(dir, ".dotdir", "in.conf")},
		j(dir, "e", ".explicit.conf"): {j(dir, "e", ".explicit.conf")},
		dir + "/d//*.conf":            {j(dir, "d", "vis.conf")},
		dir + "/./d/./*":              {j(dir, "d", "vis.conf")},
		dir + "/e/../d/*":             {j(dir, "d", "vis.conf")},
	} {
		got, warn := ExpandInclude(pat)
		if warn != "" || !reflect.DeepEqual(got, want) {
			t.Errorf("ExpandInclude(%s) = %v (%q), want %v", pat, got, warn, want)
		}
	}
}

func TestIncludeGlobDotFilesAgreeWithSSH(t *testing.T) {
	needSSH(t)
	dir := dotfileScenario(t)
	j := filepath.Join
	main := write(t, j(dir, "config"),
		"Include "+j(dir, "d", "*")+" "+j(dir, "*", "in.conf")+" "+j(dir, "e", ".explicit.conf")+"\n")
	l, err := Load(main)
	if err != nil || len(l.Warnings) != 0 {
		t.Fatalf("err=%v warnings=%v", err, l.Warnings)
	}
	loaded := map[string]bool{}
	for _, h := range l.Hosts {
		loaded[h.Name] = true
	}
	for _, name := range []string{"vis", "hid", "tmp", "indot", "explicit"} {
		applied := sshUser(t, main, name) == "u-"+name
		if applied != loaded[name] {
			t.Errorf("%s: ssh reads its file = %v, Load read it = %v", name, applied, loaded[name])
		}
	}
	if !loaded["vis"] || !loaded["explicit"] || loaded["hid"] || loaded["tmp"] {
		t.Errorf("loaded = %v", loaded)
	}
}

// ---- minor (e): backups are pruned ----

func TestBackupToKeepsTheNewestMaxBackups(t *testing.T) {
	dir := t.TempDir()
	src := write(t, filepath.Join(dir, "sshm.conf"), "")
	bdir := filepath.Join(dir, "sshm-backups")
	// Files that look similar but are not backups of sshm.conf.
	foreign := []string{
		"sshm.conf.notes", "sshm.conf.old.20260101-000000.000000", "sshm.conf.20260101-000000",
		"other.conf.20260101-000000.000000", "sshm.conf.20260101-000000.000000-x",
	}
	for _, n := range foreign {
		write(t, filepath.Join(bdir, n), "keep me")
	}

	const total = MaxBackups + 7
	for i := 0; i < total; i++ {
		if err := os.WriteFile(src, []byte(fmt.Sprintf("version %d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := BackupTo(src, bdir); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(bdir)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, e := range ents {
		if contains(foreign, e.Name()) {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(bdir, e.Name()))
		kept[string(b)] = true
	}
	if len(kept) != MaxBackups {
		t.Fatalf("%d backups kept, want %d", len(kept), MaxBackups)
	}
	for i := 0; i < total; i++ {
		if want := i >= total-MaxBackups; kept[fmt.Sprintf("version %d", i)] != want {
			t.Errorf("version %d kept = %v, want %v (the NEWEST %d must stay)", i, !want, want, MaxBackups)
		}
	}
	for _, n := range foreign {
		if b, err := os.ReadFile(filepath.Join(bdir, n)); err != nil || string(b) != "keep me" {
			t.Errorf("pruning touched %s: %v", n, err)
		}
	}
}

// ---- lock and chmod helpers ----

func TestLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sshm.lock")
	unlock, err := LockFile(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file: %v %v", fi, err)
	}
	// Held: a second taker times out, even in the same process.
	start := time.Now()
	if _, err := LockFile(path, 60*time.Millisecond); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("second lock: %v", err)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond {
		t.Errorf("gave up after %v, before the timeout", waited)
	}
	// A waiter gets it as soon as it is released.
	got := make(chan error, 1)
	go func() {
		u, err := LockFile(path, 5*time.Second)
		if err == nil {
			u()
		}
		got <- err
	}()
	time.Sleep(40 * time.Millisecond)
	unlock()
	if err := <-got; err != nil {
		t.Errorf("waiter: %v", err)
	}
	// The file stays (removing it would split the lock), and can be re-locked.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("lock file removed: %v", err)
	}
	u, err := LockFile(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	u()
	if _, err := LockFile(filepath.Join(t.TempDir(), "no-such-dir", "l"), 0); err == nil {
		t.Error("lock in a missing directory succeeded")
	}
}

func TestChmodNoFollow(t *testing.T) {
	dir := t.TempDir()
	victim := write(t, filepath.Join(dir, "victim"), "x")
	if err := os.Chmod(victim, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := ChmodNoFollow(link, 0o600); err == nil {
		t.Error("chmod through a symlink succeeded")
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o644 {
		t.Errorf("the link's target was chmodded to %o", fi.Mode().Perm())
	}
	if err := ChmodNoFollow(victim, 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o", fi.Mode().Perm())
	}
}
