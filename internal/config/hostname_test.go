package config

// P7 clauses N1 and N3 (PLAN-p7.md, section 7 items 13-14): the parser's
// Host.Name is the name a user types: the one pattern of a Host line (comment
// and quotes stripped); for several patterns the patterns joined by ONE space,
// comment stripped (`Host db-1 db-2 # pair` -> "db-1 db-2"); for no pattern the
// raw argument text. N3 characterizes what must not change.

import (
	"path/filepath"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

type hnCase struct {
	line string // the Host line, as written
	want string // Host.Name
}

var hnCases = []hnCase{
	// one pattern: comment and quotes stripped
	{line: "Host web-1 # prod", want: "web-1"},
	{line: "Host web-1   # prod", want: "web-1"},
	{line: "Host web-1 #prod", want: "web-1"},
	{line: "Host web-1", want: "web-1"},
	{line: "Host\tweb-2\t# x", want: "web-2"},
	{line: "host web-3 # lower-case keyword", want: "web-3"},
	{line: "HOST web-4", want: "web-4"},
	{line: "Host=x", want: "x"},
	{line: "Host = y # eq", want: "y"},
	{line: `Host "a b"`, want: "a b"},
	{line: `Host "a b" # quoted with comment`, want: "a b"},
	{line: "Host *", want: "*"},
	{line: "Host * # defaults", want: "*"},
	// several patterns: joined by one space, comment and quotes stripped
	{line: "Host a b", want: "a b"},
	{line: "Host a\tb", want: "a b"},
	{line: "Host * !x", want: "* !x"},
	{line: `Host "a b" c`, want: "a b c"},
	{line: "Host db-1 db-2 # pair", want: "db-1 db-2"},
	{line: "Host db-1   db-2\t# pair", want: "db-1 db-2"},
	// no pattern at all: keeps its current name (N3)
	{line: "Host # c", want: "# c"},
}

func hnCheck(t *testing.T, what, line, got string, c hnCase) {
	t.Helper()
	if got != c.want {
		t.Errorf("%s: %q gave Name %q, want %q", what, line, got, c.want)
	}
}

// N1 through Parse.
func TestHostName_ParseNamesAreWhatAUserTypes(t *testing.T) {
	for _, c := range hnCases {
		cfg, err := Parse([]byte(c.line + "\n  HostName 10.0.0.1\n"))
		if err != nil {
			t.Errorf("Parse(%q): %v", c.line, err)
			continue
		}
		if len(cfg.Hosts) != 1 {
			t.Errorf("Parse(%q): %d hosts, want 1", c.line, len(cfg.Hosts))
			continue
		}
		hnCheck(t, "Parse", c.line, cfg.Hosts[0].Name, c)
		if cfg.Hosts[0].HostName != "10.0.0.1" {
			t.Errorf("Parse(%q): the block lost its options (HostName %q)", c.line, cfg.Hosts[0].HostName)
		}
	}
}

// N1 through Load: the merged view carries the same names.
func TestHostName_LoadNamesAreWhatAUserTypes(t *testing.T) {
	dir := t.TempDir()
	for i, c := range hnCases {
		path := write(t, filepath.Join(dir, "cfg"+string(rune('a'+i))), c.line+"\n  HostName 10.0.0.1\n")
		l, err := Load(path)
		if err != nil {
			t.Errorf("Load(%q): %v", c.line, err)
			continue
		}
		if len(l.Hosts) != 1 {
			t.Errorf("Load(%q): %d hosts, want 1", c.line, len(l.Hosts))
			continue
		}
		hnCheck(t, "Load", c.line, l.Hosts[0].Name, c)
		if l.Hosts[0].SourceFile == "" {
			t.Errorf("Load(%q): no SourceFile", c.line)
		}
	}
}

// N1: a literal `Host "a b"` and `Host a b` collide in the name (accepted as
// today), they are told apart by the pattern list.
func TestHostName_QuotedAndPlainTwoWordsCollide(t *testing.T) {
	cfg, err := Parse([]byte("Host \"a b\"\n  User q\n\nHost a b\n  User p\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}
	if cfg.Hosts[0].Name != "a b" || cfg.Hosts[1].Name != "a b" {
		t.Fatalf("names = %q and %q, want both %q", cfg.Hosts[0].Name, cfg.Hosts[1].Name, "a b")
	}
	if n := len(cfg.Hosts[0].PatternList()); n != 1 {
		t.Errorf("quoted block has %d patterns, want 1", n)
	}
	if n := len(cfg.Hosts[1].PatternList()); n != 2 {
		t.Errorf("plain block has %d patterns, want 2", n)
	}
}

// N3 (characterization, green now): `Host * !x` is not a wildcard; `Host *`
// is; `Host * # defaults` is now the wildcard block too (N1: its Name is "*").
func TestHostName_WildcardStatus(t *testing.T) {
	cfg, err := Parse([]byte("Host * !x\n  User a\n\nHost *\n  User b\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(cfg.Hosts))
	}
	if cfg.Hosts[0].IsWildcard() {
		t.Errorf("Host * !x (Name %q) is a wildcard, want not", cfg.Hosts[0].Name)
	}
	if !cfg.Hosts[1].IsWildcard() {
		t.Errorf("Host * (Name %q) is not a wildcard", cfg.Hosts[1].Name)
	}
	cfg, err = Parse([]byte("Host * # defaults\n  User c\n"))
	if err != nil || len(cfg.Hosts) != 1 {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Hosts[0].IsWildcard() {
		t.Errorf("`Host * # defaults` has Name %q and is not a wildcard (N1: the name is the one pattern)", cfg.Hosts[0].Name)
	}
}

func hnRules(issues []domain.Issue, rule string) []domain.Issue {
	var out []domain.Issue
	for _, i := range issues {
		if i.Rule == rule {
			out = append(out, i)
		}
	}
	return out
}

// N3: validation does not change for multi-pattern lines: `Host a b` followed by
// `Host a` raises no duplicate-host (characterization, green now), and a
// genuinely repeated single name still does (presence assertion for the rule).
func TestHostName_ValidateDuplicateHost(t *testing.T) {
	cfg, err := Parse([]byte("Host a b\n  HostName 1.1.1.1\n\nHost a\n  HostName 2.2.2.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	issues := domain.Validate(cfg.Hosts)
	if d := hnRules(issues, "duplicate-host"); len(d) != 0 {
		t.Errorf("duplicate-host for `Host a b` + `Host a`: %v", d)
	}

	cfg, err = Parse([]byte("Host a\n  HostName 1.1.1.1\n\nHost a\n  HostName 2.2.2.2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d := hnRules(domain.Validate(cfg.Hosts), "duplicate-host"); len(d) != 1 {
		t.Errorf("`Host a` twice: %d duplicate-host issues, want 1", len(d))
	}
}

// N1 / spec item 14 (accepted side effect): ssh treats `Host web-1 # prod` and
// `Host web-1` as the same host, so in ONE file they are a duplicate-host, and
// `Host * # c` is the default `Host *` (a second one is a duplicate too). The
// multi-pattern comment forms keep matching the plain line of the same patterns.
func TestHostName_CommentedLinesDuplicateThePlainOnes(t *testing.T) {
	for _, c := range []struct{ name, first, second string }{
		{"single pattern with comment first", "Host web-1 # prod", "Host web-1"},
		{"single pattern with comment second", "Host web-1", "Host web-1 # prod"},
		{"default block", "Host * # c", "Host *"},
		{"several patterns", "Host db-1 db-2 # pair", "Host db-1   db-2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := write(t, filepath.Join(t.TempDir(), "config"),
				c.first+"\n  HostName 1.1.1.1\n\n"+c.second+"\n  HostName 2.2.2.2\n")
			l, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(l.Hosts) != 2 {
				t.Fatalf("got %d hosts, want 2", len(l.Hosts))
			}
			if l.Hosts[0].Name != l.Hosts[1].Name {
				t.Fatalf("names %q and %q differ, want the same host", l.Hosts[0].Name, l.Hosts[1].Name)
			}
			if d := hnRules(domain.Validate(l.Hosts), "duplicate-host"); len(d) != 1 {
				t.Errorf("%q + %q in one file: %d duplicate-host issues, want 1: %v", c.first, c.second, len(d), d)
			}
		})
	}

	// `Host * # c` is the default block: IsWildcard through Load.
	path := write(t, filepath.Join(t.TempDir(), "config"), "Host * # c\n  User d\n")
	l, err := Load(path)
	if err != nil || len(l.Hosts) != 1 {
		t.Fatalf("Load: %v, %d hosts", err, len(l.Hosts))
	}
	if !l.Hosts[0].IsWildcard() {
		t.Errorf("`Host * # c` has Name %q and is not the default block", l.Hosts[0].Name)
	}
}

// N3: isConcreteName decides the cross-file warning. Unchanged for patterns
// (`Host *`, `Host * !x`, `Host a b` in two files: no warning, characterization
// green now); `Host web-1 # prod` is concrete now, so it collides with
// `Host web-1` of an included file.
func TestHostName_CrossFileWarningFollowsConcreteNames(t *testing.T) {
	cross := func(t *testing.T, mainHost, incHost string) []domain.Issue {
		t.Helper()
		dir := t.TempDir()
		inc := write(t, filepath.Join(dir, "inc.conf"), incHost+"\n  HostName 2.2.2.2\n")
		main := write(t, filepath.Join(dir, "config"), "Include "+inc+"\n\n"+mainHost+"\n  HostName 1.1.1.1\n")
		l, err := Load(main)
		if err != nil {
			t.Fatal(err)
		}
		if len(l.Hosts) != 2 {
			t.Fatalf("got %d hosts, want 2", len(l.Hosts))
		}
		return hnRules(domain.Validate(l.Hosts), "dup-host-cross-file")
	}
	for _, c := range []struct{ main, inc string }{
		{"Host *", "Host *"},
		{"Host * !x", "Host * !x"},
		{"Host a b", "Host a b"},
		{"Host a?", "Host a?"},
	} {
		if got := cross(t, c.main, c.inc); len(got) != 0 {
			t.Errorf("%q in two files: cross-file warning %v, want none", c.main, got)
		}
	}
	if got := cross(t, "Host web-1", "Host web-1"); len(got) != 1 {
		t.Errorf("`Host web-1` in two files: %d cross-file warnings, want 1 (rule must exist)", len(got))
	}
	if got := cross(t, "Host web-1 # prod", "Host web-1"); len(got) != 1 {
		t.Errorf("`Host web-1 # prod` + `Host web-1` in an included file: %d cross-file warnings, want 1 (the name is concrete now)", len(got))
	}
}
