package config

import (
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Tests for the P2c fix round. Same rules as the other test files: temp dirs
// only, ssh always with -F <temp file>, absolute Include paths.

// ---- Item 1 (review R1): the legacy Parse -> Write keeps every Host line ----

// legacyHostLines: Host lines in every spelling, the text the legacy writer
// must put after "Host " (what HEAD's parser kept as the name), the patterns
// ssh takes from the line, and names to probe.
var legacyHostLines = []struct {
	line     string
	name     string   // Host.Name: the raw argument text
	patterns []string // Host.Patterns: what ssh reads
	sshOK    bool     // ssh accepts a config with this line
	probes   []string
}{
	{`Host # c`, `# c`, []string{}, true, []string{"c", "#", "other"}},
	{`Host ""`, `""`, []string{""}, false, []string{"x"}},
	{`Host "a b"`, `"a b"`, []string{"a b"}, true, []string{"a", "b", "other"}},
	{`Host a\ b`, `a\ b`, []string{"a b"}, true, []string{"a", "b", "other"}},
	{`Host x # c`, `x # c`, []string{"x"}, true, []string{"x", "c", "other"}},
	{"Host\ttab1\ttab2", "tab1\ttab2", []string{"tab1", "tab2"}, true, []string{"tab1", "tab2", "other"}},
	{"Host tab3\ttab4 ", "tab3\ttab4", []string{"tab3", "tab4"}, true, []string{"tab3", "tab4"}},
	{`Host=x`, `x`, []string{"x"}, true, []string{"x", "other"}},
	{`Host = eq`, `eq`, []string{"eq"}, true, []string{"eq", "=", "other"}},
	{`Host =eq2`, `eq2`, []string{"eq2"}, true, []string{"eq2", "=eq2"}},
	{`Host m1 m2  m3`, `m1 m2  m3`, []string{"m1", "m2", "m3"}, true, []string{"m1", "m2", "m3", "m4"}},
	{`Host *.example.com`, `*.example.com`, []string{"*.example.com"}, true, []string{"w.example.com", "example.com", "other"}},
	{`Host !x a`, `!x a`, []string{"!x", "a"}, true, []string{"a", "x", "other"}},
	{`HOST up`, `up`, []string{"up"}, true, []string{"up", "UP"}},
	{`Host "x #y"`, `"x #y"`, []string{"x #y"}, true, []string{"x", "y", "#y"}},
	{`Host 'q1' "q2" # both`, `'q1' "q2" # both`, []string{"q1", "q2"}, true, []string{"q1", "q2", "both"}},
	{`  Host   lead   `, `lead`, []string{"lead"}, true, []string{"lead"}},
}

// legacyConfig embeds one Host line in a small config.
func legacyConfig(line string) string {
	return line + "\n  User hit\n\nHost other\n  User o\n\nHost *\n  User fallback\n"
}

// TestParseHostLineSpellings: Parse reads every spelling of a Host line into
// the patterns ssh takes from it (Patterns) and attaches the options to the
// block. The Name of such a line is pinned by hostname_test.go (P7 N1); here
// only a line without any pattern (`Host # c`, `Host ""`) must keep its
// argument text as the name.
func TestParseHostLineSpellings(t *testing.T) {
	for _, c := range legacyHostLines {
		in := legacyConfig(c.line)
		cfg, err := Parse([]byte(in))
		if err != nil || len(cfg.Hosts) != 3 {
			t.Errorf("%q: Parse hosts=%v err=%v", c.line, hostNames(cfg), err)
			continue
		}
		h := cfg.Hosts[0]
		if h.Patterns == nil || !reflect.DeepEqual(h.Patterns, c.patterns) {
			t.Errorf("%q: Patterns = %#v, want %#v", c.line, h.Patterns, c.patterns)
		}
		if h.User != "hit" {
			t.Errorf("%q: options not attached: %+v", c.line, h)
		}
		if strings.Join(c.patterns, "") == "" && h.Name != c.name {
			t.Errorf("%q: Name = %q, want the argument text %q for a line without pattern", c.line, h.Name, c.name)
		}
	}
}

// sshGRaw runs `ssh -F cfg -G -- host` and returns stdout, or ok=false when
// ssh refuses the configuration.
func sshGRaw(cfg, host string) (out string, ok bool) {
	b, err := exec.Command("ssh", "-F", cfg, "-G", "--", host).Output()
	return string(b), err == nil
}

// TestPatternsDriveMatching: EffectiveConfig matches on Patterns, so a quoted
// "a b" is one pattern, an inline comment is not a name and "Host # c"
// matches nothing; ssh agrees on every probe.
func TestPatternsDriveMatching(t *testing.T) {
	const in = `Host "a b"
  User quoted

Host x # c
  User commented

Host # c
  User nothing

Host a\ b
  User escaped

Host *
  User fallback
`
	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"a": "fallback", "b": "fallback", "x": "commented", "c": "fallback", "#": "fallback"}
	main := ""
	if _, err := exec.LookPath("ssh"); err == nil {
		main = write(t, filepath.Join(t.TempDir(), "config"), in)
	}
	for name, user := range want {
		got, err := domain.EffectiveConfig(cfg.Hosts, name)
		if err != nil || got.User != user {
			t.Errorf("EffectiveConfig(%q).User = %q (%v), want %q", name, got.User, err, user)
		}
		if main != "" {
			if u := sshUser(t, main, name); u != user {
				t.Errorf("ssh -G %s resolves user %q, the test expects %q", name, u, user)
			}
		}
	}
}

// hostLineRe finds a Host line the way ssh does: the keyword, then a blank
// or "=".
var hostLineRe = regexp.MustCompile(`(?i)^host[ \t=]`)

// inputHostArgs lists, independently of Parse, the argument text of every
// enabled Host line of text (what follows the keyword and its blank / "="
// separator) and every commented-out Host line inside a disabled region
// (verbatim).
func inputHostArgs(text string) (enabled, disabledLines []string) {
	region := ""
	for _, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		if g, ok := domain.IsDisabledMarkerStart(l); ok && region == "" {
			region = g
			continue
		}
		if g, ok := domain.IsDisabledMarkerEnd(l); ok && g == region {
			region = ""
			continue
		}
		if region != "" {
			if un := strings.TrimSpace(strings.TrimPrefix(l, "# ")); strings.HasPrefix(l, "# ") && hostLineRe.MatchString(un) {
				disabledLines = append(disabledLines, raw)
			}
			continue
		}
		if !hostLineRe.MatchString(l) {
			continue
		}
		arg := strings.TrimLeft(l[4:], " \t")
		arg = strings.TrimLeft(strings.TrimPrefix(arg, "="), " \t")
		if arg != "" {
			enabled = append(enabled, arg)
		}
	}
	return enabled, disabledLines
}
