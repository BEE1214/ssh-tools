package config

import (
	"bytes"
	"fmt"
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

// TestLegacyParseWriteKeepsHostLines: Parse stores the raw argument text in
// Name and what ssh reads in Patterns; Write puts the raw text back, so a
// Parse -> Write cycle keeps the bytes after "Host " (HEAD behaviour, lost in
// P2b: `Host # c` became a bare, ssh-fatal "Host ", `Host "a b"` became two
// patterns) and a second cycle changes nothing.
func TestLegacyParseWriteKeepsHostLines(t *testing.T) {
	for _, c := range legacyHostLines {
		in := legacyConfig(c.line)
		cfg, err := Parse([]byte(in))
		if err != nil || len(cfg.Hosts) != 3 {
			t.Errorf("%q: Parse hosts=%v err=%v", c.line, hostNames(cfg), err)
			continue
		}
		h := cfg.Hosts[0]
		if h.Name != c.name {
			t.Errorf("%q: Name = %q, want the raw argument text %q", c.line, h.Name, c.name)
		}
		if h.Patterns == nil || !reflect.DeepEqual(h.Patterns, c.patterns) {
			t.Errorf("%q: Patterns = %#v, want %#v", c.line, h.Patterns, c.patterns)
		}
		if h.User != "hit" {
			t.Errorf("%q: options not attached: %+v", c.line, h)
		}

		out, err := Write(cfg)
		if err != nil {
			t.Errorf("%q: Write: %v", c.line, err)
			continue
		}
		lines := strings.Split(string(out), "\n")
		if lines[0] != "Host "+c.name {
			t.Errorf("%q: Write emits %q, want %q", c.line, lines[0], "Host "+c.name)
		}
		// An ordinary "Host text" line comes back byte-for-byte (minus
		// surrounding blanks, which Parse has always trimmed). The other
		// spellings (tab, "=", keyword casing) come back as "Host text".
		if strings.HasPrefix(c.line, "Host ") && !strings.HasPrefix(c.line, "Host =") && lines[0] != strings.TrimSpace(c.line) {
			t.Errorf("%q: Host line bytes changed to %q", c.line, lines[0])
		}
		for _, l := range lines {
			if strings.TrimSpace(l) == "Host" {
				t.Errorf("%q: Write emitted a bare Host line (fatal for ssh):\n%s", c.line, out)
			}
		}

		// Stable: the second cycle reads the same host and writes the same bytes.
		cfg2, err := Parse(out)
		if err != nil || len(cfg2.Hosts) != 3 {
			t.Errorf("%q: re-Parse hosts=%v err=%v\n%s", c.line, hostNames(cfg2), err, out)
			continue
		}
		h2 := cfg2.Hosts[0]
		if h2.Name != h.Name || !reflect.DeepEqual(h2.Patterns, h.Patterns) || h2.User != h.User || h2.Group != h.Group {
			t.Errorf("%q: not stable: %+v then %+v", c.line, h, h2)
		}
		out2, err := Write(cfg2)
		if err != nil || !bytes.Equal(out, out2) {
			t.Errorf("%q: second Write differs (%v):\n%s---\n%s", c.line, err, out, out2)
		}
	}
}

// sshGRaw runs `ssh -F cfg -G -- host` and returns stdout, or ok=false when
// ssh refuses the configuration.
func sshGRaw(cfg, host string) (out string, ok bool) {
	b, err := exec.Command("ssh", "-F", cfg, "-G", "--", host).Output()
	return string(b), err == nil
}

// TestLegacyParseWriteAgreesWithSSH: for every Host line ssh accepts, each
// probe name resolves identically before and after a legacy Parse -> Write
// cycle; a line ssh refuses (`Host ""`, a bare "Host") is refused before AND
// after: the cycle makes nothing worse and nothing "better" by accident.
func TestLegacyParseWriteAgreesWithSSH(t *testing.T) {
	needSSH(t)
	dir := t.TempDir()
	cycle := func(t *testing.T, i int, in string) (before, after string) {
		t.Helper()
		before = write(t, filepath.Join(dir, fmt.Sprintf("before-%d", i)), in)
		cfg, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		out, err := Write(cfg)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		return before, write(t, filepath.Join(dir, fmt.Sprintf("after-%d", i)), string(out))
	}
	for i, c := range legacyHostLines {
		before, after := cycle(t, i, legacyConfig(c.line))
		for _, p := range c.probes {
			b, bok := sshGRaw(before, p)
			a, aok := sshGRaw(after, p)
			if bok != c.sshOK {
				t.Errorf("%q: ssh accepts the input = %v, the table says %v", c.line, bok, c.sshOK)
			}
			if bok != aok {
				t.Errorf("%q probe %q: ssh accepted before=%v after=%v", c.line, p, bok, aok)
			}
			if b != a {
				t.Errorf("%q probe %q: ssh -G differs after Parse->Write", c.line, p)
			}
		}
	}

	// A bare Host line (no argument) is fatal for ssh. It is not a Host line
	// for the parser; outside a block it is kept as text, so ssh refuses the
	// file before and after, exactly as with HEAD.
	for i, in := range []string{
		"Host\n  User hit\n\nHost other\n  User o\n",
		"Host other\n  User o\n\nHost \n  User hit\n",
	} {
		before, after := cycle(t, 100+i, in)
		_, bok := sshGRaw(before, "other")
		_, aok := sshGRaw(after, "other")
		if bok || aok {
			t.Errorf("bare Host %q: ssh accepted before=%v after=%v, want both refused", in, bok, aok)
		}
	}
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

// legacyWriteKeepsHostLines runs the legacy Write(Parse(text)) and checks
// that no Host line is lost, added or rewritten:
//   - the Host lines of the output are exactly "Host <argument text>" of the
//     input's enabled Host lines, in order (so never a bare "Host");
//   - every commented-out Host line of a disabled region is in the output
//     verbatim;
//   - reading the output again gives the same hosts (raw name, patterns,
//     disabled flag, group).
func legacyWriteKeepsHostLines(text string) error {
	cfg, err := Parse([]byte(text))
	if err != nil {
		return fmt.Errorf("Parse: %v", err)
	}
	out, err := Write(cfg)
	if err != nil {
		return fmt.Errorf("Write: %v", err)
	}
	wantArgs, wantDisabled := inputHostArgs(text)
	var gotArgs []string
	outLines := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		outLines[l] = true
		switch {
		case strings.HasPrefix(l, "Host "):
			gotArgs = append(gotArgs, l[5:])
		case hostLineRe.MatchString(strings.TrimSpace(l)) || strings.EqualFold(strings.TrimSpace(l), "host"):
			return fmt.Errorf("Write emitted an unexpected Host line %q:\n%s", l, out)
		}
	}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		return fmt.Errorf("Host lines changed by Write(Parse()):\n  input:  %q\n  output: %q\n%s", wantArgs, gotArgs, out)
	}
	for _, l := range wantDisabled {
		if !outLines[l] {
			return fmt.Errorf("disabled Host line %q lost by Write(Parse()):\n%s", l, out)
		}
	}
	cfg2, err := Parse(out)
	if err != nil {
		return fmt.Errorf("re-Parse: %v\n%s", err, out)
	}
	type rec struct {
		name     string
		patterns string
		disabled bool
		group    string
	}
	recs := func(c *ConfigFile) []rec {
		var rs []rec
		for _, h := range c.Hosts {
			rs = append(rs, rec{h.Name, strings.Join(h.Patterns, "\x00"), h.Disabled, h.Group})
		}
		return rs
	}
	if a, b := recs(cfg), recs(cfg2); !reflect.DeepEqual(a, b) {
		return fmt.Errorf("hosts differ after Write(Parse()):\n  first:  %+v\n  second: %+v\n%s", a, b, out)
	}
	return nil
}

// The helper itself must see the P2b regression: a writer that emits the
// patterns instead of the raw text is caught on the reviewer's inputs.
func TestLegacyWriteKeepsHostLinesHelper(t *testing.T) {
	for _, c := range legacyHostLines {
		if err := legacyWriteKeepsHostLines(legacyConfig(c.line)); err != nil {
			t.Errorf("%q: %v", c.line, err)
		}
	}
	got, _ := inputHostArgs("Host # c\nHOST=x\nhost\ty z\n" + domain.DisabledMarkerStart("g") + "\n# Host off\n" + domain.DisabledMarkerEnd("g") + "\nHostName not-a-host-line\nHost\n")
	if want := []string{"# c", "x", "y z"}; !reflect.DeepEqual(got, want) {
		t.Errorf("inputHostArgs = %q, want %q", got, want)
	}
}
