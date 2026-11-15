package config

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// P2c, items 3, 6 and 9 (item 1 is in p2c_test.go).

// ---- Item 3 (review R3): the Match exec detector ----

// matchExecCases: Match lines and whether IsMatchExecLine must call them
// exec lines. MARK is replaced by a file in the test's temp dir, so a command
// that really runs leaves a trace there (and only there).
var matchExecCases = []struct {
	line string
	exec bool
}{
	// Real exec criteria, in every form ssh_config(5) / readconf.c accepts.
	{`Match exec "touch MARK"`, true},
	{`Match host probe exec "touch MARK"`, true},
	{`Match exec="touch MARK"`, true},
	{`Match host probe EXEC="touch MARK"`, true},
	{`Match !exec "touch MARK"`, true},
	{`Match host probe !exec="touch MARK"`, true},
	{`Match Exec "touch MARK"`, true},
	{`MATCH EXEC "touch MARK"`, true},
	{`Match "exec" "touch MARK"`, true},
	{`Match=exec "touch MARK"`, true},
	{`Match = exec "touch MARK"`, true},
	{"Match\texec\t\"touch MARK\"", true},
	{`  match  host=probe   exec   "touch MARK"  # note`, true},
	{`Match final exec "touch MARK"`, true},
	{`Match originalhost probe exec "touch MARK"`, true},
	// Not run by this particular `ssh -G probe` (wrong pass, or an earlier
	// criterion already failed), but exec lines all the same.
	{`Match canonical exec "touch MARK"`, true},
	{`Match user nobody-x exec "touch MARK"`, true},
	{`Match host nomatch exec "touch MARK"`, true},
	// Unknown criterion before it: ssh 10.6 refuses the line; counted as
	// exec because another ssh may read it differently (conservative).
	{`Match bogus exec "touch MARK"`, true},
	{`Match host = probe exec "touch MARK"`, true},

	// "exec" as a NAME, not a criterion: nothing runs and verification must
	// not be skipped. The first three are the false positives of review R3.
	{`Match host exec-box`, false},
	{`Match host build.exec`, false},
	{`Match host=exec`, false},
	{`Match host exec`, false},
	{`Match host "exec"`, false},
	{`Match host a,exec`, false},
	{`Match user exec`, false},
	{`Match host probe user exec`, false},
	{`Match localuser exec`, false},
	{`Match originalhost exec`, false},
	{`Match tagged exec`, false},
	{`Match version exec`, false},
	{`Match command exec`, false},
	{`Match sessiontype exec`, false},
	{`Match host exec.example.com user=exec`, false},
	{`Match host !exec`, false},
	{`Match all`, false},
	{`Match final all`, false},
	{`Match host probe # exec "touch MARK"`, false},
	// Not Match lines at all.
	{`Host exec`, false},
	{`ProxyCommand exec nc %h %p`, false},
	{`# Match exec "touch MARK"`, false},
	{`MatchX exec "touch MARK"`, false},
	{`Match`, false},
	{``, false},
}

func TestIsMatchExecLine(t *testing.T) {
	for _, c := range matchExecCases {
		if got := IsMatchExecLine(c.line); got != c.exec {
			t.Errorf("IsMatchExecLine(%q) = %v, want %v", c.line, got, c.exec)
		}
	}
}

// The detector against the real thing. For every case `ssh -G probe` runs on
// a config whose only content is the line; a command, if there is one, only
// creates a marker file INSIDE the test's temp dir.
//   - whenever ssh runs the command, the detector must have said "exec"
//     (never a missed exec line);
//   - for every line the table calls harmless, nothing may run.
//
// A harmless line with no command in it could not run anything whatever ssh
// made of it, so it proves nothing here. Such a line takes part only when it
// has the word "exec" as the argument of another criterion: then a command
// is appended (`Match user exec` becomes `Match user exec "touch MARK"`),
// which ssh WOULD run if it read that "exec" as a criterion. The detector must
// call the extended line harmless too. Lines without any "exec" to
// misread (`Match all`, `Host exec`) stay in TestIsMatchExecLine only.
func TestIsMatchExecLineAgreesWithSSH(t *testing.T) {
	needSSH(t)
	dir := t.TempDir()
	ran, harmless := 0, 0
	for i, c := range matchExecCases {
		line := c.line
		if !strings.Contains(line, "MARK") {
			_, _, isMatch := blockLine(strings.TrimSpace(line))
			if c.exec || !isMatch || !strings.Contains(strings.ToLower(line), "exec") {
				continue // nothing could run: vacuous for this test
			}
			line += ` "touch MARK"`
			if IsMatchExecLine(line) {
				t.Errorf("%q: IsMatchExecLine calls the line with a command appended an exec line", line)
				continue
			}
		}
		mark := filepath.Join(dir, fmt.Sprintf("mark-%d", i))
		cfg := write(t, filepath.Join(dir, fmt.Sprintf("config-%d", i)),
			strings.ReplaceAll(line, "MARK", mark)+"\n  User hit\n")
		// An ssh error is fine: some lines are invalid on purpose.
		exec.Command("ssh", "-F", cfg, "-G", "--", "probe").Run()
		matches, _ := filepath.Glob(mark + "*")
		executed := len(matches) > 0
		if executed {
			ran++
		}
		if executed && !IsMatchExecLine(line) {
			t.Errorf("%q: ssh ran the command but IsMatchExecLine says it is not an exec line", line)
		}
		if !c.exec {
			harmless++
			if executed {
				t.Errorf("%q: listed as harmless, but ssh ran a command", line)
			}
		}
	}
	if ran < 10 {
		t.Errorf("only %d cases really ran their command: the differential proves little", ran)
	}
	if harmless < 15 {
		t.Errorf("only %d harmless lines carried a command that could have run: the harmless half proves little", harmless)
	}
}

// ---- Item 6: markers below a host block ----

// A start marker below a host block with no end marker is a comment for the
// parser (as before P2b) and for ssh; the Doc treats everything from it to
// the end of the file as opaque. Neither path edits that part: the legacy
// writer only drops the comment line (as it drops every comment inside a
// block) and keeps the options around it, the Doc refuses.
func TestUnterminatedMarkerBelowHostBlock(t *testing.T) {
	marker := domain.DisabledMarkerStart("grp")
	in := "Host a\n  HostName 10.0.0.1\n" + marker + "\n  User root\n\nHost b\n  HostName 10.0.0.2\n\nHost *\n  User fallback\n"

	cfg, err := Parse([]byte(in))
	if err != nil {
		t.Fatalf("Parse fails on a config ssh accepts: %v", err)
	}
	if got := hostNames(cfg); !reflect.DeepEqual(got, []string{"a", "b", "*"}) {
		t.Fatalf("hosts = %v", got)
	}
	if cfg.Hosts[0].User != "root" || cfg.Hosts[0].Disabled || cfg.Hosts[1].Disabled {
		t.Errorf("hosts = %+v", cfg.Hosts)
	}
	for _, c := range cfg.Comments {
		if strings.Contains(c.Text, "User root") {
			t.Errorf("an active option was moved into Comments: %q", c.Text)
		}
	}
	out, err := Write(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// ssh reads the file the same way, before and after a legacy write.
	if _, lerr := exec.LookPath("ssh"); lerr == nil {
		dir := t.TempDir()
		before := write(t, filepath.Join(dir, "before"), in)
		after := write(t, filepath.Join(dir, "after"), string(out))
		for name, user := range map[string]string{"a": "root", "b": "fallback", "other": "fallback"} {
			if got := sshUser(t, before, name); got != user {
				t.Errorf("ssh -G %s: user %q, the test expects %q", name, got, user)
			}
			b, _ := sshGRaw(before, name)
			a, _ := sshGRaw(after, name)
			if b != a {
				t.Errorf("ssh -G %s differs after the legacy Parse->Write", name)
			}
			got, _ := domain.EffectiveConfig(cfg.Hosts, name)
			if got.User != user {
				t.Errorf("EffectiveConfig(%s).User = %q, ssh says %q", name, got.User, user)
			}
		}
	}

	// The Doc: a is editable, everything from the marker on is opaque.
	d := ParseDoc([]byte(in))
	blocks := d.Blocks()
	if len(blocks) != 2 || blocks[0].Disabled || !reflect.DeepEqual(blocks[0].Names, []string{"a"}) ||
		!blocks[1].Disabled || blocks[1].End != len(d.Lines) || !reflect.DeepEqual(blocks[1].Names, []string{"b", "*"}) {
		t.Fatalf("Doc blocks = %+v", blocks)
	}
	tail := append([]string(nil), d.Lines[2:]...)
	if err := d.SetOption("b", "User", "x"); !errors.Is(err, ErrDisabledBlock) {
		t.Errorf("SetOption below the marker: %v", err)
	}
	if err := d.DeleteBlock("b"); !errors.Is(err, ErrDisabledBlock) {
		t.Errorf("DeleteBlock below the marker: %v", err)
	}
	if err := d.EnableGroup("grp"); !errors.Is(err, ErrBadValue) {
		t.Errorf("EnableGroup on an unterminated region: %v", err)
	}
	if err := d.AppendBlock(domain.Host{Name: "new-1", HostName: "10.0.0.9"}); !errors.Is(err, ErrUnterminatedRegion) {
		t.Errorf("AppendBlock below an unterminated marker: %v", err)
	}
	if string(d.Bytes()) != in {
		t.Errorf("a refused operation changed the Doc:\n%s", d.Bytes())
	}
	mustOK(t, d.SetOption("a", "Port", "2222"))
	if got := d.Lines[len(d.Lines)-len(tail):]; !reflect.DeepEqual(got, tail) {
		t.Errorf("an edit of the block above changed lines from the marker on:\n%q", got)
	}
}

// An unterminated start marker OUTSIDE a host block still fails the parse, as
// it always has (TestParseDanglingStartMarker): there it would swallow every
// following host. P2c only takes back what P2b widened.
func TestUnterminatedMarkerOutsideBlockStillFails(t *testing.T) {
	in := "Host a\n  HostName 10.0.0.1\n\n" + domain.DisabledMarkerStart("grp") + "\n# Host b\n"
	if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("err = %v", err)
	}
}

// A marker pair below a host block. Chosen behaviour:
//   - around ACTIVE lines the two markers are comments and the lines stay
//     options of the block: what ssh does, and what the parser did before
//     P2b (P2b ended the block there, turned the lines into commented-out
//     text and let the lines after the end marker become global options);
//   - around commented-out lines it is a disabled region that ends the block
//     for now (P2b; Doc.DisableBlocks writes this layout), and option lines
//     right after the end marker still belong to the block above.
//
// In both cases nothing active lands in Comments, which Write emits at the
// top of the file.
func TestParseMarkerPairAroundActiveLines(t *testing.T) {
	start, end := domain.DisabledMarkerStart("grp"), domain.DisabledMarkerEnd("grp")
	for _, c := range []struct {
		name, in string
		hosts    []string
		disabled []bool
	}{
		{
			name:  "pair around active lines",
			in:    "Host a\n  HostName 10.0.0.1\n" + start + "\n  User root\n" + end + "\n  Port 2222\n\nHost z\n  User zed\n",
			hosts: []string{"a", "z"}, disabled: []bool{false, false},
		},
		{
			name:  "pair around a mix of comments and active lines",
			in:    "Host a\n  HostName 10.0.0.1\n" + start + "\n# Host b\n  User root\n" + end + "\n  Port 2222\n\nHost z\n  User zed\n",
			hosts: []string{"a", "z"}, disabled: []bool{false, false},
		},
		{
			name:  "inert region, options after it",
			in:    "Host a\n  HostName 10.0.0.1\n" + start + "\n# Host b\n#   User off\n" + end + "\n  User root\n  # note\n  Port 2222\n\nHost z\n  User zed\n",
			hosts: []string{"a", "b", "z"}, disabled: []bool{false, true, false},
		},
		{
			name:  "inert region, then a blank line: the block is over as always",
			in:    "Host a\n  HostName 10.0.0.1\n  User root\n  Port 2222\n" + start + "\n# Host b\n" + end + "\n\nHost z\n  User zed\n",
			hosts: []string{"a", "b", "z"}, disabled: []bool{false, true, false},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Parse([]byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if got := hostNames(cfg); !reflect.DeepEqual(got, c.hosts) {
				t.Fatalf("hosts = %v, want %v", got, c.hosts)
			}
			for i, want := range c.disabled {
				if cfg.Hosts[i].Disabled != want {
					t.Errorf("host %q disabled = %v, want %v", cfg.Hosts[i].Name, cfg.Hosts[i].Disabled, want)
				}
			}
			if a := cfg.Hosts[0]; a.User != "root" || a.Port != "2222" || a.HostName != "10.0.0.1" {
				t.Errorf("host a = %+v, want user root, port 2222", a)
			}
			for _, cm := range cfg.Comments {
				if strings.Contains(cm.Text, "User root") || strings.Contains(cm.Text, "Port 2222") {
					t.Errorf("an active option was moved into Comments: %q", cm.Text)
				}
			}
			out, err := Write(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, lerr := exec.LookPath("ssh"); lerr != nil {
				return
			}
			dir := t.TempDir()
			before := write(t, filepath.Join(dir, "before"), c.in)
			after := write(t, filepath.Join(dir, "after"), string(out))
			for _, name := range []string{"a", "b", "z", "other"} {
				b, bok := sshGRaw(before, name)
				a, aok := sshGRaw(after, name)
				if !bok || !aok || b != a {
					t.Errorf("ssh -G %s differs after the legacy Parse->Write (ok %v/%v):\n%s", name, bok, aok, out)
				}
			}
			if got := sshG(t, before, "a"); first(got["user"]) != "root" || first(got["port"]) != "2222" {
				t.Errorf("ssh reads host a as user %v port %v; the test expects root, 2222", got["user"], got["port"])
			}
			// A global option would show up for an unrelated host.
			if got := sshG(t, after, "other"); first(got["port"]) != "22" {
				t.Errorf("after the write an unrelated host has port %v: an option of host a became global", got["port"])
			}
		})
	}
}

// ---- Item 9: an Include below "Host *" or "Match all" is not conditional ----

// The cases where Load deliberately says "conditional" although ssh happens
// to apply the file for the probed host: the block above the Include matches
// (nearly) everything, but not by construction. The safe direction: a save
// into such a file is refused.
func TestLoadConditionalIsConservative(t *testing.T) {
	needSSH(t)
	for _, block := range []string{"Host * !somebody", "Host * *", "Match host *", "Match final all", "Host ?*"} {
		dir := t.TempDir()
		inc := write(t, filepath.Join(dir, "inc.conf"), "Host managed\n  User u-managed\n")
		main := write(t, filepath.Join(dir, "config"), block+"\n  Port 2200\nInclude "+inc+"\n")
		l, err := Load(main)
		if err != nil || len(l.Warnings) != 0 {
			t.Fatalf("%q: err=%v warnings=%v", block, err, l.Warnings)
		}
		f, ok := l.Lookup(inc)
		if !ok || !f.Conditional {
			t.Errorf("%q: the Include below it must count as conditional: %+v", block, f)
		}
		if sshUser(t, main, "managed") != "u-managed" {
			t.Errorf("%q: fixture: ssh does not apply the file for this host", block)
		}
	}
}

func TestMatchesEveryHost(t *testing.T) {
	for _, c := range []struct {
		line string
		want bool
	}{
		{"Host *", true}, {`Host "*"`, true}, {"Host=*", true}, {"host\t* # all", true},
		{"Match all", true}, {"match ALL", true}, {"Match all # c", true},
		{"Host * *", false}, {"Host * !x", false}, {"Host !x *", false}, {"Host web-*", false}, {"Host ?*", false}, {"Host # c", false},
		{"Match host *", false}, {"Match final all", false}, {"Match canonical all", false}, {"Match !all", false}, {"Match user x", false},
	} {
		args, isHost, isMatch := blockLine(c.line)
		if !isHost && !isMatch {
			t.Fatalf("%q is not a block line", c.line)
		}
		if got := matchesEveryHost(args, isMatch); got != c.want {
			t.Errorf("matchesEveryHost(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}
