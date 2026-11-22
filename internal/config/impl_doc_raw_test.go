package config

import (
	"reflect"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

func TestImplRawBytes_RoundTripsExactly(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"", "\n", "\n\n", "Host a\n  User x\n", "Host a\n  User x", "# c\r\nHost a\r\n  User x\r\n",
		"Host a\n\n\n", "x", "Host a\n  User x \t\n",
	} {
		if got := string(ParseDoc([]byte(in)).RawBytes()); got != in {
			t.Errorf("RawBytes(ParseDoc(%q)) = %q", in, got)
		}
	}
}

func TestImplInsertLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		at   int
		line string
		want string
	}{
		{"Host a\n  User x", 0, "Include /x", "Include /x\nHost a\n  User x"}, // stays unterminated
		{"Host a\n  User x\n", 0, "Include /x", "Include /x\nHost a\n  User x\n"},
		{"Host a\n  User x", 2, "# end", "Host a\n  User x\n# end\n"}, // appending terminates
		{"", 0, "Include /x", "Include /x\n"},
		{"Host a\r\n", 0, "Include /x", "Include /x\nHost a\r\n"},
	}
	for _, c := range cases {
		d := ParseDoc([]byte(c.in))
		if err := d.InsertLine(c.at, c.line); err != nil {
			t.Fatal(err)
		}
		if got := string(d.RawBytes()); got != c.want {
			t.Errorf("InsertLine(%q, %d): %q, want %q", c.in, c.at, got, c.want)
		}
	}
	d := ParseDoc([]byte("a\n"))
	for _, bad := range []struct {
		at   int
		line string
	}{{-1, "x"}, {5, "x"}, {0, "a\nb"}, {0, "a\r"}} {
		if err := d.InsertLine(bad.at, bad.line); err == nil {
			t.Errorf("InsertLine(%d, %q) succeeded", bad.at, bad.line)
		}
	}
}

func TestImplAppendRaw(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"Host a\n  User x\n", "Host a\n  User x\n\nHost b\n"},
		{"Host a\n  User x", "Host a\n  User x\n\nHost b\n"},
		{"Host a\n  User x\n\n", "Host a\n  User x\n\nHost b\n"},         // an existing blank line is the separator
		{"Host a\n  User x\n\n\n\n", "Host a\n  User x\n\n\n\nHost b\n"}, // and nothing is trimmed
		{"", "Host b\n"},
	}
	for _, c := range cases {
		d := ParseDoc([]byte(c.in))
		d.AppendRaw([]string{"Host b"})
		if got := string(d.RawBytes()); got != c.want {
			t.Errorf("AppendRaw on %q: %q, want %q", c.in, got, c.want)
		}
	}
	d := ParseDoc([]byte("a\n"))
	d.AppendRaw(nil)
	if string(d.RawBytes()) != "a\n" {
		t.Error("AppendRaw(nil) changed the file")
	}
}

func TestImplRemoveSpans(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, in string
		spans    []Span
		want     string
	}{
		{"blank after goes", "a\n\nB1\nB2\n\nc\n", []Span{{2, 4}}, "a\n\nc\n"},
		{"blank before goes when none after", "a\n\nB1\nc\n", []Span{{2, 3}}, "a\nc\n"},
		{"first block of the file", "B1\n\nc\n", []Span{{0, 1}}, "c\n"},
		{"last block of the file", "a\n\nB1\n", []Span{{2, 3}}, "a\n"},
		{"no blank neighbour", "a\nB1\nc\n", []Span{{1, 2}}, "a\nc\n"},
		{"neighbours share one blank line", "a\n\nB1\n\nB2\n\nc\n", []Span{{2, 3}, {4, 5}}, "a\n\nc\n"},
		// Every span takes its own separator (PLAN-p3-p4 I4, and the frozen
		// helper mgMainCandidates does the same): the blank line before the
		// first and the one after the second go.
		{"adjacent spans, no blank between", "a\n\nB1\nB2\n\nc\n", []Span{{2, 3}, {3, 4}}, "a\nc\n"},
		{"unterminated file, last line kept", "B1\n\nc", []Span{{0, 1}}, "c"},
		{"unterminated file, last line moved", "a\n\nB1", []Span{{2, 3}}, "a\n"},
		{"everything", "B1\n", []Span{{0, 1}}, ""},
	}
	for _, c := range cases {
		d := ParseDoc([]byte(c.in))
		if err := d.RemoveSpans(c.spans); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := string(d.RawBytes()); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	d := ParseDoc([]byte("a\nb\nc\n"))
	for _, bad := range [][]Span{{{2, 1}}, {{0, 9}}, {{1, 2}, {0, 1}}, {{0, 2}, {1, 3}}, {{1, 1}}} {
		if err := d.RemoveSpans(bad); err == nil {
			t.Errorf("RemoveSpans(%v) succeeded", bad)
		}
	}
}

func TestImplRegionHosts(t *testing.T) {
	t.Parallel()
	d := ParseDoc([]byte("Host keep\n  User k\n\n# sshm disabled group=g start\n# Host g-1\n#   User a\n# Host g-2 g-3\n#   User b\n# sshm disabled group=g end\n"))
	var region Block
	for _, b := range d.Blocks() {
		if b.Disabled {
			region = b
		}
	}
	want := []RegionHost{{Line: 4, Names: []string{"g-1"}}, {Line: 6, Names: []string{"g-2", "g-3"}}}
	if got := d.RegionHosts(region); !reflect.DeepEqual(got, want) {
		t.Errorf("RegionHosts = %+v, want %+v", got, want)
	}
	if got := d.RegionHosts(d.Blocks()[0]); got != nil {
		t.Errorf("RegionHosts of an enabled block = %+v", got)
	}
}

func TestImplBlockLinesMatchAppendBlock(t *testing.T) {
	t.Parallel()
	h := domain.Host{Name: "web-9", HostName: "10.0.0.9", User: "u", Port: "2222", Group: "ops"}
	lines, err := BlockLines(h)
	if err != nil {
		t.Fatal(err)
	}
	d := ParseDoc(nil)
	if err := d.AppendBlock(h); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lines, d.Lines) {
		t.Errorf("BlockLines = %q, AppendBlock wrote %q", lines, d.Lines)
	}
	if _, err := BlockLines(domain.Host{Name: "a b"}); err == nil {
		t.Error("BlockLines accepted a name with a blank")
	}
}

func TestImplIncludeTarget(t *testing.T) {
	restore := SetHomeDirForTest("/home/h")
	defer restore()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/abs/x.conf", "/abs/x.conf", true},
		{"~/.ssh/config.d/sshm.conf", "/home/h/.ssh/config.d/sshm.conf", true},
		{"config.d/sshm.conf", "/home/h/.ssh/config.d/sshm.conf", true},
		{"/abs/../abs/x.conf", "/abs/x.conf", true},
		{"/abs/*.conf", "", false},
		{"/abs/%h.conf", "", false},
		{"~nobody/x", "", false},
		{"/abs/[ab].conf", "", false},
	}
	for _, c := range cases {
		got, ok := IncludeTarget(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("IncludeTarget(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
