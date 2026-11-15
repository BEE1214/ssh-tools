package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// docFixture exercises: preamble (comment, Include, global option), attached
// leading comments, an inline comment, Key=value and "key = value" forms, tab
// indentation, repeated IdentityFile, an interior comment, a section comment
// that belongs to no block, a Match block, a multi-pattern Host line, a
// disabled-group region and a trailing block. LF line endings are assumed.
const docFixture = `# managed by sshm
Include /nonexistent/other.conf
ServerAliveInterval 15

# group: lab
# primary web
Host web-1
  HostName 10.0.0.1   # main addr
  User alice
  IdentityFile ~/.ssh/a
  # keep this
  IdentityFile ~/.ssh/b
  LocalForward 8080 localhost:80
  # trailing note

Host db-1
	HostName=10.0.0.2
	user = bob
	Port 2222

# section: misc

Match host x exec "true"
  User matchy

Host multi-a multi-b
  User shared

# sshm disabled group=old start
# Host old-1
#   HostName 10.0.0.9
# sshm disabled group=old end

Host last
  HostName 10.0.0.3
`

func fixtureDoc() *Doc { return ParseDoc([]byte(docFixture)) }

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestDoc_BytesRoundTrip(t *testing.T) {
	for _, in := range []string{"", "\n", "\n\n", "Host a\n", "Host a\n\n\n", "# only\n", docFixture} {
		if got := string(ParseDoc([]byte(in)).Bytes()); got != in {
			t.Errorf("round trip of %q = %q", in, got)
		}
	}
	// The one normalization: a missing final newline is added.
	if got := string(ParseDoc([]byte("Host a")).Bytes()); got != "Host a\n" {
		t.Errorf("no-final-newline = %q", got)
	}
}

func TestDoc_Blocks(t *testing.T) {
	d := fixtureDoc()
	got := d.Blocks()
	want := []Block{
		// Start includes "# group: lab" and "# primary web"; End includes
		// "# trailing note" (line 13) but not the blank line after it.
		{Names: []string{"web-1"}, Start: 4, End: 14, HostLine: 6},
		{Names: []string{"db-1"}, Start: 15, End: 19, HostLine: 15},
		{Names: []string{"host", "x", "exec", "true"}, Start: 22, End: 24, HostLine: 22, Match: true},
		{Names: []string{"multi-a", "multi-b"}, Start: 25, End: 27, HostLine: 25},
		{Names: []string{"old-1"}, Start: 28, End: 32, HostLine: 29, Disabled: true, Group: "old"},
		{Names: []string{"last"}, Start: 33, End: 35, HostLine: 33},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("blocks =\n%+v\nwant\n%+v", got, want)
	}

	raw := func(i int) string { return strings.Join(d.Raw(got[i]), "\n") }
	if want := "# group: lab\n# primary web\nHost web-1\n  HostName 10.0.0.1   # main addr\n  User alice\n  IdentityFile ~/.ssh/a\n  # keep this\n  IdentityFile ~/.ssh/b\n  LocalForward 8080 localhost:80\n  # trailing note"; raw(0) != want {
		t.Errorf("web-1 span = %q", raw(0))
	}
	if want := "Host db-1\n\tHostName=10.0.0.2\n\tuser = bob\n\tPort 2222"; raw(1) != want {
		t.Errorf("db-1 span = %q (the \"# section\" comment after a blank line must belong to no block)", raw(1))
	}
	if want := "Match host x exec \"true\"\n  User matchy"; raw(2) != want {
		t.Errorf("match span = %q", raw(2))
	}
	if want := "# sshm disabled group=old start\n# Host old-1\n#   HostName 10.0.0.9\n# sshm disabled group=old end"; raw(4) != want {
		t.Errorf("disabled span = %q", raw(4))
	}
	if got[0].HostLine != 6 || d.Lines[got[0].HostLine] != "Host web-1" {
		t.Errorf("web-1 HostLine = %d", got[0].HostLine)
	}
}

func TestDoc_BlockSpanEdgeCases(t *testing.T) {
	cases := []struct {
		name, in string
		spans    []string // joined raw lines per block
	}{
		{"empty block", "Host a\nHost b\n  User x\n", []string{"Host a", "Host b\n  User x"}},
		{"comment directly above next Host attaches to it", "Host a\n  User x\n# about b\nHost b\n", []string{"Host a\n  User x", "# about b\nHost b"}},
		{"comment after a blank belongs to nobody", "Host a\n  User x\n\n# loose\n\nHost b\n", []string{"Host a\n  User x", "Host b"}},
		{"options after a blank line stay in the block", "Host a\n  User x\n\n  Port 22\n", []string{"Host a\n  User x\n\n  Port 22"}},
		{"trailing blank lines excluded", "Host a\n  User x\n\n\n", []string{"Host a\n  User x"}},
		{"case-insensitive keyword and equals form", "host=a\n  user x\nHOST\tb\n", []string{"host=a\n  user x", "HOST\tb"}},
		{"HostName is not a Host line", "HostName x\nHost a\n", []string{"Host a"}},
		{"unterminated marker is opaque to EOF", "Host a\n\n# sshm disabled group=g start\n# Host b\nHost c\n", []string{"Host a", "# sshm disabled group=g start\n# Host b\nHost c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := ParseDoc([]byte(tc.in))
			var got []string
			for _, b := range d.Blocks() {
				got = append(got, strings.Join(d.Raw(b), "\n"))
			}
			if !reflect.DeepEqual(got, tc.spans) {
				t.Errorf("spans = %q, want %q", got, tc.spans)
			}
		})
	}
}

func TestDoc_SetOption(t *testing.T) {
	cases := []struct {
		name, host, key, value string
		old, new               string // one line replaced / inserted ("" = n/a)
		wantInsertAfter        string // existing line the new line must follow
		wantErr                error
	}{
		{name: "keeps inline comment and indent", host: "web-1", key: "HostName", value: "10.9.9.9",
			old: "  HostName 10.0.0.1   # main addr", new: "  HostName 10.9.9.9   # main addr"},
		{name: "keeps key=value style and tab indent", host: "db-1", key: "HostName", value: "10.2.2.2",
			old: "\tHostName=10.0.0.2", new: "\tHostName=10.2.2.2"},
		{name: "keeps key spelling and ' = ' separator", host: "db-1", key: "User", value: "carol",
			old: "\tuser = bob", new: "\tuser = carol"},
		{name: "case-insensitive key match", host: "db-1", key: "PORT", value: "2200",
			old: "\tPort 2222", new: "\tPort 2200"},
		{name: "insert after last option, block's tab indent", host: "db-1", key: "ForwardAgent", value: "yes",
			new: "\tForwardAgent yes", wantInsertAfter: "\tPort 2222"},
		{name: "insert goes before attached trailing comment", host: "web-1", key: "Port", value: "2201",
			new: "  Port 2201", wantInsertAfter: "  LocalForward 8080 localhost:80"},
		{name: "insert into block without options uses 2 spaces", host: "last2", key: "User", value: "z",
			new: "  User z", wantInsertAfter: "Host last2"},
		{name: "canonical key casing on insert", host: "last", key: "serveraliveinterval", value: "30",
			new: "  ServerAliveInterval 30", wantInsertAfter: "  HostName 10.0.0.3"},
		{name: "repeated IdentityFile is ambiguous", host: "web-1", key: "IdentityFile", value: "~/.ssh/c", wantErr: ErrAmbiguousOption},
		{name: "multi-pattern Host line", host: "multi-a", key: "User", value: "x", wantErr: ErrNotPlainHost},
		{name: "Match block", host: "x", key: "User", value: "x", wantErr: ErrNotPlainHost},
		{name: "disabled region", host: "old-1", key: "User", value: "x", wantErr: ErrDisabledBlock},
		{name: "unknown host", host: "nope", key: "User", value: "x", wantErr: ErrBlockNotFound},
		{name: "value with a line break", host: "last", key: "User", value: "a\nProxyCommand evil", wantErr: ErrBadValue},
		{name: "value that would become a comment", host: "last", key: "User", value: "a # b", wantErr: ErrBadValue},
		{name: "empty value", host: "last", key: "User", value: " ", wantErr: ErrBadValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := docFixture + "\nHost last2\n"
			d := ParseDoc([]byte(src))
			before := append([]string(nil), d.Lines...)
			err := d.SetOption(tc.host, tc.key, tc.value)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if !reflect.DeepEqual(d.Lines, before) {
					t.Error("a failed SetOption changed the document")
				}
				return
			}
			mustOK(t, err)
			// Expected result: exactly one line replaced, or exactly one
			// inserted right after the (unique) anchor line.
			var want []string
			for _, l := range before {
				if tc.old != "" && l == tc.old {
					want = append(want, tc.new)
					continue
				}
				want = append(want, l)
				if tc.old == "" && l == tc.wantInsertAfter {
					want = append(want, tc.new)
				}
			}
			if !reflect.DeepEqual(d.Lines, want) {
				t.Errorf("unexpected edit:\n got %q\nwant %q", d.Lines, want)
			}
		})
	}
}

func TestDoc_SetOption_IncludeInsideBlockIsNotAnAnchor(t *testing.T) {
	d := ParseDoc([]byte("Host a\n  User x\n  Include /abs/more.conf\n"))
	mustOK(t, d.SetOption("a", "Port", "22"))
	if got, want := string(d.Bytes()), "Host a\n  User x\n  Port 22\n  Include /abs/more.conf\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDoc_SetOption_ProxyCommandHashIsPartOfValue(t *testing.T) {
	d := ParseDoc([]byte("Host a\n  ProxyCommand ssh -W %h:%p j #1\n"))
	mustOK(t, d.SetOption("a", "ProxyCommand", "nc %h %p # raw"))
	if got, want := string(d.Bytes()), "Host a\n  ProxyCommand nc %h %p # raw\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDoc_SetOption_RepeatedScalarIsAmbiguous(t *testing.T) {
	d := ParseDoc([]byte("Host a\n  User x\n  User y\n"))
	err := d.SetOption("a", "User", "z")
	if !errors.Is(err, ErrAmbiguousOption) || !strings.Contains(err.Error(), "by hand") {
		t.Errorf("err = %v, want ErrAmbiguousOption telling the user to edit by hand", err)
	}
	// A host defined in two blocks is ambiguous as well.
	d = ParseDoc([]byte("Host a\n  User x\n\nHost a\n  Port 1\n"))
	if err := d.SetOption("a", "User", "z"); !errors.Is(err, ErrAmbiguousOption) {
		t.Errorf("duplicate blocks: err = %v", err)
	}
}

func TestDoc_UnsetOption(t *testing.T) {
	d := ParseDoc([]byte("Host a\n  IdentityFile k1\n  User x\n  # c\n  identityfile=k2\n"))
	mustOK(t, d.UnsetOption("a", "IdentityFile"))
	if got, want := string(d.Bytes()), "Host a\n  User x\n  # c\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	mustOK(t, d.UnsetOption("a", "Port")) // absent: no-op
	if got, want := string(d.Bytes()), "Host a\n  User x\n  # c\n"; got != want {
		t.Errorf("no-op changed doc: %q", got)
	}
}

func TestDoc_AddAndRemoveOptionValue(t *testing.T) {
	d := ParseDoc([]byte("Host a\n  IdentityFile k1\n\tIdentityFile=k2\n  User x\n  LocalForward 1 h:1\n"))

	mustOK(t, d.AddOptionValue("a", "IdentityFile", "k3"))
	// After the LAST same-key line, with that line's indentation.
	if got, want := string(d.Bytes()), "Host a\n  IdentityFile k1\n\tIdentityFile=k2\n\tIdentityFile k3\n  User x\n  LocalForward 1 h:1\n"; got != want {
		t.Errorf("add: got %q, want %q", got, want)
	}
	mustOK(t, d.AddOptionValue("a", "IdentityFile", "k3")) // already present: no-op
	mustOK(t, d.AddOptionValue("a", "DynamicForward", "1080"))
	if got, want := string(d.Bytes()), "Host a\n  IdentityFile k1\n\tIdentityFile=k2\n\tIdentityFile k3\n  User x\n  LocalForward 1 h:1\n  DynamicForward 1080\n"; got != want {
		t.Errorf("add new key: got %q, want %q", got, want)
	}

	mustOK(t, d.RemoveOptionValue("a", "IdentityFile", "k2")) // matches "IdentityFile=k2"
	mustOK(t, d.RemoveOptionValue("a", "LocalForward", "1   h:1"))
	if got, want := string(d.Bytes()), "Host a\n  IdentityFile k1\n\tIdentityFile k3\n  User x\n  DynamicForward 1080\n"; got != want {
		t.Errorf("remove: got %q, want %q", got, want)
	}
	if err := d.RemoveOptionValue("a", "IdentityFile", "zz"); !errors.Is(err, ErrOptionNotFound) {
		t.Errorf("err = %v, want ErrOptionNotFound", err)
	}
	if err := d.AddOptionValue("a", "User", "y"); !errors.Is(err, ErrNotListOption) {
		t.Errorf("err = %v, want ErrNotListOption", err)
	}
	if err := d.RemoveOptionValue("a", "Port", "1"); !errors.Is(err, ErrNotListOption) {
		t.Errorf("err = %v, want ErrNotListOption", err)
	}
}

func TestDoc_AppendBlock(t *testing.T) {
	h := domain.Host{Name: "new-1", HostName: "10.0.0.50", Port: "22", IdentityFiles: []string{"~/.ssh/a", "~/.ssh/b"}, Group: "lab"}
	canonical := "# group: lab\nHost new-1\n  HostName 10.0.0.50\n  Port 22\n  IdentityFile ~/.ssh/a\n  IdentityFile ~/.ssh/b\n"

	for name, tc := range map[string]struct{ in, want string }{
		"empty doc":                {"", canonical},
		"previous content":         {"Host a\n  User x\n", "Host a\n  User x\n\n" + canonical},
		"extra trailing blanks":    {"Host a\n  User x\n\n\n\n", "Host a\n  User x\n\n" + canonical},
		"preamble only":            {"# header\n", "# header\n\n" + canonical},
		"comment-only blank lines": {"\n\n", canonical},
	} {
		t.Run(name, func(t *testing.T) {
			d := ParseDoc([]byte(tc.in))
			mustOK(t, d.AppendBlock(h))
			if got := string(d.Bytes()); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}

	d := ParseDoc([]byte("Host new-1\n"))
	if err := d.AppendBlock(h); !errors.Is(err, ErrHostExists) {
		t.Errorf("duplicate: err = %v", err)
	}
	d = ParseDoc([]byte("# sshm disabled group=g start\n# Host new-1\n# sshm disabled group=g end\n"))
	if err := d.AppendBlock(h); !errors.Is(err, ErrHostExists) {
		t.Errorf("name used inside a disabled region: err = %v", err)
	}
	for _, bad := range []domain.Host{{Name: ""}, {Name: "a b"}, {Name: "a", User: "x\nProxyCommand evil"}} {
		if err := ParseDoc(nil).AppendBlock(bad); !errors.Is(err, ErrBadValue) {
			t.Errorf("AppendBlock(%+v) err = %v, want ErrBadValue", bad, err)
		}
	}
}

func TestDoc_DeleteBlock(t *testing.T) {
	cases := []struct{ name, in, host, want string }{
		{"middle: takes the blank after", "Host a\n  U 1\n\nHost b\n  U 2\n\nHost c\n  U 3\n", "b", "Host a\n  U 1\n\nHost c\n  U 3\n"},
		{"last: takes the blank before", "Host a\n  U 1\n\nHost b\n  U 2\n", "b", "Host a\n  U 1\n"},
		{"first", "Host a\n  U 1\n\nHost b\n  U 2\n", "a", "Host b\n  U 2\n"},
		{"only block keeps preamble", "# header\n\nHost a\n  U 1\n", "a", "# header\n"},
		{"leading comments go with the block, section comment stays",
			"Host a\n  U 1\n\n# section\n\n# about b\nHost b\n  U 2\n  # tail\n\nHost c\n", "b", "Host a\n  U 1\n\n# section\n\nHost c\n"},
		{"no blank neighbours: only the span", "Host a\n  U 1\n# about b\nHost b\n  U 2\n", "b", "Host a\n  U 1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := ParseDoc([]byte(tc.in))
			mustOK(t, d.DeleteBlock(tc.host))
			if got := string(d.Bytes()); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDoc_DeleteBlock_Refusals(t *testing.T) {
	src := docFixture + "\nHost wild-*\n  User w\n\nHost *\n  User s\n"
	for host, want := range map[string]error{
		"multi-a":   ErrNotPlainHost,
		"multi-b":   ErrNotPlainHost,
		"x":         ErrNotPlainHost, // token of a Match block
		"old-1":     ErrDisabledBlock,
		"wild-*":    ErrNotPlainHost,
		"*":         ErrNotPlainHost,
		"web-?":     ErrNotPlainHost,
		"!web-1":    ErrNotPlainHost,
		"not-there": ErrBlockNotFound,
	} {
		d := ParseDoc([]byte(src))
		err := d.DeleteBlock(host)
		if !errors.Is(err, want) {
			t.Errorf("DeleteBlock(%q) err = %v, want %v", host, err, want)
		}
		if string(d.Bytes()) != src {
			t.Errorf("DeleteBlock(%q) changed the document despite the error", host)
		}
	}
}

func TestDoc_DuplicateBlock(t *testing.T) {
	d := fixtureDoc()
	mustOK(t, d.DuplicateBlock("web-1", "web-2"))
	want := strings.Replace(docFixture, "  # trailing note\n\nHost db-1",
		"  # trailing note\n\n# group: lab\n# primary web\nHost web-2\n  HostName 10.0.0.1   # main addr\n  User alice\n  IdentityFile ~/.ssh/a\n  # keep this\n  IdentityFile ~/.ssh/b\n  LocalForward 8080 localhost:80\n  # trailing note\n\nHost db-1", 1)
	if got := string(d.Bytes()); got != want {
		t.Errorf("duplicate:\n got %q\nwant %q", got, want)
	}

	// At EOF and when the next line is not blank.
	d = ParseDoc([]byte("Host a # note\n  User x\n"))
	mustOK(t, d.DuplicateBlock("a", "b"))
	if got, want := string(d.Bytes()), "Host a # note\n  User x\n\nHost b # note\n  User x\n"; got != want {
		t.Errorf("EOF: got %q, want %q", got, want)
	}
	d = ParseDoc([]byte("Host a\n  User x\n# about c\nHost c\n"))
	mustOK(t, d.DuplicateBlock("a", "b"))
	if got, want := string(d.Bytes()), "Host a\n  User x\n\nHost b\n  User x\n\n# about c\nHost c\n"; got != want {
		t.Errorf("attached next block: got %q, want %q", got, want)
	}

	for _, tc := range []struct {
		src, dst string
		want     error
	}{
		{"web-1", "db-1", ErrHostExists},
		{"web-1", "old-1", ErrHostExists},
		{"multi-a", "z", ErrNotPlainHost},
		{"old-1", "z", ErrDisabledBlock},
		{"nope", "z", ErrBlockNotFound},
		{"web-1", "a b", ErrBadValue},
	} {
		d := fixtureDoc()
		if err := d.DuplicateBlock(tc.src, tc.dst); !errors.Is(err, tc.want) {
			t.Errorf("DuplicateBlock(%q,%q) err = %v, want %v", tc.src, tc.dst, err, tc.want)
		}
		if string(d.Bytes()) != docFixture {
			t.Errorf("DuplicateBlock(%q,%q) changed the document despite the error", tc.src, tc.dst)
		}
	}
}

func TestDoc_DisableEnableRoundTrip(t *testing.T) {
	d := fixtureDoc()
	mustOK(t, d.DisableBlocks([]string{"web-1", "db-1"}, "lab"))

	// The legacy parser sees exactly the disabled hosts, in group "lab".
	cfg, err := Parse(d.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var dis []string
	for _, h := range cfg.Hosts {
		if h.Disabled && h.Group == "lab" {
			dis = append(dis, h.Name)
		}
	}
	if !reflect.DeepEqual(dis, []string{"web-1", "db-1"}) {
		t.Errorf("legacy Parse sees disabled hosts %v", dis)
	}
	// Every disabled line is commented out: ssh cannot see the hosts.
	for _, b := range d.Blocks() {
		if b.Disabled && b.Group == "lab" {
			for _, l := range d.Raw(b)[1 : len(d.Raw(b))-1] {
				if t2 := strings.TrimSpace(l); t2 != "" && !strings.HasPrefix(t2, "#") {
					t.Errorf("disabled line not commented out: %q", l)
				}
			}
		}
	}
	// Refused while disabled.
	if err := d.SetOption("web-1", "User", "x"); !errors.Is(err, ErrDisabledBlock) {
		t.Errorf("SetOption on disabled host: %v", err)
	}
	if err := d.DisableBlocks([]string{"web-1"}, "lab"); !errors.Is(err, ErrDisabledBlock) {
		t.Errorf("double disable: %v", err)
	}

	mustOK(t, d.EnableGroup("lab"))
	if got := string(d.Bytes()); got != docFixture {
		t.Errorf("Disable->Enable is not byte-for-byte identity:\n got %q\nwant %q", got, docFixture)
	}
	if err := d.EnableGroup("lab"); !errors.Is(err, ErrGroupNotDisabled) {
		t.Errorf("enable of enabled group: %v", err)
	}
	// A group disabled by someone else (legacy file) is enabled as well.
	mustOK(t, d.EnableGroup("old"))
	if strings.Contains(string(d.Bytes()), "sshm disabled") || !strings.Contains(string(d.Bytes()), "\nHost old-1\n  HostName 10.0.0.9\n") {
		t.Errorf("legacy region not restored:\n%s", d.Bytes())
	}
}

func TestDoc_DisableRefusals(t *testing.T) {
	for _, tc := range []struct {
		names []string
		group string
		want  error
	}{
		{[]string{"web-1", "multi-a"}, "g", ErrNotPlainHost}, // second name refuses the whole call
		{[]string{"web-1", "nope"}, "g", ErrBlockNotFound},
		{[]string{"old-1"}, "g", ErrDisabledBlock},
		{[]string{"web-1"}, "bad group", nil},
		{nil, "g", ErrBadValue},
	} {
		d := fixtureDoc()
		err := d.DisableBlocks(tc.names, tc.group)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("DisableBlocks(%v,%q) err = %v, want %v", tc.names, tc.group, err, tc.want)
		}
		if string(d.Bytes()) != docFixture {
			t.Errorf("DisableBlocks(%v,%q) changed the document despite the error", tc.names, tc.group)
		}
	}
}

func TestDoc_UnterminatedMarkerIsNeverEdited(t *testing.T) {
	src := "Host a\n  User x\n\n# sshm disabled group=g start\n# Host b\nHost c\n  User y\n"
	d := ParseDoc([]byte(src))
	if err := d.SetOption("c", "User", "z"); !errors.Is(err, ErrBlockNotFound) && !errors.Is(err, ErrDisabledBlock) {
		t.Errorf("edit below an unterminated marker: %v", err)
	}
	if err := d.EnableGroup("g"); err == nil {
		t.Error("EnableGroup accepted a region without end marker")
	}
	if string(d.Bytes()) != src {
		t.Error("document changed")
	}
}
