package config

// Review fix F4: AppendRaw rejects lines containing CR or LF like InsertLine
// does, and leaves the Doc untouched on error.

import (
	"errors"
	"reflect"
	"testing"
)

func TestAppendRaw_RejectsLineBreaksAndLeavesTheDocUntouched(t *testing.T) {
	t.Parallel()
	for _, bad := range [][]string{
		{"Host b\n  User x"},
		{"Host b\r"},
		{"Host b", "  User x\r\n"}, // a good line before the bad one is not appended either
		{"a\nb", "c"},
	} {
		for _, in := range []string{"Host a\n  User x\n", "Host a\n  User x", ""} {
			d := ParseDoc([]byte(in))
			lines := append([]string(nil), d.Lines...)
			err := d.AppendRaw(bad)
			if err == nil {
				t.Errorf("AppendRaw(%q) on %q succeeded", bad, in)
				continue
			}
			if !errors.Is(err, ErrBadValue) {
				t.Errorf("AppendRaw(%q) error = %v, want ErrBadValue", bad, err)
			}
			if !reflect.DeepEqual(d.Lines, lines) || string(d.RawBytes()) != in {
				t.Errorf("AppendRaw(%q) on %q changed the Doc: lines %q, bytes %q", bad, in, d.Lines, d.RawBytes())
			}
		}
	}
}

func TestAppendRaw_ValidLinesBehaveAsBefore(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in    string
		lines []string
		want  string
	}{
		{"Host a\n  User x\n", []string{"Host b", "  HostName h"}, "Host a\n  User x\n\nHost b\n  HostName h\n"},
		{"Host a\n  User x", []string{"Host b"}, "Host a\n  User x\n\nHost b\n"},
		{"Host a\n\n", []string{"Host b"}, "Host a\n\nHost b\n"},
		{"", []string{"Host b"}, "Host b\n"},
		{"Host a\n", nil, "Host a\n"},
		{"Host a", []string{}, "Host a"}, // nothing to append: even the missing final newline stays
	}
	for _, c := range cases {
		d := ParseDoc([]byte(c.in))
		if err := d.AppendRaw(c.lines); err != nil {
			t.Errorf("AppendRaw(%q) on %q: %v", c.lines, c.in, err)
			continue
		}
		if got := string(d.RawBytes()); got != c.want {
			t.Errorf("AppendRaw(%q) on %q: %q, want %q", c.lines, c.in, got, c.want)
		}
	}
}
