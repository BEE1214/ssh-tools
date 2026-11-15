package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Raw line operations for the hand-owned main file (sshm setup, sshm init,
// sshm import). They work on a Doc like the managed-file operations, but they
// touch NOTHING except the lines they name, and RawBytes gives the bytes back
// exactly: unlike Bytes it does not add a missing final newline to a file that
// was left without one, and CRLF endings stay on the lines that already had
// them.

// RawBytes joins the lines like Bytes, except that a Doc parsed from bytes
// without a final newline keeps its last line unterminated for as long as
// that line is the last one (InsertLine, AppendRaw and RemoveSpans maintain
// this). Use it for files whose other bytes must not change.
func (d *Doc) RawBytes() []byte {
	if len(d.Lines) == 0 {
		return nil
	}
	s := strings.Join(d.Lines, "\n")
	if !d.unterminated {
		s += "\n"
	}
	return []byte(s)
}

// InsertLine inserts line before index at (0-based; len(Lines) appends).
func (d *Doc) InsertLine(at int, line string) error {
	if at < 0 || at > len(d.Lines) {
		return fmt.Errorf("%w: line index %d out of range", ErrBadValue, at)
	}
	if strings.ContainsAny(line, "\r\n") {
		return fmt.Errorf("%w: line %q", ErrBadValue, line)
	}
	if at == len(d.Lines) {
		d.unterminated = false
	}
	d.insertAt(at, line)
	return nil
}

// AppendRaw appends lines at the end. When the file does not already end with
// a blank line and has content, one blank line separates the old and the new
// content; the existing lines (blank ones at the end too) are never touched.
func (d *Doc) AppendRaw(lines []string) {
	if len(lines) == 0 {
		return
	}
	out := append([]string(nil), d.Lines...)
	if n := len(out); n > 0 && strings.TrimSpace(out[n-1]) != "" {
		out = append(out, "")
	}
	d.Lines = append(out, lines...)
	d.unterminated = false
}

// Span is a half-open range [From, To) of 0-based line indices.
type Span struct{ From, To int }

// RemoveSpans removes the given line ranges (ascending, not overlapping) and,
// for each of them, ONE adjacent blank line as the separator that belonged to
// it: the blank line right after the span, else the blank line right before
// it, unless that line is gone already (a span that follows another one with
// one blank line between them shares that blank line). Every other line stays
// byte for byte.
func (d *Doc) RemoveSpans(spans []Span) error {
	n := len(d.Lines)
	drop := make([]bool, n)
	prevEnd := 0
	for _, s := range spans {
		if s.From < prevEnd || s.To <= s.From || s.To > n {
			return fmt.Errorf("%w: span [%d,%d) of %d lines", ErrBadValue, s.From, s.To, n)
		}
		prevEnd = s.To
		for i := s.From; i < s.To; i++ {
			drop[i] = true
		}
	}
	blank := func(i int) bool { return i >= 0 && i < n && !drop[i] && strings.TrimSpace(d.Lines[i]) == "" }
	for _, s := range spans {
		switch {
		case blank(s.To):
			drop[s.To] = true
		case blank(s.From - 1):
			drop[s.From-1] = true
		}
	}
	out := make([]string, 0, n)
	for i, l := range d.Lines {
		if !drop[i] {
			out = append(out, l)
		}
	}
	if n > 0 && drop[n-1] {
		d.unterminated = false
	}
	d.Lines = out
	return nil
}

// RegionHost is one Host line inside a disabled-group region.
type RegionHost struct {
	Line  int      // 0-based index of the (commented-out) Host line
	Names []string // the patterns on it
}

// RegionHosts lists the Host lines inside the disabled region b, in file
// order. A region the legacy group disable wrote holds the adjacent hosts of
// the group between ONE pair of markers, so a region can name several hosts.
func (d *Doc) RegionHosts(b Block) []RegionHost {
	if !b.Disabled {
		return nil
	}
	inner := b.End
	if regionClosed(d.Lines, b.Start, b.End) {
		inner = b.End - 1
	}
	var out []RegionHost
	for k := b.Start + 1; k < inner; k++ {
		line := uncommentLines([]string{d.Lines[k]})[0]
		if names, isHost, _ := blockLine(strings.TrimSpace(line)); isHost {
			out = append(out, RegionHost{Line: k, Names: names})
		}
	}
	return out
}

// BlockLines renders h as sshm's canonical block (the format AppendBlock
// writes): an optional "# group:" comment, the Host line and the options.
func BlockLines(h domain.Host) ([]string, error) {
	if err := validName(h.Name); err != nil {
		return nil, err
	}
	if err := checkLineBreaks(h); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadValue, err)
	}
	var buf strings.Builder
	buf.WriteString(groupCommentFor(h))
	writeHostBlock(&buf, h)
	return strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n"), nil
}

// HomeDir is the passwd home directory ssh uses for "~" and for relative
// Include paths (see homeDir).
func HomeDir() string { return homeDir() }

// IncludeTarget returns the file an Include pattern names without consulting
// the file system, for a pattern without glob characters ("~" and relative
// paths resolved like ExpandInclude does). ok is false for glob patterns and
// for patterns sshm cannot expand (tokens, ~user).
func IncludeTarget(pattern string) (path string, ok bool) {
	if strings.ContainsAny(pattern, "*?[%$") || strings.HasPrefix(pattern, "~") && pattern != "~" && !strings.HasPrefix(pattern, "~/") {
		return "", false
	}
	home := homeDir()
	p := pattern
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return "", false
		}
		p = home + p[1:]
	case !filepath.IsAbs(p):
		if home == "" {
			return "", false
		}
		p = home + "/.ssh/" + p
	}
	return filepath.Clean(p), true
}
