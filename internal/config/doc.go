package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Doc is a line-based view of the file sshm owns (the managed Include file).
// Unlike ConfigFile/Write it never re-serializes anything: every operation
// edits, inserts or removes whole lines and leaves every other byte alone.
//
// Pure: no I/O, no exec. Assumptions: LF line endings ONLY. CRLF files are
// not supported as such: a trailing "\r" is tolerated when reading and kept
// on lines that are only value-patched, but every new line is written with
// "\n", so a CRLF file ends up with mixed endings (ssh accepts those). A file
// that has content ends with exactly one "\n" after Bytes (a missing final
// newline is added; that is the only normalization ParseDoc+Bytes performs).
//
// Structure rules (see Blocks): a Host line starts a block, a Match line
// starts an opaque block, everything before the first block is preamble
// (Include lines, global options, comments), and a "# sshm disabled group=g
// start" .. "end" region is an opaque disabled block. Host names are split
// with SplitWords, the same splitter Parse uses.
type Doc struct {
	Lines []string // verbatim file lines, no trailing "\n" elements

	base []byte // the bytes the Doc was parsed from, see Base

	// unterminated: the last line has no "\n" in the file the Doc stands for
	// (see RawBytes). Only the raw operations of doc_raw.go look at it.
	unterminated bool
}

// Base returns the exact bytes the Doc was parsed from (nil for a Doc that
// was not read from a file). A save compares them with the file on disk to
// detect that somebody else changed it in between (ErrConflict in app).
func (d *Doc) Base() []byte { return d.base }

// Errors returned by Doc operations. They are sentinels wrapped with context:
// test with errors.Is.
var (
	// ErrAmbiguousOption: the block has several lines for the option (or the
	// host has several blocks), so there is no single line to patch.
	ErrAmbiguousOption = errors.New("ambiguous option")
	// ErrNotPlainHost: the target is a wildcard / multi-pattern Host line or
	// a Match block; sshm only edits blocks that name exactly one plain host.
	ErrNotPlainHost = errors.New("not a plain single host block")
	// ErrBlockNotFound: no Host block with that name.
	ErrBlockNotFound = errors.New("host block not found")
	// ErrDisabledBlock: the host lives inside a disabled group region.
	ErrDisabledBlock = errors.New("host is in a disabled group")
	// ErrHostExists: a block with that name already exists.
	ErrHostExists = errors.New("host already exists")
	// ErrNotListOption: AddOptionValue/RemoveOptionValue on a key that is not
	// a list option.
	ErrNotListOption = errors.New("not a list option")
	// ErrOptionNotFound: RemoveOptionValue found no line with that value.
	ErrOptionNotFound = errors.New("option value not found")
	// ErrBadValue: a key, host name or value that cannot be written as one
	// config line (line break, empty, would start an inline comment).
	ErrBadValue = errors.New("value cannot be written to a config line")
	// ErrGroupNotDisabled: EnableGroup found no disabled region for the group.
	ErrGroupNotDisabled = errors.New("group has no disabled blocks")
	// ErrUnterminatedRegion: the file has a "# sshm disabled group=g start"
	// line with no end marker below it. The Doc treats everything from that
	// line to the end of the file as opaque and never edits it.
	ErrUnterminatedRegion = errors.New("disabled-group start marker without an end marker")
	// ErrReservedKey: Host, Match and Include are structure, not options.
	// Writing one as an option line would open a new block or pull in a
	// file whose hosts no verification probes.
	ErrReservedKey = errors.New("reserved keyword, not an option")
)

// ParseDoc splits raw into lines. It never fails: the Doc is just the lines.
// The Doc remembers raw (a copy) as its Base.
func ParseDoc(raw []byte) *Doc {
	d := &Doc{base: append([]byte(nil), raw...)}
	d.unterminated = len(raw) > 0 && raw[len(raw)-1] != '\n'
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" && len(raw) == 0 {
		return d
	}
	d.Lines = strings.Split(text, "\n")
	return d
}

// Bytes joins the lines, each terminated by "\n" (empty for an empty Doc).
func (d *Doc) Bytes() []byte {
	if len(d.Lines) == 0 {
		return nil
	}
	return []byte(strings.Join(d.Lines, "\n") + "\n")
}

// Block is one editable unit of the file.
type Block struct {
	// Names are the patterns on the Host line. For a Match block they are
	// the Match arguments (so a name can be recognized and refused); for a
	// disabled region they are the host names found inside it.
	Names []string
	// Start, End: the half-open line span [Start, End). It begins with the
	// comment lines directly above the Host line (no blank line between) and
	// ends after the block's last option line plus any comment lines
	// directly below it (no blank between), excluding trailing blank lines.
	// A comment that follows a blank line belongs to no block.
	Start, End int
	HostLine   int  // index of the Host/Match line (first Host line in a disabled region)
	Match      bool // a Match block: opaque, never edited
	Disabled   bool // a disabled-group region: opaque, only EnableGroup touches it
	Group      string
}

// Raw returns the block's verbatim lines.
func (d *Doc) Raw(b Block) []string { return d.Lines[b.Start:b.End] }

type lineKind int

const (
	kBlank lineKind = iota
	kComment
	kOption
	kHost
	kMatch
	kRegion // inside a disabled-group region (markers included)
)

// optLine is an option line split so the value can be replaced alone:
// line == indent + key + sep + value + tail.
type optLine struct {
	indent, key, sep, value, tail string
}

func (o optLine) String() string { return o.indent + o.key + o.sep + o.value + o.tail }

// restOfLineKeys take the whole rest of the line as their value: ssh does not
// treat '#' as a comment start there. These are exactly the four options
// readconf.c reads through its "parse_command" path. Checked against
// OpenSSH 10.6 with `ssh -G`: "KnownHostsCommand /bin/echo x # c" keeps
// "# c", while PKCS11Provider and SecurityKeyProvider (ordinary
// single-argument options) drop it; Match exec takes a quoted argument.
var restOfLineKeys = map[string]bool{
	"proxycommand":      true,
	"localcommand":      true,
	"remotecommand":     true,
	"knownhostscommand": true,
}

// reservedKeys are keywords that are file structure rather than options of a
// block; no option operation may write or remove them.
var reservedKeys = map[string]bool{"host": true, "match": true, "include": true}

func checkNotReserved(key string) error {
	if reservedKeys[strings.ToLower(key)] {
		return fmt.Errorf("%w: %s", ErrReservedKey, key)
	}
	return nil
}

// parseOptLine splits a "Key value", "Key=value" or "Key = value" line. A
// trailing " # comment" (and trailing blanks, "\r") lands in tail. ok is
// false for blank lines, comments and lines without a value.
func parseOptLine(l string) (o optLine, ok bool) {
	i := 0
	for i < len(l) && (l[i] == ' ' || l[i] == '\t') {
		i++
	}
	o.indent = l[:i]
	rest := l[i:]
	if rest == "" || rest[0] == '#' {
		return o, false
	}
	k := strings.IndexAny(rest, " \t=\r")
	if k <= 0 {
		return o, false
	}
	o.key = rest[:k]
	j := k
	for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
		j++
	}
	if j < len(rest) && rest[j] == '=' {
		j++
		for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t') {
			j++
		}
	}
	o.sep = rest[k:j]
	body := rest[j:]
	end := len(body)
	if !restOfLineKeys[strings.ToLower(o.key)] {
		if c := commentStart(body); c >= 0 {
			end = c
		}
	}
	v := strings.TrimRight(body[:end], " \t\r")
	if v == "" {
		return o, false
	}
	o.value = v
	o.tail = body[len(v):]
	return o, true
}

// commentStart returns the index of a '#' that starts an inline comment (at
// the start of s or after a blank, outside quotes), or -1.
func commentStart(s string) int {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return i
		}
	}
	return -1
}

// sameKey compares option keywords like ssh: case-insensitively, with the
// PubkeyAcceptedKeyTypes alias folded.
func sameKey(a, b string) bool {
	return strings.EqualFold(canonicalKey(a), canonicalKey(b))
}

// scan classifies every line and derives the blocks.
func (d *Doc) scan() ([]lineKind, []Block) {
	n := len(d.Lines)
	kinds := make([]lineKind, n)
	type region struct {
		start, end int // [start, end)
		group      string
	}
	var regions []region

	for i := 0; i < n; i++ {
		trimmed := strings.TrimSpace(d.Lines[i])
		if g, ok := domain.IsDisabledMarkerStart(trimmed); ok {
			// Same rule as the parser: the region closes at the first end
			// marker of the same group. Unterminated: opaque up to EOF, so
			// nothing after a broken marker is ever edited.
			j := n - 1
			for k := i + 1; k < n; k++ {
				if eg, ok := domain.IsDisabledMarkerEnd(strings.TrimSpace(d.Lines[k])); ok && eg == g {
					j = k
					break
				}
			}
			for k := i; k <= j; k++ {
				kinds[k] = kRegion
			}
			regions = append(regions, region{i, j + 1, g})
			i = j
			continue
		}
		switch {
		case trimmed == "":
			kinds[i] = kBlank
		case strings.HasPrefix(trimmed, "#"):
			kinds[i] = kComment
		default:
			kinds[i] = kOption
			// blockLine is what Parse uses too: both must agree on what a
			// Host line is and on its names.
			switch _, isHost, isMatch := blockLine(trimmed); {
			case isHost:
				kinds[i] = kHost
			case isMatch:
				kinds[i] = kMatch
			}
		}
	}

	// Block starts: Host/Match lines (with their attached leading comments)
	// and disabled regions, in file order.
	type unit struct {
		start, hostLine int
		region          int // index into regions, or -1
	}
	var units []unit
	ri := 0
	for i := 0; i < n; i++ {
		switch {
		case kinds[i] == kRegion:
			if ri < len(regions) && regions[ri].start == i {
				units = append(units, unit{start: i, hostLine: i, region: ri})
				ri++
			}
			i = regions[ri-1].end - 1
		case kinds[i] == kHost || kinds[i] == kMatch:
			s := i
			for s > 0 && kinds[s-1] == kComment {
				s--
			}
			units = append(units, unit{start: s, hostLine: i, region: -1})
		}
	}

	var blocks []Block
	for ui, u := range units {
		next := n
		if ui+1 < len(units) {
			next = units[ui+1].start
		}
		if u.region >= 0 {
			r := regions[u.region]
			b := Block{Start: r.start, End: r.end, HostLine: r.start, Disabled: true, Group: r.group}
			inner := r.end - 1 // exclude the end marker (an unterminated region has none)
			if !regionClosed(d.Lines, r.start, r.end) {
				inner = r.end
			}
			sawHost := false
			for k := r.start + 1; k < inner; k++ {
				line := uncommentLines([]string{d.Lines[k]})[0]
				if names, isHost, _ := blockLine(strings.TrimSpace(line)); isHost {
					if !sawHost {
						b.HostLine = k
						sawHost = true
					}
					b.Names = append(b.Names, names...)
				}
			}
			blocks = append(blocks, b)
			continue
		}
		last := u.hostLine
		for k := u.hostLine + 1; k < next; k++ {
			if kinds[k] == kOption {
				last = k
			}
		}
		end := last + 1
		for end < next && kinds[end] == kComment {
			end++
		}
		b := Block{Start: u.start, End: end, HostLine: u.hostLine, Match: kinds[u.hostLine] == kMatch}
		b.Names, _, _ = blockLine(strings.TrimSpace(d.Lines[u.hostLine]))
		blocks = append(blocks, b)
	}
	return kinds, blocks
}

// regionClosed reports whether the region [start, end) ends with its end
// marker (false for an unterminated start marker that runs to EOF).
func regionClosed(lines []string, start, end int) bool {
	if end-start < 2 {
		return false
	}
	g, _ := domain.IsDisabledMarkerStart(strings.TrimSpace(lines[start]))
	eg, ok := domain.IsDisabledMarkerEnd(strings.TrimSpace(lines[end-1]))
	return ok && eg == g
}

// Blocks returns the file's blocks in file order.
func (d *Doc) Blocks() []Block {
	_, b := d.scan()
	return b
}

// hasWildcard reports whether a host pattern contains ssh pattern syntax.
func hasWildcard(s string) bool { return strings.ContainsAny(s, "*?!") }

// validName checks a host name that will be written to a Host line.
func validName(name string) error {
	if name == "" || strings.ContainsAny(name, " \t\r\n#=\"'") {
		return fmt.Errorf("%w: host name %q", ErrBadValue, name)
	}
	return nil
}

// lookup finds the one enabled Host block that names host. Several matching
// blocks are ambiguous; a Match block or a disabled region are refused with
// their own error. requirePlain additionally refuses wildcard names.
func (d *Doc) lookup(host string, requirePlain bool) (Block, []lineKind, error) {
	kinds, blocks := d.scan()
	if requirePlain && hasWildcard(host) {
		return Block{}, nil, fmt.Errorf("%w: %q contains a wildcard", ErrNotPlainHost, host)
	}
	var hits []Block
	matchHit := false
	for _, b := range blocks {
		for _, nm := range b.Names {
			if nm != host {
				continue
			}
			if b.Match {
				matchHit = true
			} else {
				hits = append(hits, b)
			}
			break
		}
	}
	// A block whose Host line names only host wins over a line that lists it
	// among several patterns (P7 M2): the first can be edited, the second never.
	var single []Block
	for _, b := range hits {
		if len(b.Names) == 1 {
			single = append(single, b)
		}
	}
	if len(single) > 0 {
		hits = single
	}
	switch {
	case len(hits) == 0 && matchHit:
		return Block{}, nil, fmt.Errorf("%w: %q is part of a Match block, which sshm never edits", ErrNotPlainHost, host)
	case len(hits) == 0:
		return Block{}, nil, fmt.Errorf("%w: %q", ErrBlockNotFound, host)
	case len(hits) > 1:
		return Block{}, nil, fmt.Errorf("%w: host %q is defined in %d blocks of the managed file; edit the file by hand", ErrAmbiguousOption, host, len(hits))
	}
	b := hits[0]
	if b.Disabled {
		return Block{}, nil, fmt.Errorf("%w: %q is in disabled group %q; enable the group first", ErrDisabledBlock, host, b.Group)
	}
	if len(b.Names) != 1 {
		return Block{}, nil, fmt.Errorf("%w: %q shares its Host line with %v", ErrNotPlainHost, host, b.Names)
	}
	return b, kinds, nil
}

// optionLines returns the indices of the block's option lines for key.
func (d *Doc) optionLines(b Block, kinds []lineKind, key string) []int {
	var idx []int
	for i := b.HostLine + 1; i < b.End; i++ {
		if kinds[i] != kOption {
			continue
		}
		if o, ok := parseOptLine(d.Lines[i]); ok && sameKey(o.key, key) {
			idx = append(idx, i)
		}
	}
	return idx
}

// lastOptionLine is the index of the block's last option line that is not an
// Include (an Include is conditional on the block above it and a new option
// must not be placed after it), or the Host line when there is none.
func (d *Doc) lastOptionLine(b Block, kinds []lineKind) int {
	last := b.HostLine
	for i := b.HostLine + 1; i < b.End; i++ {
		if kinds[i] != kOption {
			continue
		}
		if o, ok := parseOptLine(d.Lines[i]); ok && !strings.EqualFold(o.key, "include") {
			last = i
		}
	}
	return last
}

// blockIndent is the indentation of the block's first option line ("  " when
// it has none).
func (d *Doc) blockIndent(b Block, kinds []lineKind) string {
	for i := b.HostLine + 1; i < b.End; i++ {
		if kinds[i] == kOption {
			if o, ok := parseOptLine(d.Lines[i]); ok {
				return o.indent
			}
		}
	}
	return "  "
}

// insertAt inserts lines before index at.
func (d *Doc) insertAt(at int, lines ...string) {
	out := make([]string, 0, len(d.Lines)+len(lines))
	out = append(out, d.Lines[:at]...)
	out = append(out, lines...)
	out = append(out, d.Lines[at:]...)
	d.Lines = out
}

// checkKeyValue validates what will be written as "key value". Host, Match
// and Include are refused (ErrReservedKey).
func checkKeyValue(key, value string) error {
	if key == "" || strings.ContainsAny(key, " \t\r\n=#\"'") {
		return fmt.Errorf("%w: option name %q", ErrBadValue, key)
	}
	if err := checkNotReserved(key); err != nil {
		return err
	}
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%w: value %q for %s", ErrBadValue, value, key)
	}
	if !restOfLineKeys[strings.ToLower(key)] && commentStart(value) >= 0 {
		return fmt.Errorf("%w: value %q for %s would start a comment", ErrBadValue, value, key)
	}
	return nil
}

// SetOption sets key to value in host's block by patching ONE line.
//   - one existing line: only its value is replaced; indentation, key
//     spelling, separator ("Key value" / "Key=value") and a trailing
//     " # comment" stay.
//   - no line: a new "<indent>Key value" line goes after the block's last
//     option line, using the indentation of the block's first option.
//   - several lines (a repeated key, several IdentityFile lines, or several
//     blocks for the host): ErrAmbiguousOption, edit the file by hand.
func (d *Doc) SetOption(host, key, value string) error {
	if err := checkKeyValue(key, value); err != nil {
		return err
	}
	b, kinds, err := d.lookup(host, false)
	if err != nil {
		return err
	}
	idx := d.optionLines(b, kinds, key)
	switch len(idx) {
	case 0:
		d.insertAt(d.lastOptionLine(b, kinds)+1, d.blockIndent(b, kinds)+canonicalKey(key)+" "+value)
	case 1:
		o, _ := parseOptLine(d.Lines[idx[0]])
		o.value = value
		d.Lines[idx[0]] = o.String()
	default:
		return fmt.Errorf("%w: host %q has %d %s lines; edit the file by hand",
			ErrAmbiguousOption, host, len(idx), key)
	}
	return nil
}

// UnsetOption removes every line for key from host's block (none: no-op).
// Reserved keywords are refused: removing an Include line inside a block is
// not an option edit.
func (d *Doc) UnsetOption(host, key string) error {
	if err := checkNotReserved(key); err != nil {
		return err
	}
	b, kinds, err := d.lookup(host, false)
	if err != nil {
		return err
	}
	d.removeLines(d.optionLines(b, kinds, key))
	return nil
}

// removeLines removes the given (ascending) line indices.
func (d *Doc) removeLines(idx []int) {
	if len(idx) == 0 {
		return
	}
	drop := make(map[int]bool, len(idx))
	for _, i := range idx {
		drop[i] = true
	}
	out := make([]string, 0, len(d.Lines))
	for i, l := range d.Lines {
		if !drop[i] {
			out = append(out, l)
		}
	}
	d.Lines = out
}

var listKeys = []string{"IdentityFile", "CertificateFile", "LocalForward", "RemoteForward", "DynamicForward"}

func isListKey(key string) bool {
	for _, k := range listKeys {
		if sameKey(k, key) {
			return true
		}
	}
	return false
}

// sameValue compares option values ignoring blank-run differences.
func sameValue(a, b string) bool {
	return strings.Join(strings.Fields(a), " ") == strings.Join(strings.Fields(b), " ")
}

// AddOptionValue appends "key value" to host's block for a list option
// (IdentityFile, CertificateFile, LocalForward, RemoteForward,
// DynamicForward), after the last line of the same key (else after the
// block's last option line). A value that is already present is a no-op.
func (d *Doc) AddOptionValue(host, key, value string) error {
	if !isListKey(key) {
		return fmt.Errorf("%w: %s", ErrNotListOption, key)
	}
	if err := checkKeyValue(key, value); err != nil {
		return err
	}
	b, kinds, err := d.lookup(host, false)
	if err != nil {
		return err
	}
	idx := d.optionLines(b, kinds, key)
	for _, i := range idx {
		if o, _ := parseOptLine(d.Lines[i]); sameValue(o.value, value) {
			return nil
		}
	}
	if len(idx) == 0 {
		d.insertAt(d.lastOptionLine(b, kinds)+1, d.blockIndent(b, kinds)+canonicalKey(key)+" "+value)
		return nil
	}
	last := idx[len(idx)-1]
	o, _ := parseOptLine(d.Lines[last])
	d.insertAt(last+1, o.indent+canonicalKey(key)+" "+value)
	return nil
}

// RemoveOptionValue removes the line(s) of a list option whose value equals
// value (blank runs ignored); other lines of the key stay. ErrOptionNotFound
// when nothing matches.
func (d *Doc) RemoveOptionValue(host, key, value string) error {
	if !isListKey(key) {
		return fmt.Errorf("%w: %s", ErrNotListOption, key)
	}
	b, kinds, err := d.lookup(host, false)
	if err != nil {
		return err
	}
	var hit []int
	for _, i := range d.optionLines(b, kinds, key) {
		if o, _ := parseOptLine(d.Lines[i]); sameValue(o.value, value) {
			hit = append(hit, i)
		}
	}
	if len(hit) == 0 {
		return fmt.Errorf("%w: host %q has no %s %q", ErrOptionNotFound, host, key, value)
	}
	d.removeLines(hit)
	return nil
}

// exists reports whether any block (enabled or disabled) names host.
func exists(blocks []Block, host string) bool {
	for _, b := range blocks {
		if b.Match {
			continue
		}
		for _, nm := range b.Names {
			if nm == host {
				return true
			}
		}
	}
	return false
}

// AppendBlock adds a fresh block for h at the end, in sshm's canonical
// format (writeHostBlock), separated from the previous content by exactly
// one blank line. The name must not exist yet.
func (d *Doc) AppendBlock(h domain.Host) error {
	lines, err := BlockLines(h)
	if err != nil {
		return err
	}
	blocks := d.Blocks()
	if exists(blocks, h.Name) {
		return fmt.Errorf("%w: %q", ErrHostExists, h.Name)
	}
	// A start marker without an end marker makes everything below it opaque
	// up to the end of the file. A block appended there would land inside
	// that region: no Doc operation could ever reach it again.
	for _, b := range blocks {
		if b.Disabled && !regionClosed(d.Lines, b.Start, b.End) {
			return fmt.Errorf("%w: line %d (group %q); nothing is added below it, fix the file by hand",
				ErrUnterminatedRegion, b.Start+1, b.Group)
		}
	}
	end := len(d.Lines)
	for end > 0 && strings.TrimSpace(d.Lines[end-1]) == "" {
		end--
	}
	out := append([]string(nil), d.Lines[:end]...)
	if end > 0 {
		out = append(out, "")
	}
	d.Lines = append(out, lines...)
	return nil
}

// DeleteBlock removes host's block plus ONE adjacent blank separator line,
// but only when that cannot glue its neighbours together (a comment that
// followed a blank line must not become the trailing comment of the previous
// block or the leading comment of the next one):
//   - the blank line after the block goes if the block starts the file or is
//     itself preceded by a blank line;
//   - for a block with nothing but blank lines after it, the blank line
//     before it goes;
//   - otherwise only the block's own lines go.
//
// Disabled regions, Match blocks, wildcard names and Host lines with several
// patterns are refused.
func (d *Doc) DeleteBlock(name string) error {
	b, _, err := d.lookup(name, true)
	if err != nil {
		return err
	}
	blank := func(i int) bool { return strings.TrimSpace(d.Lines[i]) == "" }
	tailBlank := true
	for i := b.End; i < len(d.Lines); i++ {
		tailBlank = tailBlank && blank(i)
	}
	start, end := b.Start, b.End
	switch {
	case end < len(d.Lines) && blank(end) && (start == 0 || blank(start-1)):
		end++
	case tailBlank && start > 0 && blank(start-1):
		start--
	}
	d.Lines = append(append([]string(nil), d.Lines[:start]...), d.Lines[end:]...)
	return nil
}

// DuplicateBlock copies src's raw lines (comments included) to a new block
// named dst, changing only the Host line's name, and inserts it after src
// separated by one blank line.
func (d *Doc) DuplicateBlock(src, dst string) error {
	if err := validName(dst); err != nil {
		return err
	}
	b, _, err := d.lookup(src, true)
	if err != nil {
		return err
	}
	if exists(d.Blocks(), dst) {
		return fmt.Errorf("%w: %q", ErrHostExists, dst)
	}
	cp := append([]string(nil), d.Lines[b.Start:b.End]...)
	o, ok := parseOptLine(cp[b.HostLine-b.Start])
	if !ok {
		return fmt.Errorf("%w: cannot rewrite the Host line of %q", ErrNotPlainHost, src)
	}
	o.value = dst
	cp[b.HostLine-b.Start] = o.String()

	ins := append([]string{""}, cp...)
	if b.End < len(d.Lines) && strings.TrimSpace(d.Lines[b.End]) != "" {
		ins = append(ins, "")
	}
	d.insertAt(b.End, ins...)
	return nil
}

// DisableBlocks wraps each named block in "# sshm disabled group=<group>
// start/end" markers with every non-blank line prefixed "# " (the format of
// the group disable of earlier sshm versions, so the parser and ssh both see
// commented-out text). All names are checked first: on error nothing changes.
func (d *Doc) DisableBlocks(names []string, group string) error {
	if err := domain.ValidateGroupName(group); err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("%w: no hosts to disable", ErrBadValue)
	}
	var targets []Block
	seen := map[int]bool{}
	for _, nm := range names {
		b, _, err := d.lookup(nm, true)
		if err != nil {
			return err
		}
		if !seen[b.Start] {
			seen[b.Start] = true
			targets = append(targets, b)
		}
	}
	// Rewrite from the bottom up so earlier indices stay valid.
	sortBlocksDesc(targets)
	for _, b := range targets {
		wrapped := []string{domain.DisabledMarkerStart(group)}
		for _, l := range d.Lines[b.Start:b.End] {
			wrapped = append(wrapped, commentOutLine(l))
		}
		wrapped = append(wrapped, domain.DisabledMarkerEnd(group))
		d.Lines = append(append(append([]string(nil), d.Lines[:b.Start]...), wrapped...), d.Lines[b.End:]...)
	}
	return nil
}

// EnableGroup restores every disabled region of group to the exact lines it
// was made from. ErrGroupNotDisabled when the Doc has none.
func (d *Doc) EnableGroup(group string) error {
	var regions []Block
	for _, b := range d.Blocks() {
		if b.Disabled && b.Group == group {
			regions = append(regions, b)
		}
	}
	if len(regions) == 0 {
		return fmt.Errorf("%w: %q", ErrGroupNotDisabled, group)
	}
	for _, r := range regions {
		if !regionClosed(d.Lines, r.Start, r.End) {
			return fmt.Errorf("%w: group %q has a start marker without an end marker; fix the file by hand", ErrBadValue, group)
		}
	}
	sortBlocksDesc(regions)
	for _, r := range regions {
		inner := uncommentLines(d.Lines[r.Start+1 : r.End-1])
		d.Lines = append(append(append([]string(nil), d.Lines[:r.Start]...), inner...), d.Lines[r.End:]...)
	}
	return nil
}

func sortBlocksDesc(bs []Block) {
	for i := 1; i < len(bs); i++ {
		for j := i; j > 0 && bs[j-1].Start < bs[j].Start; j-- {
			bs[j-1], bs[j] = bs[j], bs[j-1]
		}
	}
}
