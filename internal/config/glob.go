package config

import (
	"os"
	"path/filepath"
	"sort"
)

// This file expands an Include pattern the way ssh does. ssh does not use the
// C library's glob: OpenSSH carries the OpenBSD glob(3) (openbsd-compat/glob.c,
// used wherever the system one lacks its extensions, which is every Linux) and
// calls it with GLOB_TILDE only. Go's filepath.Glob reads the same pattern
// differently, so sshm would follow other files than ssh:
//
//   - "[!x]" is "any byte but x"; "^" is an ordinary set member ("[^x]" is
//     "^ or x"). Go has it the other way round.
//   - matching is on BYTES: "?" is one byte, so it does not match "é"; Go
//     matches runes.
//   - "[" with no "]" after its first member is a literal "["; "[]x]" is the
//     set "]" and "x"; "[a-]" and "[-a]" hold a literal "-". Go rejects all
//     of these as bad patterns.
//   - a wildcard never matches a leading "." of a file name.
//   - "{a,b}" is literal (no GLOB_BRACE), as in Go.
//
// All of it was measured on OpenSSH 10.6 (TestIncludeGlobAgreesWithSSH and
// TestIncludeGlobRandomAgreesWithSSH repeat the measurement). What is not
// reproduced exactly is refused instead of guessed: compileGlob returns a
// reason and the caller reports the Include as one sshm cannot follow.

// Token kinds of a compiled pattern.
const (
	gLit = iota // one literal byte (b); "/" separates path segments
	gOne        // "?": any one byte
	gAll        // "*": any run of bytes
	gSet        // "[...]": one byte in (or, with neg, not in) ranges
)

type gRange struct{ lo, hi byte }

type gTok struct {
	kind   int
	b      byte
	neg    bool
	ranges []gRange
}

func (t gTok) isSep() bool { return t.kind == gLit && t.b == '/' }

// maxGlobStars bounds the "*" of one path segment. glob(3) limits the
// recursion of its matcher; the exact outcome beyond that is not reproduced.
const maxGlobStars = 8

// maxGlobPattern: glob(3) works in PATH_MAX buffers; a pattern anywhere near
// that is refused.
const maxGlobPattern = 1024

// compileGlob turns pattern into tokens the way glob(3) does (glob() quoting
// pass, then glob0). why is not empty when the pattern uses something this
// code does not reproduce exactly.
func compileGlob(pattern string) (toks []gTok, why string) {
	if len(pattern) > maxGlobPattern {
		return nil, "the pattern is too long"
	}
	// Quoting pass: a backslash makes the next byte ordinary; a backslash at
	// the very end stands for itself.
	type gchar struct {
		b      byte
		quoted bool
	}
	var cs []gchar
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == 0:
			return nil, "the pattern contains a NUL byte"
		case c == '\\' && i+1 < len(pattern):
			i++
			if pattern[i] == '/' {
				// An escaped "/" inside a file name cannot match anything
				// sensible; what glob(3) makes of it is not reproduced.
				return nil, `the pattern contains an escaped "/"`
			}
			cs = append(cs, gchar{pattern[i], true})
		case c == '\\':
			cs = append(cs, gchar{'\\', true})
		default:
			cs = append(cs, gchar{c, false})
		}
	}
	// is: cs[i] exists and is the unquoted byte b.
	is := func(i int, b byte) bool { return i < len(cs) && !cs[i].quoted && cs[i].b == b }

	stars := 0
	for i := 0; i < len(cs); {
		c := cs[i]
		i++
		switch {
		case c.quoted:
			toks = append(toks, gTok{kind: gLit, b: c.b})
		case c.b == '/':
			stars = 0
			toks = append(toks, gTok{kind: gLit, b: '/'})
		case c.b == '?':
			toks = append(toks, gTok{kind: gOne})
		case c.b == '*':
			if n := len(toks); n > 0 && toks[n-1].kind == gAll {
				continue // adjacent stars are one
			}
			if stars++; stars > maxGlobStars {
				return nil, `more "*" in one path segment than sshm follows`
			}
			toks = append(toks, gTok{kind: gAll})
		case c.b == '[':
			q := i
			neg := is(q, '!')
			if neg {
				q++
			}
			// A set needs a first member and a "]" somewhere AFTER it (the
			// first member may itself be "]"). Otherwise the "[" is literal
			// and a "!" behind it is read again as an ordinary byte.
			closed := false
			for j := q + 1; j < len(cs) && !closed; j++ {
				closed = is(j, ']')
			}
			if q >= len(cs) || !closed {
				toks = append(toks, gTok{kind: gLit, b: '['})
				continue
			}
			set := gTok{kind: gSet, neg: neg}
			m := cs[q]
			q++
			for {
				if !m.quoted && m.b == '[' && is(q, ':') {
					// "[:alpha:]" and friends. ssh supports them, but they
					// follow the locale ssh runs in, an unknown class name
					// makes the whole pattern match nothing and an
					// unterminated one makes ssh fail: not reproduced.
					return nil, `the pattern uses a character class ("[[:name:]]")`
				}
				r := gRange{m.b, m.b}
				if is(q, '-') && !is(q+1, ']') {
					if q+1 >= len(cs) {
						return nil, "the pattern has a malformed set"
					}
					r.hi = cs[q+1].b
					q += 2
				}
				if r.lo == '/' || r.hi == '/' {
					// glob(3) splits the pattern at this "/" although it is
					// inside the brackets.
					return nil, `the pattern has a "/" inside "[...]"`
				}
				set.ranges = append(set.ranges, r)
				if q >= len(cs) {
					return nil, "the pattern has a malformed set"
				}
				m = cs[q]
				q++
				if !m.quoted && m.b == ']' {
					break
				}
			}
			toks = append(toks, set)
			i = q
		default:
			toks = append(toks, gTok{kind: gLit, b: c.b})
		}
	}
	return toks, ""
}

// globMatch reports whether the tokens of ONE path segment match name
// completely, byte by byte (glob.c match).
func globMatch(toks []gTok, name string) bool {
	for len(toks) > 0 {
		t := toks[0]
		toks = toks[1:]
		if t.kind == gAll {
			if len(toks) == 0 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if globMatch(toks, name[i:]) {
					return true
				}
			}
			return false
		}
		if name == "" {
			return false
		}
		k := name[0]
		name = name[1:]
		switch t.kind {
		case gSet:
			in := false
			for _, r := range t.ranges {
				if r.lo <= k && k <= r.hi {
					in = true
				}
			}
			if in == t.neg {
				return false
			}
		case gLit:
			if k != t.b {
				return false
			}
		}
	}
	return name == ""
}

// sshGlob returns the paths pattern matches, as glob(3) builds them (the
// pattern's own "//", "/./" and "/../" are kept, so the kernel resolves them
// exactly as it does for ssh) and in glob(3)'s order (byte order of those
// paths). why is not empty when the pattern cannot be followed exactly; then
// there are no paths.
//
// Like glob(3) without GLOB_ERR, a directory that cannot be read matches
// nothing, and a match only has to exist (lstat): a directory or a dangling
// symlink is returned too.
func sshGlob(pattern string) (paths []string, why string) {
	toks, why := compileGlob(pattern)
	if why != "" {
		return nil, why
	}
	var walk func(path string, toks []gTok)
	walk = func(path string, toks []gTok) {
		for {
			if len(toks) == 0 {
				if _, err := os.Lstat(path); err == nil {
					paths = append(paths, path)
				}
				return
			}
			end, meta := 0, false
			for end < len(toks) && !toks[end].isSep() {
				meta = meta || toks[end].kind != gLit
				end++
			}
			if meta {
				seg, rest := toks[:end], toks[end:]
				for _, name := range dirNames(path) {
					// A leading "." must be matched by a literal ".".
					if name[0] == '.' && !(seg[0].kind == gLit && seg[0].b == '.') {
						continue
					}
					if globMatch(seg, name) {
						walk(path+name, rest)
					}
				}
				return
			}
			// A segment without wildcards is taken as it is, then every "/".
			b := make([]byte, 0, end+1)
			for _, t := range toks[:end] {
				b = append(b, t.b)
			}
			toks = toks[end:]
			for len(toks) > 0 && toks[0].isSep() {
				b = append(b, '/')
				toks = toks[1:]
			}
			path += string(b)
		}
	}
	walk("", toks)
	sort.Strings(paths)
	return paths, ""
}

// dirNames lists the entries of dir the way readdir(3) does: with "." and
// "..", which a pattern segment starting with "." can match (".*"). An
// unreadable or missing directory has no entries.
func dirNames(dir string) []string {
	if dir == "" {
		dir = "."
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil
	}
	return append(names, ".", "..")
}

// tidyGlobPath returns filepath.Clean(raw) when that names the same file as
// raw, else raw. Clean resolves ".." lexically; behind a symlinked directory
// that is another file than the one the kernel (and so ssh) reaches.
func tidyGlobPath(raw string) string {
	clean := filepath.Clean(raw)
	if clean == raw {
		return raw
	}
	a, err1 := os.Stat(raw)
	b, err2 := os.Stat(clean)
	if err1 == nil && err2 == nil && os.SameFile(a, b) {
		return clean
	}
	return raw
}
