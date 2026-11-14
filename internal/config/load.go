package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// maxIncludeDepth is OpenSSH's READCONF_MAX_DEPTH: Include nesting deeper
// than this is refused.
const maxIncludeDepth = 16

// IncludeDirective is one Include line: the 1-indexed line it is on and its
// raw (quote-stripped, not yet expanded) patterns.
type IncludeDirective struct {
	Line     int
	Patterns []string
}

// File is one parsed config file of a Loaded set.
type File struct {
	Path string
	Cfg  *ConfigFile
}

// Loaded is the read-only result of following Include directives from a main
// config file. It is deliberately a different type from ConfigFile: the merged
// Hosts view must never be handed to Write, which would flatten included
// files into the main file.
type Loaded struct {
	// Files lists every file read, in ssh evaluation order, main file first.
	Files []File
	// Hosts is the merged host list in evaluation order: hosts of an included
	// file are inlined at the position of the Include line. Every host has
	// SourceFile set.
	Hosts []domain.Host
	// Warnings are non-fatal problems: unreadable or unparsable includes,
	// depth exceeded, cycles, unsupported % / $ tokens.
	Warnings []string
}

// MainPath is the path of the main file (always Files[0]).
func (l *Loaded) MainPath() string { return l.Files[0].Path }

// homeDir returns the passwd home directory, which is what OpenSSH uses for
// "~" and for relative Include paths (it ignores $HOME). A variable so tests
// can point it at a temp dir and never touch the real ~/.ssh.
var homeDir = func() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return os.Getenv("HOME")
}

// SetHomeDirForTest points the "~" / relative-Include home lookup at dir and
// returns a function that restores the previous lookup. For tests of other
// packages, which must never resolve Include paths into the real ~/.ssh.
func SetHomeDirForTest(dir string) (restore func()) {
	prev := homeDir
	homeDir = func() string { return dir }
	return func() { homeDir = prev }
}

// Load parses mainPath and every file reachable from it through Include,
// the way OpenSSH evaluates them. An error is returned only when the main
// file cannot be read or parsed; problems with included files become
// Loaded.Warnings and the file is skipped.
//
// Read model, not an ssh emulator: an Include that sits inside a Host or
// Match block is conditional in ssh (it only applies while that block
// matches). Load follows it unconditionally so the hosts it defines are
// visible; it does not evaluate conditions.
//
// A file reachable twice is read once (the second Include is reported as a
// warning); ssh would read it twice, which only matters for list options.
func Load(mainPath string) (*Loaded, error) {
	abs, err := filepath.Abs(mainPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	l := &loader{out: &Loaded{}, seen: map[string]bool{canonPath(abs): true}}
	l.walk(abs, cfg, []string{canonPath(abs)}, 0)
	return l.out, nil
}

type loader struct {
	out  *Loaded
	seen map[string]bool // canonical paths already read
}

func (l *loader) warnf(format string, args ...any) {
	l.out.Warnings = append(l.out.Warnings, fmt.Sprintf(format, args...))
}

// walk records the file and appends its hosts, inlining each included file
// right before the first host that follows the Include line. chain holds the
// canonical paths of the files currently being included (cycle guard).
func (l *loader) walk(path string, cfg *ConfigFile, chain []string, depth int) {
	l.out.Files = append(l.out.Files, File{Path: path, Cfg: cfg})

	next := 0
	flushIncludes := func(beforeLine int) {
		for next < len(cfg.Includes) && cfg.Includes[next].Line < beforeLine {
			l.follow(path, cfg.Includes[next], chain, depth)
			next++
		}
	}
	for _, h := range cfg.Hosts {
		// Disabled hosts (negative LineStart) are commented out and carry no
		// position; they never trigger an include.
		if !h.Disabled && h.LineStart > 0 {
			flushIncludes(h.LineStart)
		}
		h.SourceFile = path
		l.out.Hosts = append(l.out.Hosts, h)
	}
	flushIncludes(int(^uint(0) >> 1))
}

func (l *loader) follow(from string, inc IncludeDirective, chain []string, depth int) {
	for _, pat := range inc.Patterns {
		paths, warn := ExpandInclude(pat)
		if warn != "" {
			l.warnf("%s:%d: %s", from, inc.Line, warn)
		}
		for _, p := range paths {
			l.include(from, inc.Line, p, chain, depth)
		}
	}
}

func (l *loader) include(from string, line int, p string, chain []string, depth int) {
	key := canonPath(p)
	switch {
	case slices.Contains(chain, key):
		l.warnf("%s:%d: include cycle: %s is already being included", from, line, p)
		return
	case depth+1 > maxIncludeDepth:
		l.warnf("%s:%d: include depth limit (%d) exceeded, skipping %s", from, line, maxIncludeDepth, p)
		return
	case l.seen[key]:
		l.warnf("%s:%d: %s is already included elsewhere, skipping the repeat", from, line, p)
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		l.warnf("%s:%d: cannot read include %s: %v", from, line, p, err)
		return
	}
	cfg, err := Parse(raw)
	if err != nil {
		l.warnf("%s:%d: cannot parse include %s: %v", from, line, p, err)
		return
	}
	l.seen[key] = true
	l.walk(filepath.Clean(p), cfg, append(slices.Clone(chain), key), depth+1)
}

// canonPath returns an absolute, symlink-free form of p when it can be
// computed, for cycle and repeat detection.
func canonPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	if a, err := filepath.Abs(p); err == nil {
		p = a
	}
	return filepath.Clean(p)
}

// ExpandInclude resolves one Include pattern to the existing regular files it
// names, in glob (lexical) order. It mirrors OpenSSH:
//   - "~" and "~/..." expand to the passwd home, not $HOME;
//   - a relative pattern is relative to <home>/.ssh, not to the including file;
//   - a pattern matching nothing (or a missing file) yields no paths and no
//     warning;
//   - patterns with % or $ tokens are not supported yet: no paths, a warning.
func ExpandInclude(pattern string) ([]string, string) {
	if strings.ContainsAny(pattern, "%$") {
		return nil, fmt.Sprintf("Include %q: %% and $ tokens are not supported yet, skipped", pattern)
	}

	p := pattern
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		home := homeDir()
		if home == "" {
			return nil, fmt.Sprintf("Include %q: cannot determine home directory, skipped", pattern)
		}
		p = filepath.Join(home, p[1:])
	case strings.HasPrefix(p, "~"):
		return nil, fmt.Sprintf("Include %q: ~user paths are not supported yet, skipped", pattern)
	case !filepath.IsAbs(p):
		home := homeDir()
		if home == "" {
			return nil, fmt.Sprintf("Include %q: cannot determine home directory, skipped", pattern)
		}
		p = filepath.Join(home, ".ssh", p)
	}

	matches, err := filepath.Glob(p)
	if err != nil {
		return nil, fmt.Sprintf("Include %q: bad glob pattern, skipped", pattern)
	}
	var files []string
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() {
			files = append(files, m)
		}
	}
	sort.Strings(files)
	return files, ""
}

// parseIncludeLine recognizes an "Include" line (trimmed, not a comment) and
// returns its patterns. The keyword is case-insensitive, "Include=x" and
// "Include = x" are accepted, several patterns may follow, and surrounding
// quotes are stripped.
func parseIncludeLine(trimmed string) ([]string, bool) {
	const kw = "include"
	if len(trimmed) <= len(kw) || !strings.EqualFold(trimmed[:len(kw)], kw) {
		return nil, false
	}
	rest := trimmed[len(kw):]
	if c := rest[0]; c != ' ' && c != '\t' && c != '=' {
		return nil, false // e.g. "IncludeFoo"
	}
	rest = strings.TrimLeft(rest, " \t")
	rest = strings.TrimPrefix(rest, "=")
	pats := splitArgs(strings.TrimLeft(rest, " \t"))
	if len(pats) == 0 {
		return nil, false
	}
	return pats, true
}

// splitArgs splits s on blanks, honoring single and double quotes (stripped)
// and stopping at an unquoted "#" that starts a token.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inTok := false
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			inTok = true
		case r == ' ' || r == '\t':
			if inTok {
				args = append(args, cur.String())
				cur.Reset()
				inTok = false
			}
		case r == '#' && !inTok:
			return args
		default:
			cur.WriteRune(r)
			inTok = true
		}
	}
	if inTok {
		args = append(args, cur.String())
	}
	return args
}
