package config

import "strings"

// SplitWords splits the argument part of a config line into words the way
// ssh does (misc.c argv_split): words are separated by blanks; single and
// double quotes group characters and are stripped (`"a b"` is one word, `a"b"`
// is `ab`); a backslash escapes a quote, a backslash and, outside quotes, a
// space; an unquoted "#" at the START of a word begins a comment and ends the
// list ("bar # note" is [bar], "a#b" is [a#b]).
//
// It is the ONE splitter for Host / Match / Include arguments: Parse and Doc
// both use it, so they can never disagree on a host name.
func SplitWords(s string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s) &&
			(s[i+1] == '\'' || s[i+1] == '"' || s[i+1] == '\\' || (quote == 0 && s[i+1] == ' ')):
			i++
			cur.WriteByte(s[i])
			inWord = true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			inWord = true
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '#' && !inWord:
			return words
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// Match criteria of ssh_config(5) (OpenSSH 10.6 readconf.c match_cfg_line):
// those without an argument, and those that take one, either as the next
// word or attached with "=" ("host=x", "exec=cmd").
var (
	matchNoArg  = map[string]bool{"all": true, "canonical": true, "final": true}
	matchOneArg = map[string]bool{
		"host": true, "originalhost": true, "user": true, "localuser": true,
		"localnetwork": true, "tagged": true, "command": true, "version": true,
		"sessiontype": true, "exec": true,
	}
)

// IsMatchExecLine reports whether line is a "Match" line with an "exec"
// criterion, i.e. a line that makes ssh (and `ssh -G`) run a command.
//
// The arguments are split with SplitWords and walked like ssh walks them:
// criterion, then its argument. "exec" counts only where ssh reads a
// criterion: `Match exec "cmd"`, `Match host a exec "cmd"`, `Match !exec
// "cmd"`, `Match exec="cmd"`, `Match final exec "cmd"`, any keyword casing.
// It does not count as the ARGUMENT of another criterion, so `Match host
// exec`, `Match host exec-box`, `Match host=exec` and `Match user exec` are
// not exec lines (checked against OpenSSH 10.6: none of them runs anything).
//
// Conservative where ssh's reading is unknown: after a word that is not a
// criterion of this table (a newer ssh may know it, and may give it no
// argument) any later "exec" / "exec=..." word counts.
func IsMatchExecLine(line string) bool {
	args, _, isMatch := blockLine(strings.TrimSpace(line))
	if !isMatch {
		return false
	}
	isExec := func(w string) bool {
		w = strings.ToLower(strings.TrimPrefix(w, "!"))
		return w == "exec" || strings.HasPrefix(w, "exec=")
	}
	for i := 0; i < len(args); i++ {
		w := strings.ToLower(strings.TrimPrefix(args[i], "!"))
		if isExec(w) {
			return true
		}
		name, _, attached := strings.Cut(w, "=")
		switch {
		case matchNoArg[w]:
		case attached && matchOneArg[name]: // "host=x": the argument is attached
		case matchOneArg[w]:
			i++ // the next word is its argument, whatever it says
		default:
			// Unknown criterion: no idea whether the next word is its
			// argument. Any "exec" further on counts.
			for _, rest := range args[i+1:] {
				if isExec(rest) {
					return true
				}
			}
			return false
		}
	}
	return false
}

// blockLine recognizes a (trimmed) "Host ..." or "Match ..." line and returns
// its arguments split with SplitWords. A Host line whose arguments are only a
// comment ("Host # note") is still a Host line: ssh opens a block that matches
// nothing, so the names are empty but the options below it belong to it. (A
// bare "Host" with nothing after it is a fatal error for ssh, OpenSSH 10.6;
// it is not a block line here and the BEFORE check of a save reports it.)
func blockLine(trimmed string) (names []string, isHost, isMatch bool) {
	key, value, ok := splitKeyword(trimmed)
	if !ok {
		return nil, false, false
	}
	switch {
	case strings.EqualFold(key, "host"):
		return SplitWords(value), true, false
	case strings.EqualFold(key, "match"):
		return SplitWords(value), false, true
	}
	return nil, false, false
}
