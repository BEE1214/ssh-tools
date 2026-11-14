package domain

import (
	"slices"
	"strings"
)

// EffectiveConfig resolves the effective SSH options for a given host name,
// mirroring what `ssh -G <host>` does (ssh_config(5)):
//
//  1. hosts must be in ssh evaluation order (file order, with Include
//     directives already inlined at their position, as config.Load returns).
//  2. Every block whose Host pattern line matches hostName applies (see
//     matchPattern for the pattern syntax, including "!" negation).
//  3. For scalar options the FIRST matching block that sets an option wins;
//     later blocks only fill options that are still unset. So a "Host *"
//     block placed before a specific block overrides it, exactly as in ssh.
//  4. List-type options accumulate across all matching blocks, in order,
//     de-duplicated by exact value: LocalForward, RemoteForward,
//     DynamicForward and the SendEnv extra option.
//
// Known limitation: the Host model stores IdentityFile and CertificateFile as
// single strings (the parser keeps the last line of a block), so here they are
// first-wins although ssh accumulates them. Use MatchingHosts to see every
// block's value.
//
// Match blocks are not modeled (the parser treats them as comments).
func EffectiveConfig(hosts []Host, hostName string) (Host, error) {
	matching := MatchingHosts(hosts, hostName)
	if len(matching) == 0 {
		return Host{}, ErrHostNotFound
	}

	result := Host{Name: hostName}
	for _, h := range matching {
		mergeHost(&result, h)
	}
	result.Name = hostName
	return result, nil
}

// MatchingHosts returns, in the given (evaluation) order, the blocks whose
// Host pattern line applies to hostName.
func MatchingHosts(hosts []Host, hostName string) []Host {
	var out []Host
	for _, h := range hosts {
		if matchPattern(h.Name, hostName) {
			out = append(out, h)
		}
	}
	return out
}

// ErrHostNotFound is returned when no Host block matches the given name.
var ErrHostNotFound = errHostNotFound{}

type errHostNotFound struct{}

func (errHostNotFound) Error() string { return "host not found" }

// matchPattern reports whether a Host pattern line applies to name, like
// ssh's match_pattern_list: the line is a space-separated list of globs ("*"
// any run, "?" one character); a "!"-prefixed entry is a negation. The line
// applies iff at least one positive pattern matches and no negated pattern
// matches. Matching is case-sensitive.
func matchPattern(pattern, name string) bool {
	matched := false
	for _, p := range strings.Fields(pattern) {
		if neg, ok := strings.CutPrefix(p, "!"); ok {
			if globMatch(neg, name) {
				return false
			}
			continue
		}
		if globMatch(p, name) {
			matched = true
		}
	}
	return matched
}

// globMatch matches name against a pattern with "*" and "?" wildcards.
func globMatch(pattern, name string) bool {
	p, n := 0, 0
	star, mark := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]):
			p++
			n++
		case star >= 0:
			mark++
			n = mark
			p = star + 1
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// mergeHost folds src (a later matching block) into dst: scalar options are
// only taken if dst has not set them yet (first wins, like ssh); list options
// are appended with exact-value de-duplication.
func mergeHost(dst *Host, src Host) {
	setIfEmpty := func(d *string, s string) {
		if *d == "" {
			*d = s
		}
	}
	setIfEmpty(&dst.HostName, src.HostName)
	setIfEmpty(&dst.User, src.User)
	setIfEmpty(&dst.Port, src.Port)
	setIfEmpty(&dst.IdentityFile, src.IdentityFile)       // ssh accumulates; see EffectiveConfig
	setIfEmpty(&dst.CertificateFile, src.CertificateFile) // ssh accumulates; see EffectiveConfig
	setIfEmpty(&dst.ProxyJump, src.ProxyJump)
	setIfEmpty(&dst.ProxyCommand, src.ProxyCommand)
	setIfEmpty(&dst.ForwardAgent, src.ForwardAgent)
	setIfEmpty(&dst.ForwardX11, src.ForwardX11)
	setIfEmpty(&dst.StrictHostKeyChecking, src.StrictHostKeyChecking)
	setIfEmpty(&dst.LogLevel, src.LogLevel)
	setIfEmpty(&dst.HostKeyAlgorithms, src.HostKeyAlgorithms)
	setIfEmpty(&dst.KexAlgorithms, src.KexAlgorithms)
	setIfEmpty(&dst.PubkeyAcceptedAlgorithms, src.PubkeyAcceptedAlgorithms)
	setIfEmpty(&dst.Ciphers, src.Ciphers)
	setIfEmpty(&dst.MACs, src.MACs)

	for k, v := range src.Extra {
		if dst.Extra == nil {
			dst.Extra = make(map[string]string)
		}
		cur, ok := dst.Extra[k]
		switch {
		case !ok:
			dst.Extra[k] = v
		case strings.EqualFold(k, "SendEnv"):
			// SendEnv is a list option: accumulate patterns, de-duplicated.
			dst.Extra[k] = strings.Join(appendUnique(strings.Fields(cur), strings.Fields(v)), " ")
		}
		// Any other already-set Extra key: first wins. Keys keep their source
		// casing, so differently-cased spellings of one option are not merged.
	}

	dst.LocalForwards = appendUnique(dst.LocalForwards, src.LocalForwards)
	dst.RemoteForwards = appendUnique(dst.RemoteForwards, src.RemoteForwards)
	dst.DynamicForwards = appendUnique(dst.DynamicForwards, src.DynamicForwards)
}

// appendUnique appends the entries of add not already present in dst.
func appendUnique(dst, add []string) []string {
	for _, a := range add {
		if !slices.Contains(dst, a) {
			dst = append(dst, a)
		}
	}
	return dst
}
