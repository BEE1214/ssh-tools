package app

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// sshQuery returns the names the local ssh supports for an `ssh -Q <kind>`
// query ("kex", "cipher", "mac", "key-sig", ...). It is a package var so tests
// can fake it. An error (ssh missing, query unsupported) means "unknown": the
// callers then neither write nor flag algorithm names.
var sshQuery = func(kind string) ([]string, error) {
	binary, err := exec.LookPath("ssh")
	if err != nil {
		return nil, fmt.Errorf("ssh not found in PATH: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "-Q", kind).Output()
	if err != nil {
		return nil, fmt.Errorf("ssh -Q %s: %w", kind, err)
	}
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	return names, nil
}

// querySet runs sshQuery and returns the answer as a set. ok is false when the
// query failed or came back empty (an empty answer means ssh does not know the
// query type, not "supports nothing").
func querySet(kind string) (set map[string]bool, ok bool) {
	names, err := sshQuery(kind)
	if err != nil || len(names) == 0 {
		return nil, false
	}
	set = make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set, true
}

// Query kinds for `ssh -Q`. Host key and pubkey-accepted algorithms are signature
// algorithms; `key-sig` is the query that lists both the cert variants and the
// rsa-sha2-* names (`sig` lacks certs, `key` lacks rsa-sha2-*).
const (
	queryKex    = "kex"
	queryCipher = "cipher"
	queryMAC    = "mac"
	queryKeySig = "key-sig"
)

// preferred filters an ordered preference list through what the local ssh
// supports and joins the survivors with commas, keeping the preference order.
// An entry "a|b" is a group of aliases: the first one ssh knows is used. If the
// query fails or nothing survives, "" is returned and the caller must OMIT the
// option so OpenSSH defaults apply: unverified names are never produced.
func preferred(kind string, prefs ...string) string {
	set, ok := querySet(kind)
	if !ok {
		return ""
	}
	var keep []string
	for _, group := range prefs {
		for _, name := range strings.Split(group, "|") {
			if set[name] {
				keep = append(keep, name)
				break
			}
		}
	}
	return strings.Join(keep, ",")
}

// algorithmOptions maps each validated host option to its `ssh -Q` kind.
var algorithmOptions = []struct {
	option string
	kind   string
	value  func(domain.Host) string
}{
	{"KexAlgorithms", queryKex, func(h domain.Host) string { return h.KexAlgorithms }},
	{"Ciphers", queryCipher, func(h domain.Host) string { return h.Ciphers }},
	{"MACs", queryMAC, func(h domain.Host) string { return h.MACs }},
	{"HostKeyAlgorithms", queryKeySig, func(h domain.Host) string { return h.HostKeyAlgorithms }},
	{"PubkeyAcceptedAlgorithms", queryKeySig, func(h domain.Host) string { return h.PubkeyAcceptedAlgorithms }},
}

// algorithmIssues reports algorithm names that the local ssh does not know
// (rule "bad-algorithm", error): ssh aborts on the whole config for those.
// Lists follow ssh's syntax: an optional leading + (append), - (remove) or ^
// (prepend) on the whole list, comma separated; entries containing a wildcard
// are patterns and are not checked. A kind whose `ssh -Q` query fails is
// skipped silently, so a missing ssh never produces false errors.
func algorithmIssues(hosts []domain.Host) []domain.Issue {
	sets := map[string]map[string]bool{} // kind -> set; nil = unavailable
	lookup := func(kind string) map[string]bool {
		set, seen := sets[kind]
		if !seen {
			set, _ = querySet(kind)
			sets[kind] = set
		}
		return set
	}

	var issues []domain.Issue
	for _, h := range hosts {
		for _, opt := range algorithmOptions {
			value := strings.TrimSpace(opt.value(h))
			if value == "" {
				continue
			}
			set := lookup(opt.kind) // queried lazily: only if some host uses the option
			if set == nil {
				continue
			}
			if strings.ContainsRune("+-^", rune(value[0])) {
				value = value[1:]
			}
			for _, name := range strings.Split(value, ",") {
				name = strings.TrimSpace(name)
				if name == "" || strings.ContainsAny(name, "*?") || set[name] {
					continue
				}
				issues = append(issues, domain.Issue{
					HostName: h.Name,
					Severity: domain.SeverityError,
					Rule:     "bad-algorithm",
					Message:  fmt.Sprintf("%s: %q is not supported by this ssh (ssh -Q %s); ssh rejects the whole config", opt.option, name, opt.kind),
					Line:     h.LineStart,
					File:     h.SourceFile,
				})
			}
		}
	}
	return issues
}
