package config

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// ConfigFile is the parsed representation of the entire SSH config file.
type ConfigFile struct {
	Hosts []domain.Host
	Raw   []byte // original file bytes

	// Includes lists the Include directives found in the file, in line
	// order. Read-only metadata for Load.
	Includes []IncludeDirective
}

// RawTextLines returns the raw file split into lines (no trailing newline
// handling — split excludes the final empty element after a terminal \n).
// The slice is recomputed on each call; callers should use it once.
func (c *ConfigFile) RawTextLines() []string {
	text := strings.TrimSuffix(string(c.Raw), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// Parse reads raw SSH config bytes and returns a structured ConfigFile. It is
// read-only: the file is never re-serialized from it (edits go through Doc).
//
// The parser is a line-by-line state machine with two states:
//   - IDLE: skip comments and blank lines.
//   - IN_HOST: accumulate key-value pairs into current Host.
//
// It detects DevPod blocks and disabled groups.
func Parse(raw []byte) (*ConfigFile, error) {
	cfg := &ConfigFile{Raw: raw}

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	// Allow long lines (ProxyCommand can be long).
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var currentHost *domain.Host
	var pendingDevPod string
	var pendingGroup string
	var inDisabledBlock bool
	var disabledGroup string
	var disabledRaw []string
	var disabledStart int
	// inConditionalBlock: the nearest enabled Host/Match line above the
	// current line does not match every host (see matchesEveryHost).
	var inConditionalBlock bool
	lineNum := 0

	// flushHost saves the current host block.
	flushHost := func() {
		if currentHost != nil {
			cfg.Hosts = append(cfg.Hosts, *currentHost)
			currentHost = nil
		}
	}

	// All lines first: a start marker below a host block is only honoured
	// when its end marker exists further down (look-ahead).
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	// resumeHost is the index in cfg.Hosts of a host block that a disabled
	// region interrupted (the region stood directly below it), or -1. For
	// ssh the region is only comments, so option lines that follow the end
	// marker still belong to that block.
	resumeHost := -1

	for i, raw := range lines {
		lineNum = i + 1
		trimmed := strings.TrimSpace(raw)

		// Disabled group markers: "# sshm disabled group=<name> start/end".
		// Lines between markers belong to disabled host blocks and are not
		// comments — the writer re-emits them verbatim on enable.
		//
		// A start marker inside another disabled block is a raw line of that
		// block. Otherwise:
		//   - Outside a host block it opens a disabled block. If no end
		//     marker follows, the parse fails below, loudly: the block would
		//     swallow every following host and a later save would delete
		//     them. (Unchanged since before P2.)
		//   - Directly below a host block (no blank line) it opens a disabled
		//     block only when it is well formed: an end marker of the same
		//     group exists further down AND every line in between is a
		//     comment or blank, i.e. the region is inert for ssh. Then it
		//     ENDS the host block for now: Doc reads the file the same way,
		//     and Doc.DisableBlocks produces exactly this layout for
		//     "Host a / Host b" with no blank line between them.
		//   - Any other marker below a host block (no end marker; or a pair
		//     around ACTIVE lines) is an ordinary comment inside that block,
		//     as it was before P2b: the lines around it stay options of the
		//     block, which is how ssh reads them, and nothing fails.
		// An end marker only closes the open block of the same group;
		// anything else is an ordinary comment.
		if name, ok := domain.IsDisabledMarkerStart(trimmed); ok && !inDisabledBlock {
			open := currentHost == nil
			if !open {
				end := markerEnd(lines, i, name)
				open = end >= 0 && inertLines(lines[i+1:end])
			}
			if open {
				resumeHost = -1
				if currentHost != nil {
					currentHost.LineEnd = lineNum - 1
					flushHost()
					resumeHost = len(cfg.Hosts) - 1
				}
				disabledGroup = name
				disabledStart = lineNum
				inDisabledBlock = true
				continue
			}
		}
		if name, ok := domain.IsDisabledMarkerEnd(trimmed); ok && inDisabledBlock && name == disabledGroup {
			appendDisabledHosts(cfg, disabledGroup, disabledRaw)
			inDisabledBlock = false
			disabledGroup = ""
			disabledRaw = nil
			continue
		}

		// Explicit group comment: "# group: <name>" applies to the next
		// Host line and is consumed.
		// Inside a host block it stays an ordinary comment.
		if !inDisabledBlock && currentHost == nil {
			if g, ok := domain.GroupFromComment(trimmed); ok {
				pendingGroup = g
				continue
			}
		}

		// DevPod block detection: "# DevPod Start <name>"
		if strings.HasPrefix(trimmed, "# DevPod Start ") {
			flushHost()
			resumeHost = -1

			devpodName := strings.TrimPrefix(trimmed, "# DevPod Start ")
			// Set flag: next "Host" line should be marked as DevPod source.
			pendingDevPod = devpodName
			continue
		}

		// DevPod block end: "# DevPod End <name>"
		if strings.HasPrefix(trimmed, "# DevPod End ") {
			flushHost()
			resumeHost = -1
			pendingDevPod = ""
			continue
		}

		// Inside a disabled block: collect raw lines verbatim until the end
		// marker (matched at the top of the loop on the next lines).
		if inDisabledBlock {
			disabledRaw = append(disabledRaw, raw)
			continue
		}

		// Include directive: recorded for Load, then handled like any other
		// line below (inside a block it is an unmodeled option).
		// Lines inside disabled-group markers never reach this point.
		if pats, ok := parseIncludeLine(trimmed); ok {
			cfg.Includes = append(cfg.Includes, IncludeDirective{Line: lineNum, Patterns: pats, Conditional: inConditionalBlock})
		}

		names, isHost, isMatch := blockLine(trimmed)
		if isHost || isMatch {
			// For ssh a block runs to the next Host/Match line (blank lines
			// do not end it), and an Include inside it is applied only while
			// the block matches.
			inConditionalBlock = !matchesEveryHost(names, isMatch)
			// A Match line starts a new block for ssh: whatever follows it
			// no longer belongs to a host block interrupted further up.
			resumeHost = -1
		}

		// Host line: starts a new host block
		if isHost {
			flushHost()

			// Name is what a user types for the block (P7 N1): the patterns
			// ssh makes of the argument text (SplitWords: quotes removed,
			// comment dropped) joined by one space. A line without any
			// pattern keeps its argument text. Patterns is what ssh makes of
			// it; always non-nil here, see domain.Host.Patterns.
			name := hostLineName(trimmed)
			if names == nil {
				names = []string{}
			}
			if joined := strings.Join(names, " "); joined != "" {
				name = joined // not for `Host # c` and `Host ""`: no pattern to type
			}
			currentHost = &domain.Host{
				Name:     name,
				Patterns: names,
			}
			if pendingGroup != "" {
				currentHost.Group = pendingGroup
				pendingGroup = ""
			} else {
				currentHost.Group = domain.GroupFor(name)
			}
			if pendingDevPod != "" {
				currentHost.Source = domain.SourceDevPod
				pendingDevPod = ""
			} else {
				currentHost.Source = domain.SourceManual
			}
			currentHost.LineStart = lineNum
			continue
		}

		// Empty line or comment — not inside a host block
		if currentHost == nil {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				if trimmed == "" {
					resumeHost = -1 // a blank line ends a block for this parser
				}
				continue
			}
			// An option line right below a disabled region that interrupted a
			// host block: it is still an option of that block (see resumeHost).
			if resumeHost >= 0 {
				_ = parseKeyValue(&cfg.Hosts[resumeHost], trimmed)
				cfg.Hosts[resumeHost].LineEnd = lineNum
				continue
			}
			// Non-empty, non-comment, non-Host line outside a block: a stray
			// option or a "Match" block. sshm does not model it.
			continue
		}

		// Inside a host block
		if trimmed == "" {
			// Blank line ends the host block.
			currentHost.LineEnd = lineNum - 1
			if currentHost.LineEnd < currentHost.LineStart {
				currentHost.LineEnd = currentHost.LineStart
			}
			flushHost()
			continue
		}

		if strings.HasPrefix(trimmed, "#") {
			// Comment inside a host block — preserve as part of the block, don't end it.
			// We'll keep it by attaching to the host's line range.
			continue
		}

		// Key-value pair inside a host block
		if err := parseKeyValue(currentHost, trimmed); err != nil {
			// Non-fatal: collect but continue.
			// Could log warning here in future.
			_ = err
		}
	}

	flushHost()

	// An unterminated disabled block would swallow every following host and
	// a later save would delete them — fail loudly instead. (Only a start
	// marker outside a host block can get here; one inside a block is only
	// honoured when its end marker exists.)
	if inDisabledBlock {
		return nil, fmt.Errorf("unterminated disabled group block %q: start marker at line %d has no matching end marker",
			disabledGroup, disabledStart)
	}

	return cfg, nil
}

// matchesEveryHost reports whether a Host/Match line with these arguments
// certainly applies to every host, so that what stands below it (an Include
// in particular) is not conditional: exactly "Host *" (one pattern) and
// "Match all" (one criterion). Checked against OpenSSH 10.6: an Include below
// either is applied to every host. Everything else counts as conditional,
// including lines that happen to match everything ("Host * *", "Match host
// *") or nearly everything ("Host * !x"): the safe direction.
func matchesEveryHost(args []string, isMatch bool) bool {
	if len(args) != 1 {
		return false
	}
	if isMatch {
		return strings.EqualFold(args[0], "all")
	}
	return args[0] == "*"
}

// markerEnd returns the index of the first end marker of group below
// lines[start] (a start marker), or -1 when there is none.
func markerEnd(lines []string, start int, group string) int {
	for k := start + 1; k < len(lines); k++ {
		if g, ok := domain.IsDisabledMarkerEnd(strings.TrimSpace(lines[k])); ok && g == group {
			return k
		}
	}
	return -1
}

// inertLines reports whether every line is blank or a comment, i.e. means
// nothing to ssh.
func inertLines(lines []string) bool {
	for _, l := range lines {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}

// splitKeyword splits an (already trimmed) config line into its keyword and
// value the way ssh does: the keyword ends at the first blank or '=', and
// the value follows after blanks and at most one '=' ("Key value",
// "Key=value", "Key = value" and "Key =value" are all the same). ok is false
// when the line has no value.
func splitKeyword(line string) (key, value string, ok bool) {
	idx := strings.IndexAny(line, " \t=")
	if idx <= 0 {
		return "", "", false
	}
	key = line[:idx]
	rest := strings.TrimLeft(line[idx:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	value = strings.TrimSpace(rest)
	if value == "" {
		return "", "", false
	}
	return key, value, true
}

// hostLineName returns the argument text of a (trimmed) Host line: what
// follows the keyword and its separator (blanks and at most one "=", which
// ssh skips the same way), with trailing blanks removed and nothing else
// touched (`Host "a b" # c` gives `"a b" # c`). It is the host's Name ONLY
// for a line without any pattern (`Host # c`, `Host ""`); otherwise Name is
// the patterns joined by one space (see Parse), which differs from this text
// as soon as there is a quote, a comment or extra blanks.
func hostLineName(trimmed string) string {
	_, value, _ := splitKeyword(trimmed)
	return value
}

// isHostLine checks if a trimmed line is a Host directive: keyword "Host"
// (case-insensitive) followed by blank(s) or '=' and a pattern list. Not
// "HostName", "HostKeyAlgorithms" etc. (their keyword is longer).
func isHostLine(line string) bool {
	_, isHost, _ := blockLine(line)
	return isHost
}

// parseKeyValue parses a "key value" (or "key=value") line and stores it in
// the host.
//
// Repeated keys follow ssh: for scalar options the FIRST occurrence in the
// block wins; IdentityFile and CertificateFile accumulate (the singular
// field holds the first value, IdentityFiles / CertificateFiles all of them
// in order); forwards and SendEnv accumulate.
func parseKeyValue(h *domain.Host, line string) error {
	key, value, ok := splitKeyword(line)
	if !ok {
		return fmt.Errorf("malformed line: %q", line)
	}
	canonicalKey := canonicalKey(key)

	// first stores value unless the option was already set earlier in the block.
	first := func(dst *string) {
		if *dst == "" {
			*dst = value
		}
	}

	switch canonicalKey {
	case "HostName":
		first(&h.HostName)
	case "User":
		first(&h.User)
	case "Port":
		first(&h.Port)
	case "IdentityFile":
		h.IdentityFiles = append(h.IdentityFiles, value)
		first(&h.IdentityFile)
	case "CertificateFile":
		h.CertificateFiles = append(h.CertificateFiles, value)
		first(&h.CertificateFile)
	case "ProxyJump":
		first(&h.ProxyJump)
	case "ProxyCommand":
		first(&h.ProxyCommand)
	case "ForwardAgent":
		// Not plain first-wins in ssh: yes/no and an agent socket path are
		// two settings. After "ForwardAgent yes" a later "ForwardAgent
		// <path>" still sets the path, and the two lines together are what
		// "ForwardAgent <path>" alone is; so the path is the value to keep
		// (Host has one value per option). In every other order ssh keeps
		// the first line.
		if isFlag, on := agentFlag(h.ForwardAgent); isFlag && on {
			if later, _ := agentFlag(value); !later {
				h.ForwardAgent = value
			}
			break
		}
		first(&h.ForwardAgent)
	case "ForwardX11":
		first(&h.ForwardX11)
	case "StrictHostKeyChecking":
		first(&h.StrictHostKeyChecking)
	case "LogLevel":
		first(&h.LogLevel)
	case "HostKeyAlgorithms":
		first(&h.HostKeyAlgorithms)
	case "KexAlgorithms":
		first(&h.KexAlgorithms)
	case "PubkeyAcceptedAlgorithms":
		first(&h.PubkeyAcceptedAlgorithms)
	case "Ciphers":
		first(&h.Ciphers)
	case "MACs":
		first(&h.MACs)
	case "LocalForward":
		h.LocalForwards = append(h.LocalForwards, normalizeForwardValue(value))
	case "RemoteForward":
		h.RemoteForwards = append(h.RemoteForwards, normalizeForwardValue(value))
	case "DynamicForward":
		h.DynamicForwards = append(h.DynamicForwards, normalizeForwardValue(value))
	default:
		if h.Extra == nil {
			h.Extra = make(map[string]string)
		}
		// Unknown keys are matched case-insensitively (ssh keywords are).
		// SendEnv is the one list-type option here: repeated lines
		// accumulate. Any other repeated key keeps its first value, like ssh.
		for k, cur := range h.Extra {
			if !strings.EqualFold(k, canonicalKey) {
				continue
			}
			if strings.EqualFold(k, "SendEnv") {
				h.Extra[k] = cur + " " + value
			}
			return nil
		}
		h.Extra[canonicalKey] = value
	}

	return nil
}

// agentFlag reports whether a ForwardAgent value is one of ssh's flag words
// (yes, no, true, false; any case) rather than an agent socket path, and
// whether it switches forwarding on. Only the first word counts: the parser
// keeps a trailing "# comment" in the value.
func agentFlag(value string) (isFlag, on bool) {
	words := SplitWords(value)
	if len(words) == 0 {
		return false, false
	}
	switch strings.ToLower(words[0]) {
	case "yes", "true":
		return true, true
	case "no", "false":
		return true, false
	}
	return false, false
}

// normalizeForwardValue collapses internal whitespace in a
// LocalForward/RemoteForward/DynamicForward value to single spaces, so
// entries are stored in a stable, comparable form regardless of how they
// were spaced in the source file.
func normalizeForwardValue(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

// canonicalKey normalizes an SSH config key to canonical form.
// SSH config keys are case-insensitive. We canonicalize to the form
// used in ssh_config(5) man page (e.g. "HostName", "User", "Port").
func canonicalKey(key string) string {
	// SSH keys are case-insensitive. We use the canonical casing.
	// Rather than maintain a map of all keys, we just title-case the first letter
	// and keep the rest as-is. This handles the common cases:
	//   "user" -> "User", "hostname" -> "Hostname" (close enough)
	// For known keys, we override to exact canonical form.
	lower := strings.ToLower(key)
	switch lower {
	case "hostname":
		return "HostName"
	case "user":
		return "User"
	case "port":
		return "Port"
	case "identityfile":
		return "IdentityFile"
	case "certificatefile":
		return "CertificateFile"
	case "proxyjump":
		return "ProxyJump"
	case "proxycommand":
		return "ProxyCommand"
	case "forwardagent":
		return "ForwardAgent"
	case "forwardx11":
		return "ForwardX11"
	case "stricthostkeychecking":
		return "StrictHostKeyChecking"
	case "loglevel":
		return "LogLevel"
	case "hostkeyalgorithms":
		return "HostKeyAlgorithms"
	case "kexalgorithms":
		return "KexAlgorithms"
	case "pubkeyacceptedalgorithms":
		return "PubkeyAcceptedAlgorithms"
	case "pubkeyacceptedkeytypes":
		return "PubkeyAcceptedAlgorithms" // alias
	case "ciphers":
		return "Ciphers"
	case "macs":
		return "MACs"
	case "localforward":
		return "LocalForward"
	case "remoteforward":
		return "RemoteForward"
	case "dynamicforward":
		return "DynamicForward"
	case "serveraliveinterval":
		return "ServerAliveInterval"
	case "serveralivecountmax":
		return "ServerAliveCountMax"
	case "identitiesonly":
		return "IdentitiesOnly"
	case "hashknownhosts":
		return "HashKnownHosts"
	default:
		// For unknown keys, return as-is (preserves original casing).
		return key
	}
}

// appendDisabledHosts parses the raw lines collected between a disabled
// group's markers into Disabled host entries.
//
// Lines between markers are stored in the config COMMENTED OUT (each line
// prefixed with "# ", blank lines untouched) so raw ssh cannot resolve the
// hosts. This function strips one comment level and sub-parses the original
// blocks (Doc enables a group by stripping the comment level again).
//
// Disabled hosts get negative line numbers (unmoored from source
// coordinates) and Group = <disabled group>.
//
// Note: the sub-parse consumes any "# group:" comments inside the block as
// pending-group state; the marker group overrides it.
func appendDisabledHosts(cfg *ConfigFile, group string, rawLines []string) {
	inner := uncommentLines(rawLines)
	sub, err := Parse([]byte(strings.Join(inner, "\n")))
	if err != nil || len(sub.Hosts) == 0 {
		return // no parseable host blocks (Parse is non-fatal by design)
	}
	for i := range sub.Hosts {
		h := sub.Hosts[i]
		h.Disabled = true
		h.Group = group
		h.LineStart = -(1000000 + len(cfg.Hosts))
		h.LineEnd = 0
		cfg.Hosts = append(cfg.Hosts, h)
	}
}

// commentOutLine renders one host-block line inert for ssh: non-blank lines
// get a "# " prefix (preserving the line's own content and indentation),
// blank lines pass through unchanged.
func commentOutLine(l string) string {
	if strings.TrimSpace(l) == "" {
		return l
	}
	return "# " + l
}

// uncommentLines strips one comment level added by commentOutLine:
// "# Host x" -> "Host x", "# # note" -> "# note", "# note" -> "note"
// (a bare-comment line inside a disabled block loses its leading marker),
// blank lines pass through. Lines that do not start with "#" are kept
// verbatim (defensive: hand-edited disabled sections).
func uncommentLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			out[i] = l
			continue
		}
		if strings.HasPrefix(l, "# ") {
			out[i] = l[2:]
			continue
		}
		if strings.TrimSpace(l) == "#" {
			out[i] = ""
			continue
		}
		out[i] = l
	}
	return out
}
