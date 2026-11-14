package config

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// ConfigFile is the parsed representation of the entire SSH config file.
type ConfigFile struct {
	Hosts    []domain.Host
	Comments []CommentBlock // standalone comments/blank lines preserved between hosts
	Raw      []byte         // original file bytes
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

// CommentBlock preserves comments and blank lines between host blocks.
type CommentBlock struct {
	LineStart int
	LineEnd   int
	Text      string
}

// Parse reads raw SSH config bytes and returns a structured ConfigFile.
//
// The parser is a line-by-line state machine with two states:
//   - IDLE: accumulate comments/blank lines into CommentBlock.
//   - IN_HOST: accumulate key-value pairs into current Host.
//
// It preserves comments, blank lines, and detects DevPod blocks.
func Parse(raw []byte) (*ConfigFile, error) {
	cfg := &ConfigFile{Raw: raw}

	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	// Allow long lines (ProxyCommand can be long).
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var currentHost *domain.Host
	var commentLines []string
	var pendingDevPod string
	var pendingGroup string
	var inDisabledBlock bool
	var disabledGroup string
	var disabledRaw []string
	var disabledStart int
	commentStart := 0
	lineNum := 0

	// flushComment saves accumulated comment lines as a CommentBlock.
	// Trailing blank lines are trimmed: the writer adds a blank line after
	// each comment block, so keeping trailing blanks would grow the block
	// by one line on every parse→write cycle.
	flushComment := func() {
		if len(commentLines) == 0 {
			return
		}
		for len(commentLines) > 0 && strings.TrimSpace(commentLines[len(commentLines)-1]) == "" {
			commentLines = commentLines[:len(commentLines)-1]
		}
		if len(commentLines) == 0 {
			return
		}
		cfg.Comments = append(cfg.Comments, CommentBlock{
			LineStart: commentStart,
			LineEnd:   lineNum,
			Text:      strings.Join(commentLines, "\n"),
		})
		commentLines = nil
	}

	// flushHost saves the current host block.
	flushHost := func() {
		if currentHost != nil {
			cfg.Hosts = append(cfg.Hosts, *currentHost)
			currentHost = nil
		}
	}

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		// Disabled group markers: "# sshm disabled group=<name> start/end".
		// Lines between markers belong to disabled host blocks and are not
		// comments — the writer re-emits them verbatim on enable.
		//
		// Markers are only honored in well-formed positions: a start marker
		// outside any host block and outside another disabled block, an end
		// marker that closes the open block of the same group. Anything else
		// is an ordinary comment (or a raw line of the open disabled block),
		// so a stray marker can never swallow hosts.
		if name, ok := domain.IsDisabledMarkerStart(trimmed); ok && !inDisabledBlock && currentHost == nil {
			flushComment()
			disabledGroup = name
			disabledStart = lineNum
			inDisabledBlock = true
			commentLines = nil
			continue
		}
		if name, ok := domain.IsDisabledMarkerEnd(trimmed); ok && inDisabledBlock && name == disabledGroup {
			appendDisabledHosts(cfg, disabledGroup, disabledRaw)
			inDisabledBlock = false
			disabledGroup = ""
			disabledRaw = nil
			commentLines = nil
			continue
		}

		// Explicit group comment: "# group: <name>" applies to the next
		// Host line and is consumed (not treated as a comment block).
		// Inside a host block it stays an ordinary comment.
		if !inDisabledBlock && currentHost == nil {
			if g, ok := domain.GroupFromComment(trimmed); ok {
				flushComment()
				pendingGroup = g
				continue
			}
		}

		// DevPod block detection: "# DevPod Start <name>"
		if strings.HasPrefix(trimmed, "# DevPod Start ") {
			flushComment()
			flushHost()

			devpodName := strings.TrimPrefix(trimmed, "# DevPod Start ")
			// Set flag: next "Host" line should be marked as DevPod source.
			pendingDevPod = devpodName
			continue
		}

		// DevPod block end: "# DevPod End <name>"
		if strings.HasPrefix(trimmed, "# DevPod End ") {
			flushHost()
			pendingDevPod = ""
			// Don't treat the End marker as a comment block — it's part of the DevPod section.
			commentLines = nil
			continue
		}

		// Inside a disabled block: collect raw lines verbatim until the end
		// marker (matched at the top of the loop on the next lines).
		if inDisabledBlock {
			disabledRaw = append(disabledRaw, raw)
			continue
		}

		// Host line: starts a new host block
		if isHostLine(trimmed) {
			flushComment()
			flushHost()

			name := strings.TrimSpace(trimmed[5:])
			currentHost = &domain.Host{
				Name: name,
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
				if len(commentLines) == 0 {
					commentStart = lineNum
				}
				commentLines = append(commentLines, raw)
				continue
			}
			// Non-empty, non-comment, non-Host line outside a block.
			// Could be a stray option or a "Match" block. Treat as comment to preserve it.
			if len(commentLines) == 0 {
				commentStart = lineNum
			}
			commentLines = append(commentLines, raw)
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
			commentStart = lineNum
			commentLines = append(commentLines, raw)
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

	flushComment()
	flushHost()

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	// An unterminated disabled block would swallow every following host and
	// a later save would delete them — fail loudly instead.
	if inDisabledBlock {
		return nil, fmt.Errorf("unterminated disabled group block %q: start marker at line %d has no matching end marker",
			disabledGroup, disabledStart)
	}

	return cfg, nil
}

// isHostLine checks if a trimmed line starts with "Host " (case-insensitive)
// but not "HostName" or "HostKeyAlgorithms" etc.
func isHostLine(line string) bool {
	lower := strings.ToLower(line)
	if !strings.HasPrefix(lower, "host ") {
		return false
	}
	// Make sure it's not "HostName", "HostKeyAlgorithms", etc.
	rest := line[5:] // after "Host "
	if rest == "" {
		return false
	}
	// "Host " followed by non-letter means it's a Host directive.
	// "HostName" would be "Host HostName" -> no, it'd be "HostName ...".
	// Actually the prefix check is on the line: "HostName ..." doesn't start with "Host " (space after Host).
	// "HostName" starts with "HostN" not "Host " (with space).
	// But case-insensitive: "hostname" starts with "host" but not "host " (with trailing space).
	// So the HasPrefix("host ") check already excludes "hostname".
	return true
}

// parseKeyValue parses a "key value" line and stores it in the host.
func parseKeyValue(h *domain.Host, line string) error {
	// Split on first whitespace.
	idx := strings.IndexAny(line, " \t")
	if idx == -1 {
		return fmt.Errorf("malformed line: %q", line)
	}

	key := line[:idx]
	value := strings.TrimSpace(line[idx+1:])
	canonicalKey := canonicalKey(key)

	switch canonicalKey {
	case "HostName":
		h.HostName = value
	case "User":
		h.User = value
	case "Port":
		h.Port = value
	case "IdentityFile":
		h.IdentityFile = value
	case "CertificateFile":
		h.CertificateFile = value
	case "ProxyJump":
		h.ProxyJump = value
	case "ProxyCommand":
		h.ProxyCommand = value
	case "ForwardAgent":
		h.ForwardAgent = value
	case "ForwardX11":
		h.ForwardX11 = value
	case "StrictHostKeyChecking":
		h.StrictHostKeyChecking = value
	case "LogLevel":
		h.LogLevel = value
	case "HostKeyAlgorithms":
		h.HostKeyAlgorithms = value
	case "KexAlgorithms":
		h.KexAlgorithms = value
	case "PubkeyAcceptedAlgorithms":
		h.PubkeyAcceptedAlgorithms = value
	case "Ciphers":
		h.Ciphers = value
	case "MACs":
		h.MACs = value
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
		h.Extra[canonicalKey] = value
	}

	if h.LineEnd == 0 {
		h.LineEnd = 0 // will be set by flushHost
	}

	return nil
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
// hosts. This function strips one comment level, sub-parses the original
// blocks, and stores the uncommented text in RawBlock — the writer
// re-comments it on write and enable restores it verbatim.
//
// Disabled hosts get negative line numbers (unmoored from source
// coordinates) and Group = <disabled group>.
//
// Note: the sub-parse consumes any "# group:" comments inside the block as
// pending-group state; the marker group overrides it. Host blocks themselves
// are restored byte-for-byte via RawBlock.
func appendDisabledHosts(cfg *ConfigFile, group string, rawLines []string) {
	inner := uncommentLines(rawLines)
	sub, err := Parse([]byte(strings.Join(inner, "\n")))
	if err != nil || len(sub.Hosts) == 0 {
		// No parseable host blocks — preserve the bytes as fully commented
		// text so nothing is silently dropped. (Parse is non-fatal by
		// design, so this is a defensive fallback only.)
		cfg.Comments = append(cfg.Comments, CommentBlock{
			LineStart: 0,
			LineEnd:   0,
			Text:      DisabledBlockText(group, rawLines),
		})
		return
	}
	spans := disabledBlockSpans(sub, len(inner))
	for i := range sub.Hosts {
		h := sub.Hosts[i]
		h.Disabled = true
		h.Group = group
		h.LineStart = -(1000000 + len(cfg.Hosts))
		h.LineEnd = 0
		h.RawBlock = strings.Join(inner[spans[i][0]-1:spans[i][1]], "\n")
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

// disabledBlockSpans computes, for each host of a parsed disabled
// sub-config, the verbatim line span it owns within rawLines (1-indexed,
// inclusive). Spans are contiguous: span[0] of the first host is line 1 and
// each next span starts right after the previous one, so comments and blank
// lines inside the disabled section are preserved (attached to the
// preceding or following host) and nothing is dropped or duplicated.
func disabledBlockSpans(sub *ConfigFile, rawCount int) [][2]int {
	spans := make([][2]int, len(sub.Hosts))
	for i := range sub.Hosts {
		start := 1
		if i > 0 {
			start = spans[i-1][1] + 1
		}
		end := rawCount
		if j := i + 1; j < len(sub.Hosts) {
			if nextStart := sub.Hosts[j].LineStart - 1; nextStart >= start && nextStart < end {
				end = nextStart
			}
		}
		if end < start {
			end = start
		}
		spans[i] = [2]int{start, end}
	}
	return spans
}

// DisabledBlockText renders leftover disabled-block lines as a fully
// commented-out text block between the group's markers (defensive fallback
// that keeps the bytes visible in the config file).
func DisabledBlockText(group string, rawLines []string) string {
	var b strings.Builder
	b.WriteString(domain.DisabledMarkerStart(group))
	b.WriteString("\n")
	for _, l := range rawLines {
		if strings.TrimSpace(l) == "" {
			b.WriteString("#\n")
		} else {
			b.WriteString("# ")
			b.WriteString(l)
			b.WriteString("\n")
		}
	}
	b.WriteString(domain.DisabledMarkerEnd(group))
	b.WriteString("\n")
	return b.String()
}