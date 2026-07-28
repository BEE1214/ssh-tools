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
	commentStart := 0
	lineNum := 0

	// flushComment saves accumulated comment lines as a CommentBlock.
	flushComment := func() {
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

		// Host line: starts a new host block
		if isHostLine(trimmed) {
			flushComment()
			flushHost()

			name := strings.TrimSpace(strings.TrimPrefix(trimmed, strings.TrimSuffix(trimmed[:5], " ")))
			// Simpler: everything after "Host " (case-insensitive)
			name = strings.TrimSpace(trimmed[5:])
			currentHost = &domain.Host{
				Name:   name,
				Group:  domain.GroupFor(name),
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