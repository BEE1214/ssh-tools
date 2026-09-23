package config

import (
	"fmt"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Write serializes a ConfigFile back to bytes.
//
// In full-write mode (used after `sshm init` or bulk operations),
// it produces canonical formatting:
//   - 2-space indent for options
//   - Canonical key casing (HostName, User, Port, etc.)
//   - One blank line between host blocks
//
// DevPod blocks are written with their marker comments and are not reformatted.
func Write(cfg *ConfigFile) ([]byte, error) {
	var buf strings.Builder

	// Write leading comments (before any host block).
	for _, c := range cfg.Comments {
		buf.WriteString(c.Text)
		buf.WriteString("\n")
	}

	for i, h := range cfg.Hosts {
		if !h.Disabled && !h.IsWildcard() {
			// Re-emit explicit "# group:" comments (non-redundant only) so
			// group assignments survive write cycles.
			if comment := groupCommentFor(h); comment != "" {
				buf.WriteString(comment)
			}
		}
		if h.Disabled {
			// Open a marker pair once per contiguous run of same-group
			// disabled hosts (the parser emits them in file order, so a
			// group's hosts are consecutive).
			if i == 0 || !cfg.Hosts[i-1].Disabled || cfg.Hosts[i-1].Group != h.Group {
				fmt.Fprintf(&buf, "%s\n", domain.DisabledMarkerStart(h.Group))
			}
			if h.RawBlock != "" {
				// Write the block COMMENTED OUT: raw ssh must not resolve
				// disabled hosts. Enable strips the comment prefix.
				for _, l := range strings.Split(h.RawBlock, "\n") {
					buf.WriteString(commentOutLine(l))
					buf.WriteString("\n")
				}
			} else {
				writeHostBlock(&buf, h)
			}
			// Close the marker pair when the next host differs or ends.
			if i == len(cfg.Hosts)-1 || !cfg.Hosts[i+1].Disabled || cfg.Hosts[i+1].Group != h.Group {
				fmt.Fprintf(&buf, "%s\n", domain.DisabledMarkerEnd(h.Group))
			}
		} else if h.Source == domain.SourceDevPod {
			writeDevPodBlock(&buf, h)
		} else {
			writeHostBlock(&buf, h)
		}

		// Add blank line between blocks (but not after the last one).
		// Inside a contiguous disabled run the RawBlocks already carry the
		// original spacing — an extra blank line would be absorbed into the
		// previous RawBlock on re-parse and grow the file every cycle.
		if i < len(cfg.Hosts)-1 &&
			!(h.Disabled && cfg.Hosts[i+1].Disabled && cfg.Hosts[i+1].Group == h.Group) {
			buf.WriteString("\n")
		}
	}

	// Ensure file ends with newline.
	result := buf.String()
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}

	return []byte(result), nil
}

// writeHostBlock writes a single non-DevPod host block.
func writeHostBlock(buf *strings.Builder, h domain.Host) {
	fmt.Fprintf(buf, "Host %s\n", h.Name)

	if h.HostName != "" {
		fmt.Fprintf(buf, "  HostName %s\n", h.HostName)
	}
	if h.User != "" {
		fmt.Fprintf(buf, "  User %s\n", h.User)
	}
	if h.Port != "" && h.Port != "22" {
		fmt.Fprintf(buf, "  Port %s\n", h.Port)
	}
	if h.IdentityFile != "" {
		fmt.Fprintf(buf, "  IdentityFile %s\n", h.IdentityFile)
	}
	if h.CertificateFile != "" {
		fmt.Fprintf(buf, "  CertificateFile %s\n", h.CertificateFile)
	}
	if h.ProxyJump != "" {
		fmt.Fprintf(buf, "  ProxyJump %s\n", h.ProxyJump)
	}
	if h.ProxyCommand != "" {
		fmt.Fprintf(buf, "  ProxyCommand %s\n", h.ProxyCommand)
	}
	if h.ForwardAgent != "" {
		fmt.Fprintf(buf, "  ForwardAgent %s\n", h.ForwardAgent)
	}
	if h.ForwardX11 != "" {
		fmt.Fprintf(buf, "  ForwardX11 %s\n", h.ForwardX11)
	}
	if h.StrictHostKeyChecking != "" {
		fmt.Fprintf(buf, "  StrictHostKeyChecking %s\n", h.StrictHostKeyChecking)
	}
	if h.LogLevel != "" {
		fmt.Fprintf(buf, "  LogLevel %s\n", h.LogLevel)
	}
	if h.HostKeyAlgorithms != "" {
		fmt.Fprintf(buf, "  HostKeyAlgorithms %s\n", h.HostKeyAlgorithms)
	}
	if h.KexAlgorithms != "" {
		fmt.Fprintf(buf, "  KexAlgorithms %s\n", h.KexAlgorithms)
	}
	if h.PubkeyAcceptedAlgorithms != "" {
		fmt.Fprintf(buf, "  PubkeyAcceptedAlgorithms %s\n", h.PubkeyAcceptedAlgorithms)
	}
	if h.Ciphers != "" {
		fmt.Fprintf(buf, "  Ciphers %s\n", h.Ciphers)
	}
	if h.MACs != "" {
		fmt.Fprintf(buf, "  MACs %s\n", h.MACs)
	}
	for _, f := range h.LocalForwards {
		fmt.Fprintf(buf, "  LocalForward %s\n", f)
	}
	for _, f := range h.RemoteForwards {
		fmt.Fprintf(buf, "  RemoteForward %s\n", f)
	}
	for _, f := range h.DynamicForwards {
		fmt.Fprintf(buf, "  DynamicForward %s\n", f)
	}

	// Write extra options in sorted order for deterministic output.
	for _, opt := range sortedKeys(h.Extra) {
		fmt.Fprintf(buf, "  %s %s\n", opt, h.Extra[opt])
	}
}

// writeDevPodBlock writes a DevPod-managed host block with markers.
func writeDevPodBlock(buf *strings.Builder, h domain.Host) {
	fmt.Fprintf(buf, "# DevPod Start %s\n", h.Name)
	writeHostBlock(buf, h)
	fmt.Fprintf(buf, "# DevPod End %s\n", h.Name)
}

// writeDisabledBlock re-emits a disabled host block between its group's
// markers. If the host carries a verbatim RawBlock (normal case — the parser
// fills it), it is written byte-for-byte; otherwise the block is regenerated
// in canonical form. Host blocks that had an explicit "# group:" comment
// before being disabled get it re-emitted so the group survives an
// enable/disable cycle.
func writeDisabledBlock(buf *strings.Builder, h domain.Host) {
	fmt.Fprintf(buf, "%s\n", domain.DisabledMarkerStart(h.Group))
	if h.RawBlock != "" {
		buf.WriteString(h.RawBlock)
		buf.WriteString("\n")
	} else {
		writeHostBlock(buf, h)
	}
	fmt.Fprintf(buf, "%s\n", domain.DisabledMarkerEnd(h.Group))
}

// groupCommentFor returns the "# group: <name>" comment line to re-emit
// above a host block, or "" when the group equals the prefix heuristic
// (GroupFor) — in that case the comment is redundant and omitted.
func groupCommentFor(h domain.Host) string {
	if h.Disabled || h.Group == "" || h.Group == domain.GroupFor(h.Name) {
		return ""
	}
	return fmt.Sprintf("%s %s\n", domain.GroupCommentPrefix, h.Group)
}

// sortedKeys returns map keys sorted alphabetically.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}