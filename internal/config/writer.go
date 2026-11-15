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
//
// Known losses (not fixed here; the managed file is edited through Doc):
//   - a repeated Include or Match line inside one host block is lost: both
//     are stored like options (Host.Extra), and only the first is kept;
//   - text the parser found outside a host block is written at the top of
//     the file. That includes an option line below a blank line of a block
//     (for ssh still part of that block: it becomes a global option) and
//     every Match block;
//   - options come out in a fixed order. ssh takes whichever of ProxyJump
//     and ProxyCommand stands first in a block; a block that has
//     ProxyCommand first comes back with ProxyJump first.
func Write(cfg *ConfigFile) ([]byte, error) {
	var buf strings.Builder

	// Refuse values that would break out of their config line and inject
	// extra directives.
	for _, h := range cfg.Hosts {
		if err := checkLineBreaks(h); err != nil {
			return nil, err
		}
	}

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

// checkLineBreaks returns an error if any value the writer would emit for h
// contains a CR or LF. A disabled host with a verbatim RawBlock is written
// from that block, not from its fields, so its fields are not checked.
func checkLineBreaks(h domain.Host) error {
	if h.Disabled && h.RawBlock != "" {
		return nil
	}
	values := []string{
		h.Name, h.Group, h.HostName, h.User, h.Port, h.IdentityFile, h.CertificateFile,
		h.ProxyJump, h.ProxyCommand, h.ForwardAgent, h.ForwardX11,
		h.StrictHostKeyChecking, h.LogLevel, h.HostKeyAlgorithms, h.KexAlgorithms,
		h.PubkeyAcceptedAlgorithms, h.Ciphers, h.MACs,
	}
	values = append(values, h.IdentityFiles...)
	values = append(values, h.CertificateFiles...)
	values = append(values, h.LocalForwards...)
	values = append(values, h.RemoteForwards...)
	values = append(values, h.DynamicForwards...)
	for k, v := range h.Extra {
		values = append(values, k, v)
	}
	for _, v := range values {
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("host %q: value %q contains a line break; refusing to write it to the config", h.Name, v)
		}
	}
	return nil
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
	// Port is written whenever set, including 22: an explicit "Port 22" must
	// not silently fall through to a later "Host * / Port 2200".
	if h.Port != "" {
		fmt.Fprintf(buf, "  Port %s\n", h.Port)
	}
	for _, f := range h.IdentityFileList() {
		fmt.Fprintf(buf, "  IdentityFile %s\n", f)
	}
	for _, f := range h.CertificateFileList() {
		fmt.Fprintf(buf, "  CertificateFile %s\n", f)
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
