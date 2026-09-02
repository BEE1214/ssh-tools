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
		if h.Source == domain.SourceDevPod {
			writeDevPodBlock(&buf, h)
		} else {
			writeHostBlock(&buf, h)
		}

		// Add blank line between blocks (but not after the last one).
		if i < len(cfg.Hosts)-1 {
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