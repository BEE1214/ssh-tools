package config

import (
	"fmt"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// What is left of the writer after P7: the canonical text of one new host
// block, which Doc.AppendBlock and the Host * block of `sshm init` use (see
// BlockLines). The main file is never re-serialized.

// checkLineBreaks returns an error if any value the writer would emit for h
// contains a CR or LF.
func checkLineBreaks(h domain.Host) error {
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

// groupCommentFor returns the "# group: <name>" comment line to put above a
// host block, or "" when the group equals the prefix heuristic (GroupFor) — in
// that case the comment is redundant and omitted.
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
