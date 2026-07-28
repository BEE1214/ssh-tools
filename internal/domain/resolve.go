package domain

import (
	"strings"
)

// EffectiveConfig resolves the effective SSH options for a given host name
// by applying Host blocks in order, mirroring what `ssh -G <host>` does.
//
// 1. Start with the Host * block if present.
// 2. Walk all Host blocks in file order.
// 3. For each block whose pattern matches the host name, apply/override its options.
// 4. Return the merged Host.
func EffectiveConfig(hosts []Host, hostName string) (Host, error) {
	var result Host
	found := false

	for _, h := range hosts {
		if !matchPattern(h.Name, hostName) {
			continue
		}

		if !found {
			result = Host{Name: hostName}
			found = true
		}

		mergeHost(&result, h)
	}

	if !found {
		return Host{}, ErrHostNotFound
	}

	// Set the Name to the requested host name, not the pattern.
	result.Name = hostName
	return result, nil
}

// ErrHostNotFound is returned when no Host block matches the given name.
var ErrHostNotFound = errHostNotFound{}

type errHostNotFound struct{}

func (errHostNotFound) Error() string { return "host not found" }

// matchPattern checks if an SSH Host pattern matches a host name.
// Supports:
//   - "*" (matches everything)
//   - single wildcard "*" at end (prefix match)
//   - exact match
//   - multiple patterns separated by spaces
func matchPattern(pattern, name string) bool {
	for _, p := range strings.Fields(pattern) {
		if p == "*" {
			return true
		}
		if strings.Contains(p, "*") {
			if wildcardMatch(p, name) {
				return true
			}
			continue
		}
		if p == name {
			return true
		}
	}
	return false
}

// wildcardMatch does glob-style matching with "*".
func wildcardMatch(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}

	// First part must be a prefix.
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]

	// Last part must be a suffix.
	last := parts[len(parts)-1]
	if last != "" && !strings.HasSuffix(name, last) {
		return false
	}
	name = name[:len(name)-len(last)]

	// Middle parts must appear in order.
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(name, parts[i])
		if idx == -1 {
			return false
		}
		name = name[idx+len(parts[i]):]
	}

	return true
}

// mergeHost applies all non-empty fields from src onto dst.
func mergeHost(dst *Host, src Host) {
	if src.HostName != "" {
		dst.HostName = src.HostName
	}
	if src.User != "" {
		dst.User = src.User
	}
	if src.Port != "" {
		dst.Port = src.Port
	}
	if src.IdentityFile != "" {
		dst.IdentityFile = src.IdentityFile
	}
	if src.ProxyJump != "" {
		dst.ProxyJump = src.ProxyJump
	}
	if src.ProxyCommand != "" {
		dst.ProxyCommand = src.ProxyCommand
	}
	if src.ForwardAgent != "" {
		dst.ForwardAgent = src.ForwardAgent
	}
	if src.ForwardX11 != "" {
		dst.ForwardX11 = src.ForwardX11
	}
	if src.StrictHostKeyChecking != "" {
		dst.StrictHostKeyChecking = src.StrictHostKeyChecking
	}
	if src.LogLevel != "" {
		dst.LogLevel = src.LogLevel
	}
	if src.HostKeyAlgorithms != "" {
		dst.HostKeyAlgorithms = src.HostKeyAlgorithms
	}
	if src.KexAlgorithms != "" {
		dst.KexAlgorithms = src.KexAlgorithms
	}
	if src.PubkeyAcceptedAlgorithms != "" {
		dst.PubkeyAcceptedAlgorithms = src.PubkeyAcceptedAlgorithms
	}
	if src.Ciphers != "" {
		dst.Ciphers = src.Ciphers
	}
	if src.MACs != "" {
		dst.MACs = src.MACs
	}
	for k, v := range src.Extra {
		if dst.Extra == nil {
			dst.Extra = make(map[string]string)
		}
		dst.Extra[k] = v
	}
}