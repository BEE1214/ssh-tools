package domain

import (
	"fmt"
	"strconv"
	"strings"
)

// ForwardKind identifies which ssh port-forwarding mode a spec is for.
type ForwardKind int

const (
	// ForwardLocal is a local forward (-L / LocalForward).
	ForwardLocal ForwardKind = iota
	// ForwardRemote is a remote forward (-R / RemoteForward).
	ForwardRemote
	// ForwardDynamic is a dynamic/SOCKS forward (-D / DynamicForward).
	ForwardDynamic
)

// Flag returns the ssh command-line flag for this forward kind.
func (k ForwardKind) Flag() string {
	switch k {
	case ForwardRemote:
		return "-R"
	case ForwardDynamic:
		return "-D"
	default:
		return "-L"
	}
}

// ConfigKey returns the ssh_config(5) keyword for this forward kind.
func (k ForwardKind) ConfigKey() string {
	switch k {
	case ForwardRemote:
		return "RemoteForward"
	case ForwardDynamic:
		return "DynamicForward"
	default:
		return "LocalForward"
	}
}

// ParseForwardSpec validates a forward spec as typed on the CLI and returns
// its normalized ssh_config storage form.
//
// Local/remote specs are "listenPort:targetHost:targetPort" or
// "bindAddr:listenPort:targetHost:targetPort" — split on the last two
// colons, so the listen spec (everything before) may itself contain a
// colon for the bind address. They normalize to two space-separated
// tokens: "[bindAddr:]listenPort targetHost:targetPort".
//
// Dynamic specs are "listenPort" or "bindAddr:listenPort" and normalize to
// themselves (one token).
//
// IPv6 bracket addresses ("[::1]:...") are out of scope and return an error.
func ParseForwardSpec(kind ForwardKind, spec string) (string, error) {
	if strings.ContainsAny(spec, "[]") {
		return "", fmt.Errorf("invalid forward spec %q: IPv6 bracket addresses are not supported", spec)
	}

	if kind == ForwardDynamic {
		if !isValidListenSpec(spec) {
			return "", fmt.Errorf("invalid forward spec %q: expected [bindAddr:]port", spec)
		}
		return spec, nil
	}

	lastColon := strings.LastIndex(spec, ":")
	if lastColon == -1 {
		return "", fmt.Errorf("invalid forward spec %q: expected listenPort:targetHost:targetPort", spec)
	}
	targetPort := spec[lastColon+1:]

	head := spec[:lastColon]
	prevColon := strings.LastIndex(head, ":")
	if prevColon == -1 {
		return "", fmt.Errorf("invalid forward spec %q: expected listenPort:targetHost:targetPort", spec)
	}
	listenSpec := head[:prevColon]
	targetHost := head[prevColon+1:]

	if listenSpec == "" || targetHost == "" || targetPort == "" {
		return "", fmt.Errorf("invalid forward spec %q: expected listenPort:targetHost:targetPort", spec)
	}
	if !isValidListenSpec(listenSpec) {
		return "", fmt.Errorf("invalid forward spec %q: expected [bindAddr:]port", spec)
	}
	if !isValidPort(targetPort) {
		return "", fmt.Errorf("invalid forward spec %q: invalid target port %q", spec, targetPort)
	}

	return listenSpec + " " + targetHost + ":" + targetPort, nil
}

// ValidateForwardEntry validates an already-stored (normalized) forward
// entry, as found in Host.LocalForwards/RemoteForwards/DynamicForwards.
//
// Local/remote entries must be exactly two whitespace-separated tokens:
// token1 = "[bindAddr:]port" (numeric port 1-65535), token2 containing a
// colon (targetHost:targetPort). Dynamic entries must be exactly one
// token, "[bindAddr:]port".
func ValidateForwardEntry(kind ForwardKind, entry string) error {
	fields := strings.Fields(entry)

	if kind == ForwardDynamic {
		if len(fields) != 1 || !isValidListenSpec(fields[0]) {
			return fmt.Errorf("invalid %s entry %q: expected \"[bindAddr:]port\"", kind.ConfigKey(), entry)
		}
		return nil
	}

	if len(fields) != 2 || !isValidListenSpec(fields[0]) || !strings.Contains(fields[1], ":") {
		return fmt.Errorf("invalid %s entry %q: expected \"[bindAddr:]port targetHost:targetPort\"", kind.ConfigKey(), entry)
	}
	return nil
}

// ListenPort extracts the numeric listen port from a normalized forward
// entry (the first token for local/remote, the only token for dynamic).
// Returns "" if the entry is malformed.
func ListenPort(kind ForwardKind, entry string) string {
	fields := strings.Fields(entry)
	if len(fields) == 0 {
		return ""
	}
	spec := fields[0]
	if i := strings.LastIndex(spec, ":"); i != -1 {
		return spec[i+1:]
	}
	return spec
}

// isValidListenSpec reports whether s is "port" or "bindAddr:port" with a
// numeric port in 1-65535.
func isValidListenSpec(s string) bool {
	port := s
	if i := strings.LastIndex(s, ":"); i != -1 {
		if s[:i] == "" {
			return false
		}
		port = s[i+1:]
	}
	return isValidPort(port)
}

// isValidPort reports whether s is a numeric port in 1-65535.
func isValidPort(s string) bool {
	n, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return n >= 1 && n <= 65535
}
