package domain

import (
	"fmt"
	"strings"
	"time"
)

// Certificate holds metadata parsed from an SSH certificate via ssh-keygen -L.
type Certificate struct {
	// Path is the filesystem path to the -cert.pub file.
	Path string

	// Identity is the key ID (-I flag value passed to ssh-keygen -s).
	Identity string

	// Principals are the allowed user/host principals (-n flag value).
	Principals []string

	// ValidAfter is the certificate's "not before" time.
	ValidAfter time.Time

	// ValidBefore is the certificate's "not after" time (expiry).
	ValidBefore time.Time

	// Serial is the certificate serial number.
	Serial uint64

	// CAKey is the fingerprint of the signing CA key.
	CAKey string

	// KeyType is the key type string (e.g. "ssh-ed25519-cert-v01@openssh.com").
	KeyType string

	// PubKeyFingerprint is the SHA256 fingerprint of the certified public key.
	PubKeyFingerprint string
}

// IsExpired returns true if the certificate has passed its ValidBefore time.
func (c Certificate) IsExpired() bool {
	return time.Now().After(c.ValidBefore)
}

// Validity returns a human-readable validity window.
func (c Certificate) Validity() string {
	return fmt.Sprintf("%s to %s", c.ValidAfter.Format("2006-01-02 15:04:05"), c.ValidBefore.Format("2006-01-02 15:04:05"))
}

// ParseCertInfo parses the output of `ssh-keygen -L -f <cert.pub>` into a
// Certificate struct. The output looks like:
//
//	/path/to/cert.pub:
//	        Type: ssh-ed25519-cert-v01@openssh.com user certificate
//	        Public key: SHA256:abcdef...
//	        Signing CA: SHA256:fedcba... (using ssh-ed25519)
//	        Key ID: "my-identity"
//	        Serial: 1234567890
//	        Valid: from 2024-01-01T00:00:00 to 2024-01-01T12:00:00
//	        Principals:
//	                user1
//	                user2
//	        Critical Options:
//	                (none)
//	        Extensions:
//	                permit-X11-forwarding
//	                permit-agent-forwarding
//	                permit-port-forwarding
//	                permit-pty
//	                permit-user-rc
func ParseCertInfo(path, output string) (Certificate, error) {
	c := Certificate{Path: path}

	lines := strings.Split(output, "\n")

	inPrincipals := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "Type:") {
			// "Type: ssh-ed25519-cert-v01@openssh.com user certificate"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				c.KeyType = parts[1]
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Public key:") {
			// "Public key: SHA256:abcdef..."
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				c.PubKeyFingerprint = parts[2]
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Signing CA:") {
			// "Signing CA: SHA256:fedcba... (using ssh-ed25519)"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				c.CAKey = parts[2]
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Key ID:") {
			// Key ID: "my-identity"
			rest := strings.TrimPrefix(trimmed, "Key ID:")
			c.Identity = strings.Trim(strings.Trim(rest, `"`), " ")
			continue
		}

		if strings.HasPrefix(trimmed, "Serial:") {
			// "Serial: 1234567890"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				var serial uint64
				_, _ = fmt.Sscanf(parts[1], "%d", &serial)
				c.Serial = serial
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Valid:") {
			// "Valid: from 2024-01-01T00:00:00 to 2024-01-01T12:00:00"
			// Parse "from" and "to" dates in ISO format.
			rest := strings.TrimPrefix(trimmed, "Valid:")
			rest = strings.TrimSpace(rest)
			// Expected: "from 2024-01-01T00:00:00 to 2024-01-01T12:00:00"
			if strings.HasPrefix(rest, "from ") {
				rest = strings.TrimPrefix(rest, "from ")
				idx := strings.Index(rest, " to ")
				if idx > 0 {
					afterStr := rest[:idx]
					beforeStr := rest[idx+4:]

					// ssh-keygen outputs dates like "2024-01-01T00:00:00"
					// but also can include timezone. Try multiple layouts.
					c.ValidAfter = parseCertTime(afterStr)
					c.ValidBefore = parseCertTime(beforeStr)
				}
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Principals:") {
			inPrincipals = true
			continue
		}

		// Principal entries are indented under the "Principals:" header.
		// They end when we hit another section header (indented but not
		// a principal, like "Critical Options:" or "Extensions:").
		if inPrincipals {
			if strings.HasPrefix(trimmed, "Critical Options:") ||
				strings.HasPrefix(trimmed, "Extensions:") ||
				strings.HasPrefix(trimmed, "(none)") && i > 0 && !strings.Contains(lines[i-1], "Principals") {
				inPrincipals = false
				continue
			}
			if trimmed == "(none)" || trimmed == "" {
				continue
			}
			// Stop if this line doesn't look like a principal (it's a new section).
			if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, "@") {
				inPrincipals = false
				continue
			}
			c.Principals = append(c.Principals, trimmed)
		}
	}

	if c.ValidBefore.IsZero() {
		return c, fmt.Errorf("could not parse certificate validity from output")
	}

	return c, nil
}

// parseCertTime parses an ssh-keygen date string.
// ssh-keygen outputs dates in formats like:
//   "2024-01-01T00:00:00"
//   "2024-01-01T00:00:00+0000"
//   "2024-01-01T00:00:00Z"
func parseCertTime(s string) time.Time {
	s = strings.TrimSpace(s)
	layouts := []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05.000000Z",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}