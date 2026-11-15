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

	// ValidAfter is the certificate's "not before" time. The zero time means
	// there is no start restriction ("Valid: forever" / "before <ts>").
	ValidAfter time.Time

	// ValidBefore is the certificate's "not after" time (expiry). The zero
	// time means the certificate never expires ("Valid: forever" / "after <ts>").
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

// NeverExpires reports whether the certificate has no expiry time.
func (c Certificate) NeverExpires() bool {
	return c.ValidBefore.IsZero()
}

// IsExpired returns true if the certificate has passed its ValidBefore time.
// A certificate without an expiry never expires.
func (c Certificate) IsExpired() bool {
	return !c.NeverExpires() && time.Now().After(c.ValidBefore)
}

const certTimeFormat = "2006-01-02 15:04:05"

// Expires returns the expiry as display text: the timestamp, or "never".
func (c Certificate) Expires() string {
	if c.NeverExpires() {
		return "never"
	}
	return c.ValidBefore.Format(certTimeFormat)
}

// Validity returns a human-readable validity window: "forever",
// "<from> to <to>", "after <from>" or "before <to>".
func (c Certificate) Validity() string {
	switch {
	case c.ValidAfter.IsZero() && c.ValidBefore.IsZero():
		return "forever"
	case c.ValidBefore.IsZero():
		return "after " + c.ValidAfter.Format(certTimeFormat)
	case c.ValidAfter.IsZero():
		return "before " + c.ValidBefore.Format(certTimeFormat)
	}
	return c.ValidAfter.Format(certTimeFormat) + " to " + c.ValidBefore.Format(certTimeFormat)
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
//
// ssh-keygen prints the validity timestamps in the machine's LOCAL time with no
// zone marker, so they are read in time.Local; use ParseCertInfoIn for another
// zone.
func ParseCertInfo(path, output string) (Certificate, error) {
	return ParseCertInfoIn(path, output, time.Local)
}

// ParseCertInfoIn is ParseCertInfo with an explicit zone for the zone-less
// validity timestamps (a timestamp that carries its own zone keeps it).
func ParseCertInfoIn(path, output string, loc *time.Location) (Certificate, error) {
	if loc == nil {
		loc = time.Local
	}
	c := Certificate{Path: path}

	lines := strings.Split(output, "\n")

	inPrincipals := false
	validSeen := false
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
			if len(parts) >= 3 {
				c.PubKeyFingerprint = parts[2]
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Signing CA:") {
			// "Signing CA: SHA256:fedcba... (using ssh-ed25519)"
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				c.CAKey = parts[2]
			}
			continue
		}

		if strings.HasPrefix(trimmed, "Key ID:") {
			// Key ID: "my-identity"
			rest := strings.TrimPrefix(trimmed, "Key ID:")
			c.Identity = unquoteKeyID(rest)
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
			after, before, ok := parseValidity(strings.TrimPrefix(trimmed, "Valid:"), loc)
			if !ok {
				return c, fmt.Errorf("could not parse certificate validity %q", trimmed)
			}
			c.ValidAfter, c.ValidBefore = after, before
			validSeen = true
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

	if !validSeen {
		return c, fmt.Errorf("could not parse certificate validity from output")
	}

	return c, nil
}

// unquoteKeyID strips exactly one pair of surrounding double quotes from the
// text after "Key ID:". Quotes inside the ID are kept as printed.
func unquoteKeyID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// parseValidity parses the text after "Valid:". ssh-keygen -L prints one of:
//
//	forever
//	from <ts> to <ts>
//	after <ts>     (no expiry)
//	before <ts>    (no start restriction)
//
// A missing bound is returned as the zero time. ok is false for any other
// form or an unparseable timestamp.
func parseValidity(s string, loc *time.Location) (after, before time.Time, ok bool) {
	s = strings.TrimSpace(s)
	switch {
	case s == "forever":
		return after, before, true
	case strings.HasPrefix(s, "from "):
		a, b, found := strings.Cut(strings.TrimPrefix(s, "from "), " to ")
		if !found {
			return after, before, false
		}
		after, before = parseCertTime(a, loc), parseCertTime(b, loc)
		return after, before, !after.IsZero() && !before.IsZero()
	case strings.HasPrefix(s, "after "):
		after = parseCertTime(strings.TrimPrefix(s, "after "), loc)
		return after, before, !after.IsZero()
	case strings.HasPrefix(s, "before "):
		before = parseCertTime(strings.TrimPrefix(s, "before "), loc)
		return after, before, !before.IsZero()
	}
	return after, before, false
}

// parseCertTime parses an ssh-keygen date string.
// ssh-keygen outputs dates in formats like:
//
//	"2024-01-01T00:00:00"        (local time, no zone: the usual output)
//	"2024-01-01T00:00:00+0000"
//	"2024-01-01T00:00:00Z"
//
// A timestamp that carries an explicit zone keeps it; one without is read in
// loc.
func parseCertTime(s string, loc *time.Location) time.Time {
	s = strings.TrimSpace(s)
	layouts := []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05.000000Z",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t
		}
	}
	return time.Time{}
}
