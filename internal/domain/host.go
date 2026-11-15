package domain

import "strings"

// HostSource indicates how a host block was created.
type HostSource int

const (
	// SourceManual is a hand-written host block.
	SourceManual HostSource = iota
	// SourceDevPod is a host block managed by DevPod (delimited by
	// "# DevPod Start <name>" / "# DevPod End <name>" marker comments).
	// These are read-only in the TUI (no edit/duplicate/delete). The writer
	// keeps their marker comments but re-emits the options in canonical order.
	SourceDevPod
)

// Host represents a single Host block in an SSH config file.
type Host struct {
	// Name is the argument text of the Host line exactly as written in the
	// file (usually a plain host name; can be a wildcard like "*", a pattern
	// list, or text with quotes or an inline comment). The legacy writer puts
	// it back unchanged, so it is never normalized.
	Name string

	// Patterns are the patterns of the Host line as ssh reads Name: split
	// into words with quotes removed and a trailing "# comment" dropped
	// (`"a b"` is ONE pattern, `x # note` is just x). The parser fills it;
	// it is non-nil (possibly empty: "Host # note" matches nothing) for every
	// parsed host and nil for a Host built in code. Use PatternList to read
	// it. Whoever changes Name must reset Patterns to nil.
	Patterns []string

	// First-class SSH options — the ones you actually use.
	HostName        string
	User            string
	Port            string
	IdentityFile    string
	CertificateFile string
	ProxyJump       string
	ProxyCommand    string

	// IdentityFiles / CertificateFiles hold EVERY IdentityFile / CertificateFile
	// value of the block, in order (ssh accumulates them). The singular
	// fields above are the first value. See IdentityFileList.
	IdentityFiles    []string
	CertificateFiles []string

	// Boolean options stored as strings for faithful round-trip.
	ForwardAgent string
	ForwardX11   string

	// Security-related options.
	StrictHostKeyChecking string
	LogLevel              string

	// Algorithm options.
	HostKeyAlgorithms        string
	KexAlgorithms            string
	PubkeyAcceptedAlgorithms string
	Ciphers                  string
	MACs                     string

	// Extra holds any SSH option not modeled above.
	// Key is the canonical (canonical-cased) option name.
	// The writer outputs these verbatim.
	Extra map[string]string

	// Port-forwarding options — ssh_config(5) allows many of each per
	// block, so unlike the fields above these are first-class slices
	// rather than folding into Extra. Each entry is stored normalized in
	// config syntax: two space-separated tokens for local/remote
	// ("10100 192.168.1.100:80"), one token for dynamic ("1080").
	LocalForwards   []string
	RemoteForwards  []string
	DynamicForwards []string

	// Metadata — derived, not written to config.

	// Group is the detected group name (from Name prefix or "# group:" comment).
	// Empty string means ungrouped.
	Group string

	// Disabled marks a host block that is currently commented out of the
	// config via "# sshm disabled group=<name> start/end" markers. Disabled
	// hosts are invisible to raw ssh (unresolvable) and rejected by
	// sshm connect/copy; enable restores the original block bytes.
	Disabled bool

	// RawBlock is the verbatim source text of this host block (Host line
	// through the last option/comment line, without trailing newline).
	// Populated by the parser; the writer re-emits it verbatim for disabled
	// blocks so enable can restore the original formatting byte-for-byte.
	RawBlock string

	// Source indicates how this block was created.
	Source HostSource

	// SourceFile is the absolute path of the config file this block was read
	// from. Set by config.Load for every host (main file and included files);
	// empty for hosts built in memory or parsed without Load.
	SourceFile string

	// LineStart is the 1-indexed line number of the "Host" line in the original file.
	// LineEnd is the 1-indexed line number of the last key-value line (or the Host line
	// if the block has no options).
	LineStart int
	LineEnd   int
}

// DefaultIdentityFile is the default SSH key used for ad-hoc connections
// and when adding a host without an explicit --identity flag.
const DefaultIdentityFile = "~/.ssh/id_ed25519"

// HasHostName returns true if the Host has an explicit HostName set.
func (h Host) HasHostName() bool { return h.HostName != "" }

// HasIdentityFile returns true if the Host has an explicit IdentityFile set.
func (h Host) HasIdentityFile() bool { return h.IdentityFile != "" }

// IdentityFileList returns every IdentityFile value in order. The singular
// IdentityFile is the first value and wins over IdentityFiles[0] when they
// differ (callers that only know the singular field keep working); an empty
// list falls back to the singular field. Code that means to REPLACE the
// option (an edit) must set both fields, or the other values stay.
func (h Host) IdentityFileList() []string {
	return fileList(h.IdentityFile, h.IdentityFiles)
}

// CertificateFileList is IdentityFileList for CertificateFile.
func (h Host) CertificateFileList() []string {
	return fileList(h.CertificateFile, h.CertificateFiles)
}

func fileList(first string, all []string) []string {
	switch {
	case len(all) == 0 && first == "":
		return nil
	case len(all) == 0:
		return []string{first}
	case first == "" || all[0] == first:
		return append([]string(nil), all...)
	}
	out := append([]string(nil), all...)
	out[0] = first
	return out
}

// PatternList returns the Host patterns as ssh reads them: Patterns when the
// parser set them, else Name split on blanks (a Host built in code, whose
// name is a plain word or a blank-separated pattern list).
func (h Host) PatternList() []string {
	if h.Patterns != nil {
		return h.Patterns
	}
	return strings.Fields(h.Name)
}

// IsWildcard returns true if this is a "Host *" defaults block.
func (h Host) IsWildcard() bool { return h.Name == "*" }

// CanonicalPort returns the port, defaulting to "22" if not set.
func (h Host) CanonicalPort() string {
	if h.Port == "" {
		return "22"
	}
	return h.Port
}

// DisplayUser returns the User, or "(default)" if not set.
func (h Host) DisplayUser() string {
	if h.User == "" {
		return "(default)"
	}
	return h.User
}

// DisplayHost returns HostName if set, otherwise Name (the Host pattern).
func (h Host) DisplayHost() string {
	if h.HostName != "" {
		return h.HostName
	}
	return h.Name
}
