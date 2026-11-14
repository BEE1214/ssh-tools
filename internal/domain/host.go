package domain

// HostSource indicates how a host block was created.
type HostSource int

const (
	// SourceManual is a hand-written host block.
	SourceManual HostSource = iota
	// SourceDevPod is a host block managed by DevPod (delimited by
	// "# DevPod Start <name>" / "# DevPod End <name>" marker comments).
	// These are read-only in the TUI and never reformatted by the writer.
	SourceDevPod
)

// Host represents a single Host block in an SSH config file.
type Host struct {
	// Name is the Host pattern (usually a hostname, can be a wildcard like "*").
	Name string

	// First-class SSH options — the ones you actually use.
	HostName        string
	User            string
	Port            string
	IdentityFile    string
	CertificateFile string
	ProxyJump       string
	ProxyCommand    string

	// Boolean options stored as strings for faithful round-trip.
	ForwardAgent string
	ForwardX11   string

	// Security-related options.
	StrictHostKeyChecking string
	LogLevel              string

	// Algorithm options.
	HostKeyAlgorithms    string
	KexAlgorithms        string
	PubkeyAcceptedAlgorithms string
	Ciphers              string
	MACs                 string

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