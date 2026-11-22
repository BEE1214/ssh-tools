package app

import (
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// InitDefaults generates the Host * defaults block of a set-up config
// (PLAN-p3-p4.md R11): a new block is appended as the LAST host block of the
// main file, because ssh uses the first value found for each option, so a
// catch-all Host * only supplies defaults when it comes after the specific
// hosts. It is written only when no Host * exists in any loaded file; an
// existing one is never rewritten, and note says where it is. A config that is
// not set up gets ErrNotSetUp (use InitFresh for a machine without a config).
func (a *App) InitDefaults() (note string, err error) {
	_, note, err = a.InitDefaultsReport()
	return note, err
}

// InitDefaultsReport is InitDefaults that also says whether a block was
// written (false: an existing Host * was found, see note).
func (a *App) InitDefaultsReport() (written bool, note string, err error) {
	v, err := a.gate()
	if err != nil {
		return false, "", err
	}
	return a.initManaged(v)
}

// defaultHost returns the recommended Host * block with security and
// keepalive defaults.
func defaultHost() domain.Host {
	return domain.Host{
		Name:                  "*",
		Source:                domain.SourceManual,
		StrictHostKeyChecking: "accept-new",
		Extra: map[string]string{
			"ServerAliveInterval": "60",
			"ServerAliveCountMax": "3",
			"IdentitiesOnly":      "yes",
			"HashKnownHosts":      "yes",
		},
		// Algorithm lists are preference lists filtered through what the local
		// ssh supports (ssh -Q). An unknown name makes ssh abort on the whole
		// config, so a list that cannot be verified is left out entirely and
		// OpenSSH's own defaults apply.
		KexAlgorithms: preferred(queryKex,
			"mlkem768x25519-sha256",
			"sntrup761x25519-sha512|sntrup761x25519-sha512@openssh.com",
			"curve25519-sha256",
			"curve25519-sha256@libssh.org"),
		HostKeyAlgorithms: preferred(queryKeySig,
			"ssh-ed25519",
			"ssh-ed25519-cert-v01@openssh.com",
			"rsa-sha2-512",
			"rsa-sha2-256"),
		Ciphers: preferred(queryCipher,
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com"),
		MACs: preferred(queryMAC,
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com"),
	}
}

// FormatHost returns a human-readable string representation of a host.
func FormatHost(h domain.Host) string {
	var b strings.Builder

	b.WriteString("Host " + h.Name + "\n")
	if h.HostName != "" {
		b.WriteString("  HostName " + h.HostName + "\n")
	}
	if h.User != "" {
		b.WriteString("  User " + h.User + "\n")
	}
	if h.Port != "" && h.Port != "22" {
		b.WriteString("  Port " + h.Port + "\n")
	}
	if h.IdentityFile != "" {
		b.WriteString("  IdentityFile " + h.IdentityFile + "\n")
	}
	if h.CertificateFile != "" {
		b.WriteString("  CertificateFile " + h.CertificateFile + "\n")
	}
	if h.ProxyJump != "" {
		b.WriteString("  ProxyJump " + h.ProxyJump + "\n")
	}
	if h.ProxyCommand != "" {
		b.WriteString("  ProxyCommand " + h.ProxyCommand + "\n")
	}
	if h.ForwardAgent != "" {
		b.WriteString("  ForwardAgent " + h.ForwardAgent + "\n")
	}
	if h.ForwardX11 != "" {
		b.WriteString("  ForwardX11 " + h.ForwardX11 + "\n")
	}
	if h.StrictHostKeyChecking != "" {
		b.WriteString("  StrictHostKeyChecking " + h.StrictHostKeyChecking + "\n")
	}
	if h.LogLevel != "" {
		b.WriteString("  LogLevel " + h.LogLevel + "\n")
	}
	if h.HostKeyAlgorithms != "" {
		b.WriteString("  HostKeyAlgorithms " + h.HostKeyAlgorithms + "\n")
	}
	if h.KexAlgorithms != "" {
		b.WriteString("  KexAlgorithms " + h.KexAlgorithms + "\n")
	}
	if h.Ciphers != "" {
		b.WriteString("  Ciphers " + h.Ciphers + "\n")
	}
	if h.MACs != "" {
		b.WriteString("  MACs " + h.MACs + "\n")
	}
	for _, f := range h.LocalForwards {
		b.WriteString("  LocalForward " + f + "\n")
	}
	for _, f := range h.RemoteForwards {
		b.WriteString("  RemoteForward " + f + "\n")
	}
	for _, f := range h.DynamicForwards {
		b.WriteString("  DynamicForward " + f + "\n")
	}

	for k, v := range h.Extra {
		b.WriteString("  " + k + " " + v + "\n")
	}

	return b.String()
}
