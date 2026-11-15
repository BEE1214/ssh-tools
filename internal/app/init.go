package app

import (
	"fmt"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// InitDefaults generates or repairs the Host * defaults block of the config
// file. A new block is appended as the LAST host block: ssh uses the first
// value found for each option, so a catch-all Host * only supplies defaults
// when it comes after the specific hosts. An existing Host * block is
// replaced in place and never moved; if other hosts follow it (in file order,
// included files inlined), the returned note says its values override theirs.
//
// In managed mode (PLAN-p3-p4.md R11) a new block is appended to the END of the
// main file only when no Host * exists in any loaded file; an existing one is
// never rewritten, and note says where it is.
func (a *App) InitDefaults() (note string, err error) {
	_, note, err = a.InitDefaultsReport()
	return note, err
}

// InitDefaultsReport is InitDefaults that also says whether a block was
// written (false: managed mode found an existing Host *, see note).
func (a *App) InitDefaultsReport() (written bool, note string, err error) {
	if v, err := a.activeView(); err != nil {
		return false, "", err
	} else if v != nil {
		return a.initManaged(v)
	}
	note, err = a.initLegacy()
	return err == nil, note, err
}

func (a *App) initLegacy() (note string, err error) {
	cfg, err := a.load()
	if err != nil {
		return "", err
	}

	defaults := defaultHost()

	found := false
	for i, h := range cfg.Hosts {
		if h.IsWildcard() {
			cfg.Hosts[i] = defaults
			found = true
			break
		}
	}
	if !found {
		cfg.Hosts = append(cfg.Hosts, defaults)
	}
	if err := a.save(cfg); err != nil {
		return "", err
	}
	if found {
		// After the save, so the reported line is the one in the file now.
		note = a.misplacedWildcardNote()
	}
	return note, nil
}

// misplacedWildcardNote reports a Host * block of the main file that is
// followed by other host blocks. Best effort: "" if the config cannot be
// loaded with its includes.
func (a *App) misplacedWildcardNote() string {
	l, err := a.loadAll()
	if err != nil {
		return ""
	}
	for i, h := range l.Hosts {
		if h.Name != "*" || h.SourceFile != l.MainPath() || i == len(l.Hosts)-1 {
			continue
		}
		return fmt.Sprintf("Host * is at line %d, before other hosts; its values override theirs (ssh uses the first value found). Move it to the end.", h.LineStart)
	}
	return ""
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
