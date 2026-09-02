package app

import (
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// InitDefaults generates or repairs the Host * defaults block at the top
// of the config file. If a Host * block already exists, it is replaced.
func (a *App) InitDefaults() error {
	cfg, err := a.load()
	if err != nil {
		return err
	}

	defaults := defaultHost()

	// Find and replace existing Host * block, or prepend.
	found := false
	for i, h := range cfg.Hosts {
		if h.IsWildcard() {
			cfg.Hosts[i] = defaults
			found = true
			break
		}
	}

	if !found {
		// Prepend Host * at the beginning.
		cfg.Hosts = append([]domain.Host{defaults}, cfg.Hosts...)
	}

	return a.save(cfg)
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
		KexAlgorithms:     "mlkem768x25519-sha256@openssh.com,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org",
		HostKeyAlgorithms: "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256",
		Ciphers:           "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
		MACs:              "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
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

	for k, v := range h.Extra {
		b.WriteString("  " + k + " " + v + "\n")
	}

	return b.String()
}
