package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// caConfigFile stores the CA key path so you don't repeat --ca-key on every
// invocation. Lives in ~/.ssh/sshm-ca.conf.
const caConfigFile = "sshm-ca.conf"

// SignOpts holds parameters for signing a public key with a CA.
type SignOpts struct {
	// Identity is the key ID (-I flag). If empty, uses the host name or
	// the basename of the key path.
	Identity string

	// Principals is a comma-separated list of principals (-n flag).
	// If empty, uses the host's User field.
	Principals string

	// Validity is the -V value (e.g. "+12h", "+1d", "+1w").
	// If empty, defaults to "+12h".
	Validity string

	// CAKey is the path to the CA private key. If empty, reads from
	// ~/.ssh/sshm-ca.conf.
	CAKey string

	// HostName is the ssh config host name to look up IdentityFile from.
	// If empty, PubKeyPath must be set.
	HostName string

	// PubKeyPath is a direct path to a .pub file. Used when HostName is
	// empty or when signing a key not in ssh config.
	PubKeyPath string
}

// InitCA generates a new CA key pair using ssh-keygen.
// keyPath is the path to write the CA key (e.g. ~/.ssh/my-ca).
func (a *App) InitCA(keyPath string) error {
	if keyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("get home dir: %w", err)
		}
		keyPath = filepath.Join(home, ".ssh", "sshm-ca")
	}

	// Don't overwrite an existing CA key.
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("CA key already exists at %s — refusing to overwrite", keyPath)
	}

	binary, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return fmt.Errorf("ssh-keygen not found in PATH: %w", err)
	}

	cmd := exec.Command(binary,
		"-t", "ed25519",
		"-f", keyPath,
		"-N", "",
		"-C", "sshm-CA",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen: %w", err)
	}

	// Store the CA key path for future use.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	confPath := filepath.Join(home, ".ssh", caConfigFile)
	if err := os.WriteFile(confPath, []byte(keyPath+"\n"), 0o600); err != nil {
		return fmt.Errorf("write CA config: %w", err)
	}

	return nil
}

// caKeyPath reads the CA key path from ~/.ssh/sshm-ca.conf.
func caKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	confPath := filepath.Join(home, ".ssh", caConfigFile)
	data, err := os.ReadFile(confPath)
	if err != nil {
		return "", fmt.Errorf("read CA config (%s) — run 'sshm cert init' first: %w", confPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// SignCert signs a public key with the CA key, producing a short-lived
// certificate. It wraps `ssh-keygen -s`.
func (a *App) SignCert(opts SignOpts) (string, error) {
	// Resolve CA key.
	caKey := opts.CAKey
	if caKey == "" {
		var err error
		caKey, err = caKeyPath()
		if err != nil {
			return "", err
		}
	}
	if _, err := os.Stat(caKey); err != nil {
		return "", fmt.Errorf("CA key not found at %s: %w", caKey, err)
	}

	// Resolve the public key to sign.
	pubKeyPath := opts.PubKeyPath
	principals := opts.Principals
	identity := opts.Identity

	if pubKeyPath == "" && opts.HostName != "" {
		// Look up the host in ssh config.
		l, err := a.loadAll()
		if err != nil {
			return "", fmt.Errorf("load config: %w", err)
		}
		if err := a.ensureHostNotDisabled(l.Hosts, opts.HostName); err != nil {
			return "", err
		}
		idx := findHostIndex(l.Hosts, opts.HostName)
		if idx == -1 {
			return "", fmt.Errorf("host %q not found in config", opts.HostName)
		}
		h := l.Hosts[idx]
		if h.IdentityFile == "" {
			return "", fmt.Errorf("host %q has no IdentityFile — cannot sign", opts.HostName)
		}
		// Expand ~ to home dir.
		pubKeyPath = expandTilde(h.IdentityFile) + ".pub"
		if principals == "" {
			principals = h.User
		}
		if identity == "" {
			identity = opts.HostName
		}
	}

	if pubKeyPath == "" {
		return "", fmt.Errorf("no public key path — provide --identity <host> or --pubkey <path>")
	}
	if _, err := os.Stat(pubKeyPath); err != nil {
		return "", fmt.Errorf("public key not found at %s: %w", pubKeyPath, err)
	}

	// Defaults.
	if identity == "" {
		identity = filepath.Base(strings.TrimSuffix(pubKeyPath, ".pub"))
	}
	if principals == "" {
		// Fall back to current user.
		principals = os.Getenv("USER")
		if principals == "" {
			principals = "root"
		}
	}
	if opts.Validity == "" {
		opts.Validity = "+12h"
	}

	binary, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return "", fmt.Errorf("ssh-keygen not found in PATH: %w", err)
	}

	args := []string{
		"-s", caKey,
		"-I", identity,
		"-n", principals,
		"-V", opts.Validity,
		pubKeyPath,
	}
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh-keygen -s: %w", err)
	}

	// ssh-keygen writes the cert to <pubkey-basename>-cert.pub in the
	// same directory as the .pub file.
	dir := filepath.Dir(pubKeyPath)
	base := strings.TrimSuffix(filepath.Base(pubKeyPath), ".pub")
	certPath := filepath.Join(dir, base+"-cert.pub")

	if _, err := os.Stat(certPath); err != nil {
		return "", fmt.Errorf("certificate was not created at expected path %s: %w", certPath, err)
	}

	// If we signed via a host name, write CertificateFile into its config block.
	if opts.HostName != "" {
		changes := map[string]string{"certificatefile": certPath}
		if err := a.EditHost(opts.HostName, changes); err != nil {
			return certPath, fmt.Errorf("cert created but failed to update config: %w", err)
		}
	}

	return certPath, nil
}

// ListCerts walks ~/.ssh/ for *-cert.pub files and returns their metadata.
func (a *App) ListCerts() ([]domain.Certificate, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	sshDir := filepath.Join(home, ".ssh")

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, fmt.Errorf("read ~/.ssh: %w", err)
	}

	var certs []domain.Certificate
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, "-cert.pub") {
			continue
		}
		certPath := filepath.Join(sshDir, name)
		cert, err := a.InspectCert(certPath)
		if err != nil {
			continue // skip unreadable certs
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// InspectCert runs ssh-keygen -L on a cert file and parses the output.
func (a *App) InspectCert(path string) (domain.Certificate, error) {
	if _, err := os.Stat(path); err != nil {
		return domain.Certificate{}, fmt.Errorf("cert file not found: %w", err)
	}

	binary, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return domain.Certificate{}, fmt.Errorf("ssh-keygen not found in PATH: %w", err)
	}

	cmd := exec.Command(binary, "-L", "-f", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return domain.Certificate{}, fmt.Errorf("ssh-keygen -L: %w", err)
	}

	return domain.ParseCertInfo(path, string(output))
}

// RevokeCert removes the CertificateFile line from the host's config block
// and deletes the cert file. This is "soft revocation" — OpenSSH has no CRL,
// so the cert may still be accepted by servers until they re-read authorized_keys
// or the CA's known_hosts entry is removed.
func (a *App) RevokeCert(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cert file not found: %w", err)
	}

	// Identity (which may match a host name) is only known if ssh-keygen can
	// read the cert. The CertificateFile lookup below must not depend on it.
	identity := ""
	if cert, err := a.InspectCert(path); err == nil {
		identity = cert.Identity
	}

	// Look the host up across the main file AND included files, so a cert
	// referenced from an included host is not silently orphaned.
	l, err := a.loadAll()
	if err != nil {
		return fmt.Errorf("cert file not deleted: cannot check which host references it: %w", err)
	}
	target := filepath.Clean(expandTilde(path))
	for _, h := range l.Hosts {
		byFile := h.CertificateFile != "" && filepath.Clean(expandTilde(h.CertificateFile)) == target
		byIdentity := identity != "" && h.Name == identity
		if byFile || byIdentity {
			// If the CertificateFile line cannot be cleared (host defined in
			// an included file, disabled, ...) keep the cert file: deleting
			// it would leave a dangling CertificateFile line behind.
			if err := a.ClearCertificateFile(h.Name); err != nil {
				return fmt.Errorf("cert file not deleted: cannot clear CertificateFile of host %q: %w", h.Name, err)
			}
		}
	}

	// Delete the cert file.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete cert file: %w", err)
	}

	return nil
}

// ClearCertificateFile removes the CertificateFile setting from a host by
// setting it to empty and saving. This is used by RevokeCert since EditHost
// with an empty map is a no-op.
func (a *App) ClearCertificateFile(name string) error {
	if err := a.ensureInMain(name); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}

	idx := findHostIndex(cfg.Hosts, name)
	if idx == -1 {
		return nil // host not found, nothing to clear
	}
	if err := ensureEditable(cfg.Hosts[idx]); err != nil {
		return err
	}

	cfg.Hosts[idx].CertificateFile = ""
	return a.save(cfg)
}

// expandTilde replaces a leading ~ with the home directory.
func expandTilde(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
