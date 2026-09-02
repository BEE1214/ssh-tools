package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// maxSafePerm is the maximum permission mask a private key or the ssh
// config should have. Anything group/world accessible is flagged (ssh
// outright refuses world-writable keys).
const maxSafePerm = 0o100

// CheckFiles verifies that referenced files exist and have safe
// permissions. It returns file-integrity issues for:
//   - IdentityFile paths that don't exist
//   - CertificateFile paths that don't exist
//   - private keys / config readable by group or others
func (a *App) CheckFiles() ([]domain.Issue, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}

	var issues []domain.Issue

	for _, h := range cfg.Hosts {
		// IdentityFile checks.
		if h.IdentityFile != "" {
			path := expandTilde(h.IdentityFile)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				issues = append(issues, domain.Issue{
					HostName: h.Name,
					Severity: domain.SeverityError,
					Rule:     "missing-identity-file",
					Message:  fmt.Sprintf("IdentityFile %s does not exist", h.IdentityFile),
					Line:     h.LineStart,
				})
			} else if err == nil {
				// Only check permissions on private keys — the .pub is public.
				if !strings.HasSuffix(path, ".pub") {
					issues = append(issues, checkPerm(h.Name, h.IdentityFile, path, h.LineStart)...)
				}
			}
		}

		// CertificateFile checks.
		if h.CertificateFile != "" {
			path := expandTilde(h.CertificateFile)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				issues = append(issues, domain.Issue{
					HostName: h.Name,
					Severity: domain.SeverityWarning,
					Rule:     "missing-cert-file",
					Message:  fmt.Sprintf("CertificateFile %s does not exist", h.CertificateFile),
					Line:     h.LineStart,
				})
			}
		}
	}

	// Config file itself should not be readable by others.
	issues = append(issues, checkPerm("", a.configPath, a.configPath, 0)...)

	return issues, nil
}

// CheckCertExpiry inspects all certificates referenced in the config and
// reports expired ones.
func (a *App) CheckCertExpiry() ([]domain.Issue, error) {
	cfg, err := a.load()
	if err != nil {
		return nil, err
	}

	var issues []domain.Issue
	seen := make(map[string]bool)

	for _, h := range cfg.Hosts {
		if h.CertificateFile == "" {
			continue
		}
		path := expandTilde(h.CertificateFile)
		if seen[path] {
			continue
		}
		seen[path] = true

		cert, err := a.InspectCert(path)
		if err != nil {
			continue // missing file already reported by CheckFiles
		}
		if issue, expired := domain.ValidateCertExpiry(cert); expired {
			issue.HostName = h.Name
			issues = append(issues, issue)
		}
	}

	return issues, nil
}

// checkPerm flags files readable/writable by group or others.
func checkPerm(hostName, displayPath, realPath string, line int) []domain.Issue {
	info, err := os.Stat(realPath)
	if err != nil {
		return nil
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return nil // owner-only — safe
	}

	what := "file"
	if info.IsDir() {
		what = "directory"
	}

	return []domain.Issue{{
		HostName: hostName,
		Severity: domain.SeverityError,
		Rule:     "unsafe-permissions",
		Message:  fmt.Sprintf("%s %s has permissions %04o — group/world access (ssh requires owner-only, e.g. 0600)", what, displayPath, perm),
		Line:     line,
	}}
}

// displayPath converts an absolute path back to ~/ form for messages.
func displayPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return path
	}
	return "~/" + rel
}
