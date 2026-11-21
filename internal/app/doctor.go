package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adamdvorsky/ssh-tools/internal/config"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// Rule names of the doctor-only findings (PLAN-p5.md section 4).
const (
	RuleMissingIdentityFile     = "missing-identity-file"    // D7
	RuleMissingCertFile         = "missing-cert-file"        // D8
	RuleUnsafePermissions       = "unsafe-permissions"       // D9, D10
	RuleManagedPermissions      = "managed-permissions"      // D11
	RuleCertExpired             = "cert-expired"             // D12
	RuleNotSetUp                = "not-set-up"               // D14
	RuleIncludeConditional      = "include-conditional"      // D15, D16
	RuleHomeMismatch            = "home-mismatch"            // D17
	RuleSSHMissing              = "ssh-missing"              // D18
	RuleVerifySkipped           = "verify-skipped"           // D19
	RuleSSHRejectsConfig        = "ssh-rejects-config"       // D20
	RuleHardeningHashKnownHosts = "hardening-hashknownhosts" // D21
	RuleHardeningIdentitiesOnly = "hardening-identitiesonly" // D22
	RuleAgentForwardingDefault  = "agent-forwarding-default" // D23
)

// Test seams for the owner rules of D9/D10: the current uid and the owner of a
// file. A non-root test cannot chown a fixture to another user, so tests
// replace ownerOf; production code never reassigns them.
var (
	currentUID = os.Getuid
	ownerOf    = fileOwnerUID
)

// doctorProbeHost is the host name doctor hands to `ssh -G`; it must not
// collide with a real host (PLAN-p5.md section 4, D21-D23).
const doctorProbeHost = "sshm-doctor-probe"

// DoctorOptions are the options of Doctor.
type DoctorOptions struct {
	// SkipFiles omits the file checks D7-D13.
	SkipFiles bool
}

// Doctor returns validate's issues plus the doctor-only findings. It never
// writes anything and never creates a file or a backup.
//
// Order (D5): Validate's issues unchanged, then the file checks (D7-D13), the
// include checks (D14-D17) and the ssh checks (D18-D23), each clause in table
// order, within a clause by file evaluation order and line.
func (a *App) Doctor(opts DoctorOptions) ([]domain.Issue, error) {
	l, err := a.loadAll() // D6: the same error as Validate
	if err != nil {
		return nil, err
	}
	issues := validateLoaded(l) // D2
	managed := a.doctorManagedPath()
	if !opts.SkipFiles {
		issues = append(issues, doctorFileChecks(l, managed)...)
	}
	issues = append(issues, doctorIncludeChecks(l, managed)...)
	issues = append(issues, a.doctorSSHChecks(l)...)
	return issues, nil
}

// doctorManagedPath is the absolute path of the managed file.
func (a *App) doctorManagedPath() string {
	p := a.ManagedPath()
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// issueFile is the Issue.File of a finding in path: empty for the main file
// (as validate does), the path itself for any other file (5.2).
func issueFile(l *config.Loaded, path string) string {
	if path == l.MainPath() {
		return ""
	}
	return path
}

// ---- file checks (D7-D13) ------------------------------------------------------------------

// doctorCheckablePath expands the IdentityFile / CertificateFile value v to the
// path doctor looks at. ok is false for what doctor must not check (D7): the
// value none, a value ssh expands at connect time (% or $), a ~user path and a
// relative path. "~" expands with the passwd home, never $HOME.
func doctorCheckablePath(v string) (path string, ok bool) {
	if v == "" || strings.EqualFold(v, "none") || strings.ContainsAny(v, "%$") {
		return "", false
	}
	switch {
	case v == "~" || strings.HasPrefix(v, "~/"):
		home := config.HomeDir()
		if home == "" {
			return "", false
		}
		return home + v[1:], true
	case strings.HasPrefix(v, "/"):
		return v, true
	}
	return "", false
}

// doctorFileChecks runs D7-D13 and returns the findings in table order.
func doctorFileChecks(l *config.Loaded, managed string) []domain.Issue {
	var missingID, missingCert, unsafeKey, expired []domain.Issue
	inspected := map[string]*domain.Certificate{} // nil: unreadable certificate

	// Evaluation order of the files, then the order of the blocks in the file.
	for _, f := range l.Files {
		for _, h := range l.Hosts {
			if h.SourceFile != f.Path || h.Disabled {
				continue
			}
			at := func(sev domain.Severity, rule, msg string) domain.Issue {
				return domain.Issue{HostName: h.Name, Severity: sev, Rule: rule, Message: msg,
					Line: h.LineStart, File: issueFile(l, f.Path)}
			}

			seen := map[string]bool{} // D13: one finding per (block, path)
			for _, v := range h.IdentityFileList() {
				p, ok := doctorCheckablePath(v)
				if !ok || seen[p] {
					continue
				}
				seen[p] = true
				fi, err := os.Stat(p)
				switch {
				case errors.Is(err, fs.ErrNotExist):
					missingID = append(missingID, at(domain.SeverityError, RuleMissingIdentityFile,
						fmt.Sprintf("IdentityFile %s does not exist", v)))
				case err != nil:
					// Unreadable for another reason: not doctor's finding.
				case fi.Mode().IsRegular() && !strings.HasSuffix(p, ".pub") && fi.Mode().Perm()&0o077 != 0 && keyOwnerRefused(fi):
					unsafeKey = append(unsafeKey, at(domain.SeverityError, RuleUnsafePermissions,
						fmt.Sprintf("IdentityFile %s has mode %04o: readable or writable by group/other, ssh refuses such a key (chmod 600 %s)",
							v, fi.Mode().Perm(), v)))
				}
			}

			seen = map[string]bool{}
			for _, v := range h.CertificateFileList() {
				p, ok := doctorCheckablePath(v)
				if !ok || seen[p] {
					continue
				}
				seen[p] = true
				fi, err := os.Stat(p)
				switch {
				case errors.Is(err, fs.ErrNotExist):
					missingCert = append(missingCert, at(domain.SeverityWarning, RuleMissingCertFile,
						fmt.Sprintf("CertificateFile %s does not exist", v)))
				case err != nil || !fi.Mode().IsRegular():
				default:
					cert, done := inspected[p]
					if !done {
						// A missing ssh-keygen or an unparsable certificate
						// gives no finding (D12).
						if c, err := (&App{}).InspectCert(p); err == nil {
							cert = &c
						}
						inspected[p] = cert
					}
					if cert != nil && cert.IsExpired() {
						expired = append(expired, at(domain.SeverityWarning, RuleCertExpired,
							fmt.Sprintf("CertificateFile %s expired on %s", v, cert.Expires())))
					}
				}
			}
		}
	}

	out := append(missingID, missingCert...)
	out = append(out, unsafeKey...)
	perms, managedIssues := doctorConfigPermissions(l, managed)
	out = append(out, perms...)
	out = append(out, managedIssues...)
	return append(out, expired...)
}

// keyOwnerRefused reports whether ssh would refuse the loosely-moded private
// key fi: authfile.c sshkey_perm_ok refuses it only when the current user owns
// it. When the owner is unknown the key is judged by its mode alone (true).
func keyOwnerRefused(fi os.FileInfo) bool {
	uid, ok := ownerOf(fi)
	return !ok || uid == currentUID()
}

// doctorConfigPermissions runs D10 over every config file read (the managed
// file included) and D11 for the managed file. A managed file that no Include
// reaches is still looked at, directly.
func doctorConfigPermissions(l *config.Loaded, managed string) (d10, d11 []domain.Issue) {
	paths := make([]string, 0, len(l.Files)+1)
	for _, f := range l.Files {
		paths = append(paths, f.Path)
	}
	if _, ok := l.Lookup(managed); !ok {
		paths = append(paths, managed)
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		mode := fi.Mode().Perm()
		isManaged := samePath(p, managed)
		// readconf.c: a file whose owner is neither root nor the current user
		// is refused ("Bad owner or permissions"). Without an owner (ok false)
		// only the mode is judged.
		ownerUID, ownerKnown := ownerOf(fi)
		badOwner := ownerKnown && ownerUID != 0 && ownerUID != currentUID()
		ownerMsg := fmt.Sprintf("owned by uid %d: ssh accepts only root (uid 0) or the current user (uid %d) as owner", ownerUID, currentUID())
		switch {
		case mode&0o022 != 0:
			msg := fmt.Sprintf("config file %s has mode %04o: writable by group/other, ssh may refuse it (chmod 600 %s)", p, mode, p)
			if badOwner {
				msg += "; also " + ownerMsg
			}
			d10 = append(d10, domain.Issue{
				Severity: domain.SeverityError, Rule: RuleUnsafePermissions, File: issueFile(l, p), Message: msg,
			})
		case badOwner:
			d10 = append(d10, domain.Issue{
				Severity: domain.SeverityError, Rule: RuleUnsafePermissions, File: issueFile(l, p),
				Message: fmt.Sprintf("config file %s is %s", p, ownerMsg),
			})
		case isManaged && mode&0o044 != 0:
			d11 = append(d11, domain.Issue{
				Severity: domain.SeverityWarning, Rule: RuleManagedPermissions, File: issueFile(l, p),
				Message: fmt.Sprintf("managed file %s has mode %04o: readable by group/other; sshm creates it 0600 (chmod 600 %s)", p, mode, p),
			})
		}
	}
	return d10, d11
}

// ---- include / setup checks (D14-D17) -------------------------------------------------------

func doctorIncludeChecks(l *config.Loaded, managed string) []domain.Issue {
	var out []domain.Issue

	switch state, where := managedIncludeState(l, managed); state {
	case includeNone: // D14
		out = append(out, domain.Issue{Severity: domain.SeverityInfo, Rule: RuleNotSetUp,
			Message: "sshm-managed file is not included; run 'sshm setup'"})
	case includeConditional: // D15
		out = append(out, domain.Issue{Severity: domain.SeverityWarning, Rule: RuleIncludeConditional,
			Message: fmt.Sprintf("sshm-managed file is included only conditionally (%s): ssh reads it only for matching hosts", where)})
	}

	// D16: every other Include that ssh reads only for matching hosts. The
	// managed Include is D15's.
	for _, f := range l.Files {
		for _, inc := range f.Cfg.Includes {
			if !inc.Conditional && !f.Conditional {
				continue
			}
			for _, pat := range inc.Patterns {
				if includeReaches(pat, managed) {
					continue
				}
				out = append(out, domain.Issue{Severity: domain.SeverityWarning, Rule: RuleIncludeConditional,
					Message: fmt.Sprintf("Include %s is read only for matching hosts", pat),
					Line:    inc.Line, File: issueFile(l, f.Path)})
			}
		}
	}

	// D17
	if env, pw := os.Getenv("HOME"), config.HomeDir(); env != "" && pw != "" && !sameDir(env, pw) {
		out = append(out, domain.Issue{Severity: domain.SeverityWarning, Rule: RuleHomeMismatch,
			Message: fmt.Sprintf("$HOME (%s) differs from the passwd home (%s); ssh ignores $HOME and expands ~ to the passwd home", env, pw)})
	}
	return out
}

// includeReaches reports whether the Include pattern names the managed file,
// literally or through a glob.
func includeReaches(pattern, managed string) bool {
	if p, ok := config.IncludeTarget(pattern); ok && samePath(p, managed) {
		return true
	}
	paths, _ := config.ExpandInclude(pattern)
	for _, p := range paths {
		if samePath(p, managed) {
			return true
		}
	}
	return false
}

// sameDir compares two directory paths after cleaning and symlink resolution;
// a path that does not exist is compared in its cleaned form.
func sameDir(a, b string) bool {
	norm := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		return filepath.Clean(p)
	}
	return norm(a) == norm(b)
}

// ---- ssh checks (D18-D23) -------------------------------------------------------------------

func (a *App) doctorSSHChecks(l *config.Loaded) []domain.Issue {
	if _, err := exec.LookPath("ssh"); err != nil { // D18
		return []domain.Issue{{Severity: domain.SeverityInfo, Rule: RuleSSHMissing,
			Message: "ssh not found; ssh-based checks skipped"}}
	}
	// D19: `ssh -G` runs the command of a `Match exec` line, so no probe.
	if f := execMatchFile(l, nil, ""); f != "" {
		return []domain.Issue{{Severity: domain.SeverityInfo, Rule: RuleVerifySkipped,
			Message: fmt.Sprintf("%s has a 'Match ... exec' line: sshm cannot verify saves with ssh -G, and doctor did not run ssh", f)}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), sshTimeout)
	defer cancel()
	stdout, stderr, err := sshRun(ctx, "-F", a.configPath, "-G", "--", doctorProbeHost)
	if err != nil { // D20
		msg := err.Error()
		for _, line := range strings.Split(string(stderr), "\n") {
			if s := strings.TrimSpace(line); s != "" {
				msg = s
				break
			}
		}
		return []domain.Issue{{Severity: domain.SeverityError, Rule: RuleSSHRejectsConfig, Message: msg}}
	}

	// D21-D23: what an otherwise unmatched host gets.
	eff := optionValues(string(stdout))
	first := func(key string) string {
		if v := eff[key]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	var out []domain.Issue
	if first("hashknownhosts") != "yes" {
		out = append(out, domain.Issue{Severity: domain.SeverityInfo, Rule: RuleHardeningHashKnownHosts,
			Message: "HashKnownHosts is not 'yes' for hosts without their own setting; consider 'HashKnownHosts yes' under 'Host *'"})
	}
	if first("identitiesonly") != "yes" {
		out = append(out, domain.Issue{Severity: domain.SeverityInfo, Rule: RuleHardeningIdentitiesOnly,
			Message: "IdentitiesOnly is not 'yes' for hosts without their own setting; consider 'IdentitiesOnly yes' under 'Host *'"})
	}
	if first("forwardagent") == "yes" {
		out = append(out, domain.Issue{Severity: domain.SeverityWarning, Rule: RuleAgentForwardingDefault,
			Message: "ForwardAgent is 'yes' for every host (it comes from 'Host *' or an earlier match); enable it only for the hosts that need it"})
	}
	return out
}
