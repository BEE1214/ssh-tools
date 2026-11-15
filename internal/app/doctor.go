package app

import "github.com/adamdvorsky/ssh-tools/internal/domain"

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
func (a *App) Doctor(opts DoctorOptions) ([]domain.Issue, error) {
	return nil, ErrNotImplemented
}
