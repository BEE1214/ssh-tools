package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/spf13/cobra"
)

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage short-lived SSH certificates",
		Long:  "Create and inspect short-lived SSH certificates signed by a private CA.",
	}

	cmd.AddCommand(
		newCertInitCmd(),
		newCertSignCmd(),
		newCertListCmd(),
		newCertInspectCmd(),
		newCertRevokeCmd(),
	)

	return cmd
}

func newCertInitCmd() *cobra.Command {
	var caKey string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a new CA key pair",
		Long:  "Creates an Ed25519 CA key pair and stores its path for future signing operations. The CA key should be kept offline and never shared.",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			if err := a.InitCA(caKey); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "CA key created and path stored.\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&caKey, "ca-key", "", "path for the CA key (default: ~/.ssh/sshm-ca)")

	return cmd
}

func newCertSignCmd() *cobra.Command {
	var identity, principals, validity, caKey, pubKeyPath string

	cmd := &cobra.Command{
		Use:   "sign [hostname]",
		Short: "Sign a public key with the CA to create a certificate",
		Long: `Sign a public key with the CA, producing a short-lived certificate.

If a hostname from ssh config is given, uses its IdentityFile and User.
Otherwise, use --pubkey to specify a .pub file directly.

Examples:
  sshm cert sign host-acq-dev --validity +4h
  sshm cert sign --pubkey ~/.ssh/id_ed25519.pub --identity my-key --principal root --validity +12h`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := app.SignOpts{
				Identity:   identity,
				Principals: principals,
				Validity:   validity,
				CAKey:      caKey,
				PubKeyPath: pubKeyPath,
			}
			if len(args) > 0 {
				opts.HostName = args[0]
			}

			a := newApp()
			certPath, err := a.SignCert(opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Certificate created: %s\n", certPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&identity, "identity", "", "key ID for the certificate (-I)")
	cmd.Flags().StringVar(&principals, "principal", "", "comma-separated principals (-n, default: host's User)")
	cmd.Flags().StringVar(&validity, "validity", "", "validity period (-V, default: +12h)")
	cmd.Flags().StringVar(&caKey, "ca-key", "", "CA key path (default: read from ~/.ssh/sshm-ca.conf)")
	cmd.Flags().StringVar(&pubKeyPath, "pubkey", "", "direct path to a .pub file (alternative to hostname)")

	return cmd
}

func newCertListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all certificates in ~/.ssh/",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			certs, err := a.ListCerts()
			if err != nil {
				return err
			}

			if len(certs) == 0 {
				fmt.Println("No certificates found in ~/.ssh/.")
				return nil
			}

			fmt.Printf("%-30s %-15s %-20s %-25s %s\n", "IDENTITY", "SERIAL", "PRINCIPALS", "EXPIRES", "PATH")
			for _, c := range certs {
				expiry := c.Expires()
				if c.IsExpired() {
					expiry = "EXPIRED " + expiry
				}
				principals := "-"
				if len(c.Principals) > 0 {
					principals = fmt.Sprintf("%d", len(c.Principals))
				}
				fmt.Printf("%-30s %-15d %-20s %-25s %s\n",
					truncate(c.Identity, 30),
					c.Serial,
					principals,
					expiry,
					c.Path,
				)
			}
			return nil
		},
	}

	return cmd
}

func newCertInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <cert.pub>",
		Short: "Show full certificate details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			cert, err := a.InspectCert(args[0])
			if err != nil {
				return err
			}

			fmt.Printf("Path:           %s\n", cert.Path)
			fmt.Printf("Identity:       %s\n", cert.Identity)
			fmt.Printf("Serial:         %d\n", cert.Serial)
			fmt.Printf("Type:           %s\n", cert.KeyType)
			fmt.Printf("Public key:     %s\n", cert.PubKeyFingerprint)
			fmt.Printf("Signing CA:     %s\n", cert.CAKey)
			fmt.Printf("Validity:       %s\n", cert.Validity())
			if cert.IsExpired() {
				fmt.Printf("Status:         EXPIRED\n")
			} else if cert.NeverExpires() {
				fmt.Printf("Status:         valid (never expires)\n")
			} else {
				remaining := time.Until(cert.ValidBefore).Round(time.Minute)
				fmt.Printf("Status:         valid (expires in %s)\n", remaining)
			}
			if len(cert.Principals) > 0 {
				fmt.Printf("Principals:\n")
				for _, p := range cert.Principals {
					fmt.Printf("  %s\n", p)
				}
			} else {
				fmt.Printf("Principals:     (none)\n")
			}

			return nil
		},
	}

	return cmd
}

func newCertRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <cert.pub>",
		Short: "Remove a certificate (soft revocation)",
		Long: `Deletes the certificate file and removes the CertificateFile line
from the matching ssh config host. This is soft revocation — OpenSSH has
no CRL, so the cert may still be accepted by servers until their
authorized_keys or CA trust is updated.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			if err := a.RevokeCert(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Certificate revoked: %s\n", args[0])
			return nil
		},
	}

	return cmd
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
