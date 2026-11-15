package cli

import (
	"fmt"
	"os"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
	"github.com/spf13/cobra"
)

func newSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search <pattern>",
		Short: "Search hosts by name or hostname",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			hosts, err := a.ListHosts("", false)
			if err != nil {
				return err
			}

			pattern := args[0]
			for _, h := range hosts {
				if contains(h.Name, pattern) || contains(h.HostName, pattern) {
					fmt.Printf("%s\t%s@%s:%s\n", h.Name, h.DisplayUser(), h.DisplayHost(), h.CanonicalPort())
				}
			}
			return nil
		},
	}
	return cmd
}

func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func newAddCmd() *cobra.Command {
	var name, hostname, user, port, identity, proxyJump string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new host to config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			h := domain.Host{
				Name:         name,
				HostName:     hostname,
				User:         user,
				Port:         port,
				IdentityFile: defaultIdentity(identity),
				ProxyJump:    proxyJump,
			}

			a := newApp()
			if err := a.AddHost(h); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Added host %s\n", name)
			printHint(a)
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "host name (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "hostname or IP")
	cmd.Flags().StringVar(&user, "user", "", "ssh user")
	cmd.Flags().StringVar(&port, "port", "", "ssh port (default 22)")
	cmd.Flags().StringVar(&identity, "identity", "", "identity file path (defaults to "+domain.DefaultIdentityFile+")")
	cmd.Flags().StringVar(&proxyJump, "proxyjump", "", "proxy jump host")
	cmd.MarkFlagRequired("name")

	registerHostFlagCompletion(cmd, "proxyjump")

	return cmd
}

// defaultIdentity returns the given identity if non-empty, otherwise the
// default identity key.
func defaultIdentity(id string) string {
	if id != "" {
		return id
	}
	return domain.DefaultIdentityFile
}
