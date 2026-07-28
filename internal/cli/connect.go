package cli

import (
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect <hostname>",
		Short: "Connect to a host via ssh",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(cmd, args[0])
		},
	}
	return cmd
}

// runConnect is shared by the root command (sshm <host>) and
// the connect subcommand (sshm connect <host>).
func runConnect(cmd *cobra.Command, name string) error {
	a := newApp()
	return a.Connect(name)
}