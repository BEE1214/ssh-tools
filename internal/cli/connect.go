package cli

import (
	"github.com/spf13/cobra"
)

func newConnectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "connect <hostname> [ssh-args...]",
		Short:             "Connect to a host via ssh",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: hostCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(cmd, args[0], args[1:])
		},
	}
	cmd.Flags().SetInterspersed(false)
	return cmd
}

// runConnect is shared by the root command (sshm <host> [ssh-args...]) and
// the connect subcommand (sshm connect <host> [ssh-args...]). extraArgs is
// passed through to ssh verbatim, after the destination.
func runConnect(cmd *cobra.Command, name string, extraArgs []string) error {
	a := newApp()
	return a.Connect(name, extraArgs)
}