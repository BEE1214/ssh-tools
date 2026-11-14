package cli

import (
	"fmt"
	"os"

	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/spf13/cobra"
)

// NewRootCmd creates the root cobra command.
//   - No args: launches the TUI (requires a terminal on stdin and stdout).
//   - One arg that matches a host name: connects via ssh.
//   - More args: connects, forwarding everything after the host verbatim to ssh.
//   - Subcommands: list, search, add, edit, copy, dump, validate, groups, init, version.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sshm",
		Short: "SSH config manager",
		Long: `Manage ~/.ssh/config hosts with a TUI and CLI.

Anything after the host name is passed to ssh verbatim:

  sshm zf-poland1 -L 10100:192.168.1.100:80

ssh accepts options after the destination, so this works like calling
ssh directly. Add -N yourself for no-shell tunnels.`,
		Version:           version,
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: hostCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			// No args -> TUI.
			if len(args) == 0 {
				return runTUI(cmd)
			}
			// One arg -> connect.
			if len(args) == 1 {
				return runConnect(cmd, args[0], nil)
			}
			// More args -> connect, passing the rest to ssh verbatim.
			return runConnect(cmd, args[0], args[1:])
		},
		SilenceUsage: true,
	}
	root.Flags().SetInterspersed(false)

	root.AddCommand(
		newListCmd(),
		newConnectCmd(),
		newCopyCmd(),
		newSearchCmd(),
		newAddCmd(),
		newEditCmd(),
		newDumpCmd(),
		newValidateCmd(),
		newGroupsCmd(),
		newInitCmd(),
		newCertCmd(),
		newForwardCmd(),
		newVersionCmd(),
	)

	return root
}

// Execute creates the root command and runs it.
func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newApp creates an App instance, printing an error and exiting on failure.
func newApp() *app.App {
	a, err := app.NewApp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	return a
}