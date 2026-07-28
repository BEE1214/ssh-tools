package cli

import (
	"fmt"
	"os"

	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/spf13/cobra"
)

// NewRootCmd creates the root cobra command.
//   - No args: launches TUI (future).
//   - One arg that matches a host name: connects via ssh.
//   - Subcommands: list, search, add, edit, dump, validate, groups, init.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sshm",
		Short: "SSH config manager",
		Long:  "Manage ~/.ssh/config hosts with a TUI and CLI.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// No args -> TUI (not yet implemented).
			if len(args) == 0 {
				return fmt.Errorf("TUI not yet implemented — use 'sshm list' to see hosts")
			}
			// One arg -> connect.
			if len(args) == 1 {
				return runConnect(cmd, args[0])
			}
			return cmd.Help()
		},
		SilenceUsage: true,
	}

	root.AddCommand(
		newListCmd(),
		newConnectCmd(),
		newSearchCmd(),
		newAddCmd(),
		newEditCmd(),
		newDumpCmd(),
		newValidateCmd(),
		newGroupsCmd(),
		newInitCmd(),
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