package cli

import (
	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/spf13/cobra"
)

func newSetupCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up the sshm-managed config file",
		Long: `Create config.d/sshm.conf next to your ssh config and include it from the
first line of the ssh config. Running it again changes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.ErrNotImplemented
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be done without changing anything")
	return cmd
}

func newImportCmd() *cobra.Command {
	var apply, force bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Move hosts from the ssh config into the sshm-managed file",
		Long: `Plan the move of plain Host blocks from your ssh config into the
sshm-managed file. Nothing is changed unless --apply is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.ErrNotImplemented
		},
	}
	cmd.Flags().BoolVar(&apply, "apply", false, "perform the move")
	cmd.Flags().BoolVar(&force, "force", false, "keep the move even if ssh would resolve a host differently or cannot be checked")
	return cmd
}
