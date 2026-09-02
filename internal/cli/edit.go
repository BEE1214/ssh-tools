package cli

import (
	"fmt"

	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/spf13/cobra"
)

func newEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "edit <hostname>",
		Short:             "Edit a host's options (via flags)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: hostCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			changes := make(map[string]string)
			flags := []string{"hostname", "user", "port", "identity", "certificate", "proxyjump", "proxycommand", "forwardagent", "forwardx11", "stricthostkeychecking", "loglevel"}
			for _, f := range flags {
				if cmd.Flags().Changed(f) {
					val, _ := cmd.Flags().GetString(f)
					if f == "identity" {
						f = "identityfile"
					}
					if f == "certificate" {
						f = "certificatefile"
					}
					changes[f] = val
				}
			}

			if len(changes) == 0 {
				return fmt.Errorf("no changes specified — use flags to set fields (e.g. --user root)")
			}

			a := newApp()
			if err := a.EditHost(name, changes); err != nil {
				return err
			}
			fmt.Printf("Updated host %s\n", name)
			return nil
		},
	}

	cmd.Flags().String("hostname", "", "hostname or IP")
	cmd.Flags().String("user", "", "ssh user")
	cmd.Flags().String("port", "", "ssh port")
	cmd.Flags().String("identity", "", "identity file path")
	cmd.Flags().String("certificate", "", "certificate file path")
	cmd.Flags().String("proxyjump", "", "proxy jump host")
	cmd.Flags().String("proxycommand", "", "proxy command")
	cmd.Flags().String("forwardagent", "", "forward agent (yes/no)")
	cmd.Flags().String("forwardx11", "", "forward X11 (yes/no)")
	cmd.Flags().String("stricthostkeychecking", "", "strict host key checking (yes/no/accept-new)")
	cmd.Flags().String("loglevel", "", "log level")

	registerHostFlagCompletion(cmd, "proxyjump")

	return cmd
}

func newDumpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "dump <hostname>",
		Short:             "Show effective config for a host (like ssh -G)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: hostCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			h, err := a.Dump(args[0])
			if err != nil {
				return err
			}
			fmt.Print(app.FormatHost(h))
			return nil
		},
	}
	return cmd
}