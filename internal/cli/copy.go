package cli

import (
	"github.com/spf13/cobra"
)

func newCopyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "copy <source> <destination>",
		Short: "Copy files via rsync between local and remote",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, dst := args[0], args[1]

			flags, _ := cmd.Flags().GetString("flags")
			if flags == "" {
				flags = "-avzP"
			}

			a := newApp()
			if err := a.Copy(src, dst, flags); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().String("flags", "", "rsync flags (defaults to -avzP)")

	return cmd
}
