package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X cli.version=...".
// Defaults to "dev" when not overridden (e.g. go run, go build without ldflags).
var version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the sshm version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
}
