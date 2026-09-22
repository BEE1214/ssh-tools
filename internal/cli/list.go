package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	var flat bool
	var group string
	var all bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all hosts",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			hosts, err := a.ListHosts(group, all)
			if err != nil {
				return err
			}

			if flat {
				for _, h := range hosts {
					if h.Disabled {
						fmt.Printf("%s [disabled]\n", h.Name)
					} else {
						fmt.Println(h.Name)
					}
				}
				return nil
			}

			printHosts(hosts)
			return nil
		},
	}

	cmd.Flags().BoolVar(&flat, "flat", false, "flat list (one host per line, for scripting/fzf)")
	cmd.Flags().StringVar(&group, "group", "", "filter by group name")
	cmd.Flags().BoolVar(&all, "all", false, "include disabled hosts (marked [disabled])")

	return cmd
}

// printHosts prints hosts in a table grouped by group name.
func printHosts(hosts []domain.Host) {
	groups := domain.GroupHosts(hosts)
	names := domain.GroupNames(groups)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	for _, name := range names {
		fmt.Fprintf(w, "%s (%d):\n", name, len(groups[name]))
		for _, h := range groups[name] {
			port := h.CanonicalPort()
			id := "-"
			if h.HasIdentityFile() {
				id = h.IdentityFile
			}
			hostname := h.DisplayHost()
			user := h.DisplayUser()
			mark := ""
			if h.Disabled {
				mark = " [disabled]"
			}

			fmt.Fprintf(w, "  %s%s	%s@%s:%s	%s\n", h.Name, mark, user, hostname, port, id)
		}
		fmt.Fprintln(w)
	}

	w.Flush()
}