package cli

import (
	"fmt"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
	"github.com/spf13/cobra"
)

func newForwardCmd() *cobra.Command {
	var remote, dynamic, save, list, clear bool

	cmd := &cobra.Command{
		Use:   "forward <host> <spec> [spec...]",
		Short: "Port-forward through a host",
		Long: `Run ssh port forwarding to a host (-N, no shell).

  sshm forward <host> <spec>...            local forwards (-L)
  sshm forward --remote <host> <spec>...   remote forwards (-R)
  sshm forward --dynamic <host> <spec>...  dynamic/SOCKS forward (-D)
  sshm forward --save <host> <spec>...     persist to the config AND run
  sshm forward --list <host>               print saved forwards (no ssh)
  sshm forward --clear <host>              remove saved forwards (no ssh)

Spec syntax: listenPort:targetHost:targetPort (local/remote), with an
optional bind address (addr:listenPort:targetHost:targetPort); dynamic
specs are just listenPort (or addr:listenPort). IPv6 bracket addresses
are not supported.`,
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: hostCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			specs := args[1:]
			a := newApp()

			if list {
				h, err := a.ListForwards(host)
				if err != nil {
					return err
				}
				printForwards(h)
				return nil
			}

			if clear {
				if err := a.ClearForwards(host); err != nil {
					return err
				}
				fmt.Printf("Cleared forwards for host %s\n", host)
				printHint(a)
				return nil
			}

			if remote && dynamic {
				return fmt.Errorf("--remote and --dynamic are mutually exclusive")
			}
			if len(specs) == 0 {
				return fmt.Errorf("at least one forward spec is required")
			}

			kind := domain.ForwardLocal
			switch {
			case remote:
				kind = domain.ForwardRemote
			case dynamic:
				kind = domain.ForwardDynamic
			}

			// ssh replaces this process after a successful --save, so the setup
			// hint (R14) is printed between the save and the exec.
			return a.RunForwardNotify(host, kind, specs, save, func() { printHint(a) })
		},
	}

	cmd.Flags().BoolVar(&remote, "remote", false, "use -R remote forwarding instead of -L")
	cmd.Flags().BoolVar(&dynamic, "dynamic", false, "use -D dynamic/SOCKS forwarding instead of -L")
	cmd.Flags().BoolVar(&save, "save", false, "persist the forwards to the host's config block, then run")
	cmd.Flags().BoolVar(&list, "list", false, "print the host's saved forwards from config (no ssh)")
	cmd.Flags().BoolVar(&clear, "clear", false, "remove all saved forwards from the host's config block (no ssh)")

	return cmd
}

// printForwards prints a host's saved forward entries in config syntax.
func printForwards(h domain.Host) {
	for _, f := range h.LocalForwards {
		fmt.Printf("LocalForward %s\n", f)
	}
	for _, f := range h.RemoteForwards {
		fmt.Printf("RemoteForward %s\n", f)
	}
	for _, f := range h.DynamicForwards {
		fmt.Printf("DynamicForward %s\n", f)
	}
}
