package cli

import (
	"fmt"
	"os"

	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/spf13/cobra"
)

// printSetupResult prints the setup actions and the notes of res to stderr, in
// the wording of `sshm setup` (prefix "would " for a dry run).
func printSetupResult(res app.SetupResult, prefix string) {
	for _, act := range res.Actions {
		fmt.Fprintln(os.Stderr, prefix+act)
	}
	for _, n := range res.Notes {
		fmt.Fprintln(os.Stderr, "note: "+n)
	}
}

func newSetupCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up the sshm-managed config file",
		Long: `Create config.d/sshm.conf next to your ssh config and include it from the
first line of the ssh config. Running it again changes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			res, err := a.Setup(app.SetupOptions{DryRun: dryRun})
			if err != nil {
				return err
			}
			if res.AlreadySetUp {
				fmt.Fprintf(os.Stderr, "already set up: %s is included from %s\n", a.ManagedPath(), a.ConfigPath())
				return nil
			}
			prefix := ""
			if dryRun {
				prefix = "would "
			}
			printSetupResult(res, prefix)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be done without changing anything")
	return cmd
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func newImportCmd() *cobra.Command {
	var apply, force bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Move hosts from the ssh config into the sshm-managed file",
		Long: `Plan the move of plain Host blocks from your ssh config into the
sshm-managed file. Nothing is changed unless --apply is given.

With --apply, ssh -G is run for every host before and after; if any host
would resolve differently both files are restored and the differences are
printed. --force keeps the move anyway (and also moves when ssh cannot be
used for the check).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			res, err := a.Import(app.ImportOptions{Apply: apply, Force: force})
			// The differences are printed even when the import failed on them.
			for _, d := range res.Diff {
				fmt.Fprintln(os.Stderr, "  "+d)
			}
			if err != nil {
				return err
			}
			for _, n := range res.Notes {
				fmt.Fprintln(os.Stderr, "note: "+n)
			}
			if len(res.Move) == 0 {
				fmt.Println("nothing to import")
				return nil
			}
			if !apply {
				printImportPlan(a, res)
				fmt.Println("run 'sshm import --apply' to perform the move")
				return nil
			}
			blocks := plural(len(res.Move), "block", "blocks")
			switch {
			case res.Checked && res.Equivalent:
				fmt.Printf("moved %s; ssh resolves every host identically\n", blocks)
			case res.Checked:
				fmt.Printf("moved %s; ssh resolves some hosts differently (--force)\n", blocks)
			default:
				fmt.Printf("moved %s; ssh equivalence was not checked\n", blocks)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&apply, "apply", false, "perform the move")
	cmd.Flags().BoolVar(&force, "force", false, "keep the move even if ssh would resolve a host differently or cannot be checked")
	return cmd
}

// printImportPlan prints the dry-run plan (PLAN-p3-p4.md section 5).
func printImportPlan(a *app.App, res app.ImportResult) {
	fmt.Printf("would move %s from %s to %s:\n", plural(len(res.Move), "block", "blocks"), a.ConfigPath(), a.ManagedPath())
	w := 0
	for _, b := range res.Move {
		w = max(w, len(b.Name))
	}
	for _, s := range res.Stay {
		w = max(w, len(s.Name))
	}
	for _, b := range res.Move {
		extra := ""
		switch {
		case b.Disabled && b.Group != "":
			extra = fmt.Sprintf("   (disabled, group %s)", b.Group)
		case b.Disabled:
			extra = "   (disabled)"
		}
		fmt.Printf("  %-*s  lines %d-%d%s\n", w, b.Name, b.FromLine, b.ToLine, extra)
	}
	var inMain, included []app.ImportStay
	for _, s := range res.Stay {
		if s.File == a.ConfigPath() {
			inMain = append(inMain, s)
		} else {
			included = append(included, s)
		}
	}
	if len(inMain) > 0 {
		fmt.Printf("staying in %s:\n", a.ConfigPath())
		for _, s := range inMain {
			fmt.Printf("  %-*s  line %d  %s\n", w, s.Name, s.Line, s.Reason)
		}
	}
	if len(included) > 0 {
		fmt.Println("staying in included files:")
		for _, s := range included {
			fmt.Printf("  %-*s  line %d of %s  %s\n", w, s.Name, s.Line, s.File, s.Reason)
		}
	}
}
