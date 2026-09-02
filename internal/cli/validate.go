package cli

import (
	"fmt"
	"os"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var strict bool
	var skipFiles bool

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Lint config: integrity, file references, permissions, cert expiry",
		Long: `Check the SSH config for issues:

  error    — config or ssh would misbehave (duplicate host, bad port,
             unsafe key permissions, missing key file)
  warning  — works, but risky or suspicious (StrictHostKeyChecking no,
             missing identity, expired certificate)
  info     — cosmetic (mixed-case keys)

Exit codes: 0 clean, 1 errors found (or warnings with --strict).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()

			var issues []domain.Issue
			var err error
			if skipFiles {
				issues, err = a.Validate()
			} else {
				issues, err = a.Lint()
			}
			if err != nil {
				return err
			}

			if len(issues) == 0 {
				fmt.Println("No issues found.")
				return nil
			}

			errorCount, warnCount := 0, 0
			for _, i := range issues {
				location := ""
				if i.Line > 0 {
					location = fmt.Sprintf(" (line %d)", i.Line)
				}
				if i.HostName != "" {
					fmt.Fprintf(os.Stderr, "%s [%s] %s: %s%s\n", i.Severity, i.Rule, i.HostName, i.Message, location)
				} else {
					fmt.Fprintf(os.Stderr, "%s [%s] %s%s\n", i.Severity, i.Rule, i.Message, location)
				}
				switch i.Severity {
				case domain.SeverityError:
					errorCount++
				case domain.SeverityWarning:
					warnCount++
				}
			}

			fmt.Fprintf(os.Stderr, "\n%d error(s), %d warning(s) found.\n", errorCount, warnCount)

			if errorCount > 0 || (strict && warnCount > 0) {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "exit 1 on warnings too (for CI)")
	cmd.Flags().BoolVar(&skipFiles, "skip-files", false, "only check config syntax, skip file existence/permission checks")

	return cmd
}

func newGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "List detected groups and host counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			groups, err := a.ListGroups()
			if err != nil {
				return err
			}

			names := domain.GroupNames(groups)
			for _, name := range names {
				fmt.Printf("%s (%d)\n", name, len(groups[name]))
			}
			return nil
		},
	}
	return cmd
}

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate or repair the Host * defaults block",
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			if err := a.InitDefaults(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Host * defaults block written to %s\n", a.ConfigPath())
			return nil
		},
	}
	return cmd
}
