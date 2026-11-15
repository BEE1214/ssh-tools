package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/adamdvorsky/ssh-tools/internal/app"
	"github.com/adamdvorsky/ssh-tools/internal/domain"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	var strict, skipFiles bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check config, files and ssh for problems (report only)",
		Long: `Run every 'validate' rule plus checks of the files the config points to
(identity files, certificates, permissions), the sshm setup, and what ssh
itself makes of the config. Nothing is changed.

Exits 1 when errors are found, or warnings with --strict.`,
		Args: cobra.NoArgs,
		// The failure summary is printed by reportDoctor; cobra must not print
		// the returned error a second time.
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			a := newApp()
			issues, err := a.Doctor(app.DoctorOptions{SkipFiles: skipFiles})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return err
			}
			return reportDoctor(issues, strict)
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "exit 1 on warnings too")
	cmd.Flags().BoolVar(&skipFiles, "skip-files", false, "do not check files referenced by the config")
	return cmd
}

// reportDoctor prints the issues (D3) and returns a non-nil error carrying the
// summary line when the run fails (D4). The summary has already been printed
// when it returns.
func reportDoctor(issues []domain.Issue, strict bool) error {
	if len(issues) == 0 {
		fmt.Println("No issues found.")
		return nil
	}
	errs, warns := 0, 0
	for _, i := range issues {
		fmt.Fprintln(os.Stderr, formatIssue(i))
		switch i.Severity {
		case domain.SeverityError:
			errs++
		case domain.SeverityWarning:
			warns++
		}
	}
	summary := fmt.Sprintf("%d error(s), %d warning(s) found.", errs, warns)
	fmt.Fprintln(os.Stderr, summary)
	if errs > 0 || (strict && warns > 0) {
		return errors.New(summary)
	}
	return nil
}
