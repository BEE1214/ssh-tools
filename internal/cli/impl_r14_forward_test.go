package cli

// R14 for `forward --save`: RunForward ends in syscall.Exec of ssh, so the
// command cannot run inside the test process. The parent test re-executes the
// test binary as a helper (TestHelperForwardSave) with a FAKE ssh first in PATH.
// The fake delegates `-G` calls (sshm's verification probes) to the real ssh
// and, for the final exec, prints a marker on stdout and exits 0.
//
// Nothing here touches the real ~/.ssh: the helper gets a temp config through
// SSH_AUTH_CONFIG, a temp passwd home, and the fixtures use absolute Includes.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/adamdvorsky/ssh-tools/internal/config"
)

const fakeSSHMarker = "FAKE-SSH-EXEC"

// TestHelperForwardSave is the subprocess body; it does nothing in a normal run.
func TestHelperForwardSave(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_FORWARD") != "1" {
		return
	}
	config.SetHomeDirForTest(os.Getenv("GO_HELPER_HOME"))
	root := NewRootCmd()
	root.SetArgs([]string{"forward", os.Getenv("GO_HELPER_HOST"), "8000:localhost:80", "--save"})
	if err := root.Execute(); err != nil {
		os.Stderr.WriteString("helper: forward failed: " + err.Error() + "\n")
		os.Exit(1)
	}
	// RunForward must have replaced the process with ssh.
	os.Stderr.WriteString("helper: forward returned instead of exec'ing ssh\n")
	os.Exit(5)
}

type forwardRun struct {
	stdout, stderr string
	err            error
}

// runForwardSave runs `sshm forward <host> 8000:localhost:80 --save` in a
// helper process against the config at mainPath.
func runForwardSave(t *testing.T, realSSH, mainPath, host string) forwardRun {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"-G\" ]; then exec " + realSSH + " \"$@\"; fi\n" +
		"done\n" +
		"echo \"" + fakeSSHMarker + " $*\"\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperForwardSave$", "-test.count=1")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_FORWARD=1",
		"GO_HELPER_HOST="+host,
		"GO_HELPER_HOME="+t.TempDir(),
		"SSH_AUTH_CONFIG="+mainPath,
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return forwardRun{stdout: out.String(), stderr: errb.String(), err: err}
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

var localForward8000 = regexp.MustCompile(`(?m)^\s*LocalForward\s+8000\s+localhost:80\s*$`)

func TestImplR14_ForwardSave_ManagedModePrintsNoHintAndSavesToTheManagedFile(t *testing.T) {
	t.Parallel()
	realSSH, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not in PATH")
	}
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "config")
	managed := filepath.Join(dir, "config.d", "sshm.conf")
	mainBody := "Include " + managed + "\n\nHost main-1\n  HostName 10.0.0.9\n"
	managedBody := cliManagedHeader + "\nHost web-1\n  HostName 10.0.0.1\n"
	writeFixture(t, mainPath, mainBody)
	writeFixture(t, managed, managedBody)

	r := runForwardSave(t, realSSH, mainPath, "web-1")
	if r.err != nil {
		t.Fatalf("helper failed: %v\nstdout: %s\nstderr: %s", r.err, r.stdout, r.stderr)
	}
	if strings.Contains(r.stderr, "hint:") {
		t.Errorf("managed mode printed a hint:\n%s", r.stderr)
	}
	if !strings.Contains(r.stdout, fakeSSHMarker+" -N -L 8000:localhost:80 web-1") {
		t.Errorf("the fake ssh was not exec'd; stdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
	}
	if got := cliRead(t, mainPath); got != mainBody {
		t.Errorf("main file changed:\n%s", got)
	}
	if got := cliRead(t, managed); !localForward8000.MatchString(got) {
		t.Errorf("the forward was not saved to the managed file:\n%s", got)
	}
}
