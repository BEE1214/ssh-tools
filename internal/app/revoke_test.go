package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// makeCert creates a throwaway CA and a user key in a temp dir and signs the
// key with the given identity. It returns the path of the -cert.pub file.
func makeCert(t *testing.T, identity string) string {
	t.Helper()
	return makeCertV(t, identity, "+1d")
}

// makeCertV is makeCert with an explicit ssh-keygen -V validity interval;
// validity == "" omits -V (a "Valid: forever" certificate).
func makeCertV(t *testing.T, identity, validity string) string {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not in PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
		}
	}
	run("-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "ca"))
	run("-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "user"))
	sign := []string{"-q", "-s", filepath.Join(dir, "ca"), "-I", identity, "-n", "placeholder-user"}
	if validity != "" {
		sign = append(sign, "-V", validity)
	}
	run(append(sign, filepath.Join(dir, "user.pub"))...)
	return filepath.Join(dir, "user-cert.pub")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func TestRevokeCert_HostInMain(t *testing.T) {
	cert := makeCert(t, "cert-main")
	e := newSetUpIncEnvWith(t, incFixture,
		"\nHost cert-main\n  HostName 10.0.0.9\n  User cm\n  CertificateFile "+cert+"\n")
	mainBefore := e.readMainFile(t)

	if err := e.a.RevokeCert(cert); err != nil {
		t.Fatal(err)
	}
	if fileExists(cert) {
		t.Error("cert file still present after revoke")
	}
	data, err := os.ReadFile(e.managedPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "CertificateFile") {
		t.Errorf("CertificateFile line not cleared:\n%s", data)
	}
	if got := e.readMainFile(t); got != mainBefore || !strings.Contains(got, "Include "+e.incPath) {
		t.Errorf("the main file changed:\n%s", got)
	}
}

func TestRevokeCert_HostOnlyInIncludedFile(t *testing.T) {
	cert := makeCert(t, "inc-cert")
	incBody := incFixture + "\nHost inc-cert\n  HostName 10.0.1.9\n  User ic\n  CertificateFile " + cert + "\n"
	e := newSetUpIncEnvWith(t, incBody, "")
	certDir := filepath.Dir(cert)
	before := snapshotDirs(t, e.dir, e.incDir, certDir)

	err := e.a.RevokeCert(cert)
	if err == nil {
		t.Fatal("RevokeCert succeeded for a host defined in an included file")
	}
	if !strings.Contains(err.Error(), "not deleted") || !strings.Contains(err.Error(), e.wantIncludedErr("inc-cert")) {
		t.Errorf("error = %q, want it to say the cert was kept and why", err)
	}
	if !fileExists(cert) {
		t.Error("cert file was deleted although its CertificateFile line could not be cleared")
	}
	after := snapshotDirs(t, e.dir, e.incDir, certDir)
	if len(after) != len(before) {
		t.Errorf("files changed: before %d entries, after %d", len(before), len(after))
	}
	for p, b := range before {
		if a, ok := after[p]; !ok || a != b {
			t.Errorf("%s changed (bytes or mtime)", p)
		}
	}
}

func TestRevokeCert_NoMatchingHost(t *testing.T) {
	cert := makeCert(t, "nobody")
	e := newIncEnv(t)
	mainBefore, err := os.ReadFile(e.mainPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := e.a.RevokeCert(cert); err != nil {
		t.Fatal(err)
	}
	if fileExists(cert) {
		t.Error("cert file not deleted when no host references it")
	}
	mainAfter, _ := os.ReadFile(e.mainPath)
	if string(mainAfter) != string(mainBefore) {
		t.Error("config changed although no host matched")
	}
}
