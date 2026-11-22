package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRevokeCert_Forever(t *testing.T) {
	cert := makeCertV(t, "no-expiry", "")
	e := newSetUpIncEnvWith(t, incFixture,
		"\nHost forever-host\n  HostName 10.0.0.9\n  CertificateFile "+cert+"\n")

	c, err := e.a.InspectCert(cert)
	if err != nil {
		t.Fatalf("InspectCert on a cert signed without -V: %v", err)
	}
	if !c.NeverExpires() || c.IsExpired() || c.Validity() != "forever" {
		t.Errorf("forever cert parsed as %+v", c)
	}

	if err := e.a.RevokeCert(cert); err != nil {
		t.Fatal(err)
	}
	if fileExists(cert) {
		t.Error("cert file still present after revoke")
	}
	data, _ := os.ReadFile(e.managedPath)
	if strings.Contains(string(data), "CertificateFile") {
		t.Errorf("CertificateFile line not cleared:\n%s", data)
	}
}

// When ssh-keygen cannot read the cert (here: not a certificate at all) the
// host must still be found through its CertificateFile line, and the
// ~-prefixed, unclean config spelling must match the absolute path.
func TestRevokeCert_InspectFailsStillClearsConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certDir := filepath.Join(home, "certs")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(certDir, "broken-cert.pub")
	writeTemp(t, cert, "this is not a certificate\n")

	e := newSetUpIncEnvWith(t, incFixture,
		"\nHost unrelated-name\n  HostName 10.0.0.9\n  CertificateFile ~/certs/../certs/broken-cert.pub\n")

	if _, err := e.a.InspectCert(cert); err == nil {
		t.Fatal("InspectCert unexpectedly succeeded on a garbage file")
	}
	if err := e.a.RevokeCert(cert); err != nil {
		t.Fatal(err)
	}
	if fileExists(cert) {
		t.Error("cert file still present after revoke")
	}
	data, _ := os.ReadFile(e.managedPath)
	if strings.Contains(string(data), "CertificateFile") {
		t.Errorf("CertificateFile line left dangling:\n%s", data)
	}
}

// Inspect failure + the referencing host lives in an included file: the clear
// fails, so the file must be kept (round-1 rule holds without InspectCert).
func TestRevokeCert_InspectFailsIncludedHostKeepsFile(t *testing.T) {
	cert := filepath.Join(t.TempDir(), "broken-cert.pub")
	writeTemp(t, cert, "this is not a certificate\n")
	e := newSetUpIncEnvWith(t, incFixture+"\nHost inc-ref\n  HostName 10.0.1.9\n  CertificateFile "+cert+"\n", "")

	if err := e.a.RevokeCert(cert); err == nil {
		t.Fatal("RevokeCert succeeded although the CertificateFile line could not be cleared")
	}
	if !fileExists(cert) {
		t.Error("cert file deleted although its CertificateFile line could not be cleared")
	}
}
