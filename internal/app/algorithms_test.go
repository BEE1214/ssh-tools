package app

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/adamdvorsky/ssh-tools/internal/domain"
)

// fakeQuery replaces sshQuery for one test. kinds maps "kex"/"cipher"/... to the
// names the fake ssh supports; a missing kind makes that query fail.
func fakeQuery(t *testing.T, kinds map[string][]string) {
	t.Helper()
	old := sshQuery
	t.Cleanup(func() { sshQuery = old })
	sshQuery = func(kind string) ([]string, error) {
		names, ok := kinds[kind]
		if !ok {
			return nil, errors.New("fake: query failed")
		}
		return names, nil
	}
}

// modernSSH is what a recent OpenSSH reports (names as in `ssh -Q`).
func modernSSH() map[string][]string {
	return map[string][]string{
		"kex": {"diffie-hellman-group14-sha256", "ecdh-sha2-nistp256", "curve25519-sha256", "curve25519-sha256@libssh.org",
			"sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha256"},
		"cipher": {"aes128-ctr", "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"},
		"mac":    {"hmac-sha2-256", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"},
		"key-sig": {"ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512",
			"rsa-sha2-512-cert-v01@openssh.com"},
	}
}

func initAndRead(t *testing.T) (string, string) {
	t.Helper()
	a, path := initEnv(t, "Host web1\n  HostName 10.0.0.1\n")
	if _, err := a.InitDefaults(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, string(raw)
}

func lineWith(content, option string) (string, bool) {
	for _, l := range strings.Split(content, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && strings.EqualFold(f[0], option) {
			return f[1], true
		}
	}
	return "", false
}

func TestInitDefaults_ModernSSHFullPreferenceLists(t *testing.T) {
	fakeQuery(t, modernSSH())
	_, content := initAndRead(t)
	want := map[string]string{
		"KexAlgorithms":     "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,curve25519-sha256@libssh.org",
		"HostKeyAlgorithms": "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256",
		"Ciphers":           "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
		"MACs":              "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
	}
	for opt, w := range want {
		if got, _ := lineWith(content, opt); got != w {
			t.Errorf("%s = %q, want %q", opt, got, w)
		}
	}
	if strings.Contains(content, "mlkem768x25519-sha256@openssh.com") {
		t.Error("bogus @openssh.com mlkem name written")
	}
}

// An old ssh without mlkem (and only the @openssh.com sntrup alias) still gets a
// valid list, in preference order, without the unknown name.
func TestInitDefaults_OldSSHWithoutMlkem(t *testing.T) {
	q := modernSSH()
	q["kex"] = []string{"curve25519-sha256@libssh.org", "sntrup761x25519-sha512@openssh.com", "diffie-hellman-group14-sha1"}
	fakeQuery(t, q)
	_, content := initAndRead(t)
	got, ok := lineWith(content, "KexAlgorithms")
	if !ok || got != "sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org" {
		t.Errorf("KexAlgorithms = %q (present=%v)", got, ok)
	}
	if strings.Contains(got, "mlkem") {
		t.Errorf("mlkem written for an ssh without it: %q", got)
	}
}

func TestInitDefaults_OnlyKnownNamesKept(t *testing.T) {
	q := modernSSH()
	q["cipher"] = []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"} // no aes256-gcm
	fakeQuery(t, q)
	_, content := initAndRead(t)
	if got, _ := lineWith(content, "Ciphers"); got != "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com" {
		t.Errorf("Ciphers = %q", got)
	}
}

func TestInitDefaults_QueryFailsOmitsAlgorithmLines(t *testing.T) {
	fakeQuery(t, nil) // every query fails
	_, content := initAndRead(t)
	for _, opt := range []string{"KexAlgorithms", "HostKeyAlgorithms", "Ciphers", "MACs"} {
		if _, ok := lineWith(content, opt); ok {
			t.Errorf("%s written although ssh -Q failed:\n%s", opt, content)
		}
	}
	// The rest of the defaults block is unaffected.
	if got, _ := lineWith(content, "StrictHostKeyChecking"); got != "accept-new" {
		t.Errorf("StrictHostKeyChecking = %q\n%s", got, content)
	}
	if got, _ := lineWith(content, "ServerAliveInterval"); got != "60" {
		t.Errorf("ServerAliveInterval = %q", got)
	}
}

func TestInitDefaults_PerKindFailureAndEmptyAnswer(t *testing.T) {
	q := modernSSH()
	delete(q, "mac")                                   // this query fails
	q["cipher"] = nil                                  // answers, but nothing: treated as unknown
	q["kex"] = []string{"diffie-hellman-group14-sha1"} // nothing from the preference list survives
	fakeQuery(t, q)
	_, content := initAndRead(t)
	for _, opt := range []string{"MACs", "Ciphers", "KexAlgorithms"} {
		if v, ok := lineWith(content, opt); ok {
			t.Errorf("%s = %q written, want omitted", opt, v)
		}
	}
	if _, ok := lineWith(content, "HostKeyAlgorithms"); !ok {
		t.Error("HostKeyAlgorithms lost although its query worked")
	}
}

// The real thing: the whole generated file, nothing stripped, must be accepted
// by the installed ssh.
func TestInitDefaults_GeneratedConfigAcceptedBySSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not in PATH")
	}
	path, content := initAndRead(t)
	if _, ok := lineWith(content, "KexAlgorithms"); !ok {
		t.Fatalf("no KexAlgorithms line generated with a working ssh -Q:\n%s", content)
	}
	for _, host := range []string{"web1", "other-host"} {
		out, err := exec.Command("ssh", "-F", path, "-G", host).CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G %s failed: %v\n%s\n--- config ---\n%s", host, err, out, content)
		}
		low := strings.ToLower(string(out))
		if strings.Contains(low, "bad ") || strings.Contains(low, "terminating") {
			t.Fatalf("ssh -G %s complained:\n%s\n--- config ---\n%s", host, out, content)
		}
	}
}

func hostFor(opt, value string) domain.Host {
	h := domain.Host{Name: "web1", LineStart: 7, SourceFile: "/example/config"}
	switch opt {
	case "KexAlgorithms":
		h.KexAlgorithms = value
	case "Ciphers":
		h.Ciphers = value
	case "MACs":
		h.MACs = value
	case "HostKeyAlgorithms":
		h.HostKeyAlgorithms = value
	case "PubkeyAcceptedAlgorithms":
		h.PubkeyAcceptedAlgorithms = value
	}
	return h
}

func TestAlgorithmIssues_BadMlkemName(t *testing.T) {
	fakeQuery(t, modernSSH())
	h := hostFor("KexAlgorithms", "mlkem768x25519-sha256@openssh.com,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org")
	issues := algorithmIssues([]domain.Host{h})
	if len(issues) != 1 {
		t.Fatalf("issues = %+v, want exactly the mlkem name", issues)
	}
	i := issues[0]
	if i.Rule != "bad-algorithm" || i.Severity != domain.SeverityError || i.HostName != "web1" || i.Line != 7 || i.File != "/example/config" {
		t.Errorf("issue = %+v", i)
	}
	for _, s := range []string{"KexAlgorithms", "mlkem768x25519-sha256@openssh.com"} {
		if !strings.Contains(i.Message, s) {
			t.Errorf("message %q lacks %q", i.Message, s)
		}
	}
}

func TestAlgorithmIssues_PrefixesWildcardsAndOptions(t *testing.T) {
	fakeQuery(t, modernSSH())
	tests := []struct {
		name, opt, value string
		bad              []string
	}{
		{"plain-ok", "Ciphers", "aes128-ctr,chacha20-poly1305@openssh.com", nil},
		{"plus-ok", "KexAlgorithms", "+diffie-hellman-group14-sha256", nil},
		{"plus-bad", "KexAlgorithms", "+nonsense-kex,curve25519-sha256", []string{"nonsense-kex"}},
		{"minus-bad", "Ciphers", "-3des-cbc", []string{"3des-cbc"}},
		{"minus-ok", "Ciphers", "-aes128-ctr", nil},
		{"caret-bad", "MACs", "^hmac-nope,hmac-sha2-256", []string{"hmac-nope"}},
		{"caret-ok", "MACs", "^hmac-sha2-256-etm@openssh.com", nil},
		{"wildcard-skipped", "Ciphers", "-*-cbc,aes*-gcm@openssh.com", nil},
		{"wildcard-with-bad", "Ciphers", "-*-cbc,bogus-cipher", []string{"bogus-cipher"}},
		{"hostkey-bad", "HostKeyAlgorithms", "ssh-ed25519,ssh-dss", []string{"ssh-dss"}},
		{"hostkey-cert-ok", "HostKeyAlgorithms", "ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512", nil},
		{"pubkey-bad", "PubkeyAcceptedAlgorithms", "+ssh-bogus", []string{"ssh-bogus"}},
		{"pubkey-ok", "PubkeyAcceptedAlgorithms", "ssh-ed25519,rsa-sha2-256", nil},
		{"spaces-and-empties", "Ciphers", "aes128-ctr, ,chacha20-poly1305@openssh.com", nil},
		{"two-bad", "KexAlgorithms", "bad1,curve25519-sha256,bad2", []string{"bad1", "bad2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := algorithmIssues([]domain.Host{hostFor(tt.opt, tt.value)})
			var got []string
			for _, i := range issues {
				if i.Rule != "bad-algorithm" || !strings.Contains(i.Message, tt.opt) {
					t.Errorf("unexpected issue %+v", i)
				}
				for _, b := range tt.bad {
					if strings.Contains(i.Message, `"`+b+`"`) {
						got = append(got, b)
					}
				}
			}
			if len(issues) != len(tt.bad) || len(got) != len(tt.bad) {
				t.Errorf("issues = %+v, want bad names %v", issues, tt.bad)
			}
		})
	}
}

func TestAlgorithmIssues_CleanAndSilentWithoutQuery(t *testing.T) {
	clean := domain.Host{Name: "*", KexAlgorithms: "curve25519-sha256", Ciphers: "chacha20-poly1305@openssh.com",
		MACs: "hmac-sha2-256-etm@openssh.com", HostKeyAlgorithms: "ssh-ed25519", PubkeyAcceptedAlgorithms: "ssh-ed25519"}
	fakeQuery(t, modernSSH())
	if issues := algorithmIssues([]domain.Host{clean, {Name: "bare"}}); len(issues) != 0 {
		t.Errorf("clean config produced issues: %+v", issues)
	}

	// ssh -Q unavailable: nothing is flagged, not even an obviously bogus name.
	fakeQuery(t, nil)
	bad := domain.Host{Name: "x", KexAlgorithms: "mlkem768x25519-sha256@openssh.com", Ciphers: "bogus"}
	if issues := algorithmIssues([]domain.Host{bad}); len(issues) != 0 {
		t.Errorf("issues without ssh -Q: %+v", issues)
	}

	// Only one kind unavailable: the others are still checked.
	q := modernSSH()
	delete(q, "cipher")
	fakeQuery(t, q)
	issues := algorithmIssues([]domain.Host{bad})
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "KexAlgorithms") {
		t.Errorf("issues = %+v, want only the KexAlgorithms one", issues)
	}
}

func TestAlgorithmIssues_NotQueriedWhenUnused(t *testing.T) {
	var asked []string
	old := sshQuery
	t.Cleanup(func() { sshQuery = old })
	sshQuery = func(kind string) ([]string, error) {
		asked = append(asked, kind)
		return modernSSH()[kind], nil
	}
	algorithmIssues([]domain.Host{{Name: "a"}, {Name: "b", Ciphers: "aes128-ctr"}, {Name: "c", Ciphers: "aes128-ctr"}})
	if len(asked) != 1 || asked[0] != "cipher" {
		t.Errorf("ssh -Q calls = %v, want one cipher query", asked)
	}
}

// Through the public entry point, with file/line like other issues, in an
// included file too.
func TestValidate_ReportsBadAlgorithm(t *testing.T) {
	fakeQuery(t, modernSSH())
	a, _ := initEnv(t, "Host web1\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/placeholder\n\nHost db1\n  HostName 10.0.0.2\n  IdentityFile ~/.ssh/placeholder\n  KexAlgorithms mlkem768x25519-sha256@openssh.com,curve25519-sha256\n")
	issues, err := a.Validate()
	if err != nil {
		t.Fatal(err)
	}
	var found []domain.Issue
	for _, i := range issues {
		if i.Rule == "bad-algorithm" {
			found = append(found, i)
		}
	}
	if len(found) != 1 {
		t.Fatalf("issues = %+v", issues)
	}
	if f := found[0]; f.HostName != "db1" || f.Line != 5 || f.File != "" || f.Severity != domain.SeverityError {
		t.Errorf("issue = %+v", f)
	}
	if !domain.HasErrors(issues) {
		t.Error("bad-algorithm should count as an error")
	}
}
