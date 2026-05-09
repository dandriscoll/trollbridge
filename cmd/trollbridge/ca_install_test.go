package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeStat returns nil for paths in `exists`, errFakeStat otherwise.
type fakeStat map[string]bool

var errFakeStat = errors.New("not present (fake stat)")

func (f fakeStat) stat(path string) (os.FileInfo, error) {
	if f[path] {
		return nil, nil
	}
	return nil, errFakeStat
}

func TestFindInstallCert_ExplicitWins_NoExistenceCheck(t *testing.T) {
	got, err := findInstallCert("/explicit/cert.pem", "/some/config-cert", fakeStat{}.stat)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got != "/explicit/cert.pem" {
		t.Errorf("got %q, want explicit path", got)
	}
}

func TestFindInstallCert_ConfigPathPreferredWhenExists(t *testing.T) {
	got, err := findInstallCert("", "/conf/cert.pem", fakeStat{"/conf/cert.pem": true}.stat)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "/conf/cert.pem" {
		t.Errorf("got %q", got)
	}
}

func TestFindInstallCert_FallsThroughToCanonical(t *testing.T) {
	// config path set but absent → fall through to canonical, where
	// /usr/local/share/ca-certificates/trollbridge-ca.crt exists.
	stat := fakeStat{"/usr/local/share/ca-certificates/trollbridge-ca.crt": true}.stat
	got, err := findInstallCert("", "/conf/missing.pem", stat)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "/usr/local/share/ca-certificates/trollbridge-ca.crt" {
		t.Errorf("got %q, want /usr/local/share/ca-certificates/trollbridge-ca.crt", got)
	}
}

func TestFindInstallCert_PrefersEtcOverShare(t *testing.T) {
	// Both /etc and /usr/local exist; /etc wins.
	stat := fakeStat{
		"/etc/trollbridge/trollbridge-ca.crt":                       true,
		"/usr/local/share/ca-certificates/trollbridge-ca.crt":       true,
	}.stat
	got, err := findInstallCert("", "", stat)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got != "/etc/trollbridge/trollbridge-ca.crt" {
		t.Errorf("got %q, want /etc/trollbridge/trollbridge-ca.crt", got)
	}
}

// TestInstallCertCandidates_NoCwd is the contract-level guard for
// issue #14: the candidate list MUST NOT contain a cwd-relative
// path. Cwd-relative defaults are not cross-machine stable.
func TestInstallCertCandidates_NoCwd(t *testing.T) {
	for _, p := range installCertCandidates() {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("candidate %q is not absolute; cwd-relative paths break cross-machine validity (issue #14)", p)
		}
	}
}

// TestFindInstallCert_OnlyCanonicalExists_PicksAbsolute asserts the
// returned cert path is absolute (so the install commands printed
// downstream are absolute too).
func TestFindInstallCert_OnlyCanonicalExists_PicksAbsolute(t *testing.T) {
	stat := fakeStat{"/etc/trollbridge/trollbridge-ca.crt": true}.stat
	got, err := findInstallCert("", "", stat)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(got, "/") {
		t.Errorf("returned path %q is not absolute; install command text would not be cross-machine valid", got)
	}
}

// TestCAInstallCmd_RelativeCert_IsAbsolutizedInOutput asserts that
// when the operator passes --cert with a relative path, the printed
// install commands use the absolute form. This is the user's "core
// issue" from the v0.4.6 follow-up: the printed commands must be
// cross-machine portable regardless of how the operator named the
// cert on the command line.
func TestCAInstallCmd_RelativeCert_IsAbsolutizedInOutput(t *testing.T) {
	dir := t.TempDir()
	rel := "relative-ca.crt"
	abs := filepath.Join(dir, rel)
	// The file just has to exist for printInstallHelp; it does not
	// need to parse as a cert (the fingerprint helper skips
	// silently when parse fails).
	if err := os.WriteFile(abs, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}

	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	cmd := newCAInstallCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--cert", "./" + rel})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, out.String())
	}
	got := out.String()
	if strings.Contains(got, "./relative-ca.crt") {
		t.Errorf("printed install commands still reference cwd-relative form ./relative-ca.crt:\n%s", got)
	}
	if !strings.Contains(got, abs) {
		t.Errorf("printed install commands missing absolute path %q:\n%s", abs, got)
	}
}

func TestFindInstallCert_NoCertAnywhere_ErrorNamesEveryCandidate(t *testing.T) {
	_, err := findInstallCert("", "/conf/missing.pem", fakeStat{}.stat)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{
		"/conf/missing.pem",
		"/etc/trollbridge/trollbridge-ca.crt",
		"/usr/local/share/ca-certificates/trollbridge-ca.crt",
		"--cert",
		"remote-mode",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in error:\n%s", want, err.Error())
		}
	}
	// And explicitly assert the cwd-relative entry is GONE — issue #14.
	if strings.Contains(err.Error(), "\n  - trollbridge-ca.crt\n") || strings.HasSuffix(err.Error(), "\n  - trollbridge-ca.crt") {
		t.Errorf("error still names a cwd-relative candidate; should be canonical paths only:\n%s", err.Error())
	}
}

// TestPrintInstallHelp_AbsolutePathsOnly closes the core defect
// from the user's #14 follow-up: every printed line referencing
// the cert must use an absolute path, not a cwd-relative one.
// `printInstallHelp` is invoked indirectly via the cmd's RunE; here
// we assert on the output of `installCommandsFor` (which composes
// the printed lines) given an absolute cert path. The cmd-level
// RunE does the abs-conversion.
func TestPrintInstallHelp_AbsolutePathsOnly(t *testing.T) {
	const certPath = "/etc/trollbridge/trollbridge-ca.crt"
	for _, p := range []platform{platformLinuxDebian, platformLinuxFedora, platformLinuxArch, platformDarwin, platformWindows} {
		lines := installCommandsFor(p, certPath)
		for _, line := range lines {
			// Skip pure-comment lines.
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if !strings.Contains(line, certPath) {
				continue
			}
			// The cert reference must be the absolute form.
			if strings.Contains(line, "./trollbridge-ca.crt") || strings.Contains(line, " trollbridge-ca.crt ") {
				t.Errorf("platform=%s line uses cwd-relative cert path: %q", p, line)
			}
		}
	}
}

func TestDetectPlatformFrom(t *testing.T) {
	cases := []struct {
		name      string
		goos      string
		osRelease string
		want      platform
	}{
		{"darwin", "darwin", "", platformDarwin},
		{"windows", "windows", "", platformWindows},
		{"linux empty os-release", "linux", "", platformLinuxUnknown},
		{"ubuntu", "linux", `ID=ubuntu` + "\n" + `ID_LIKE=debian`, platformLinuxDebian},
		{"debian", "linux", `ID=debian`, platformLinuxDebian},
		{"linux mint", "linux", `ID=linuxmint` + "\n" + `ID_LIKE="ubuntu debian"`, platformLinuxDebian},
		{"fedora", "linux", `ID=fedora`, platformLinuxFedora},
		{"rhel", "linux", `ID=rhel` + "\n" + `ID_LIKE="fedora"`, platformLinuxFedora},
		{"rocky", "linux", `ID="rocky"` + "\n" + `ID_LIKE="rhel centos fedora"`, platformLinuxFedora},
		{"alpine", "linux", `ID=alpine`, platformLinuxAlpine},
		{"arch", "linux", `ID=arch`, platformLinuxArch},
		{"manjaro", "linux", `ID=manjaro` + "\n" + `ID_LIKE=arch`, platformLinuxArch},
		{"unknown linux", "linux", `ID=tempest` + "\n" + `ID_LIKE=void`, platformLinuxUnknown},
		{"unknown OS", "plan9", "", platformUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectPlatformFrom(c.goos, c.osRelease)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestInstallCommandsFor_KeyTokens(t *testing.T) {
	cases := []struct {
		p        platform
		mustHave []string
	}{
		{platformLinuxDebian, []string{"update-ca-certificates", "/usr/local/share/ca-certificates"}},
		{platformLinuxFedora, []string{"update-ca-trust", "/etc/pki/ca-trust/source/anchors"}},
		{platformLinuxAlpine, []string{"update-ca-certificates"}},
		{platformLinuxArch, []string{"trust anchor"}},
		{platformDarwin, []string{"security add-trusted-cert", "login.keychain", "System.keychain"}},
		{platformWindows, []string{"certutil -addstore", "Root"}},
	}
	for _, c := range cases {
		t.Run(string(c.p), func(t *testing.T) {
			out := strings.Join(installCommandsFor(c.p, "/etc/trollbridge/trollbridge-ca.crt"), "\n")
			for _, tok := range c.mustHave {
				if !strings.Contains(out, tok) {
					t.Errorf("missing %q in commands for %s:\n%s", tok, c.p, out)
				}
			}
			if !strings.Contains(out, "/etc/trollbridge/trollbridge-ca.crt") {
				t.Errorf("commands for %s did not interpolate cert path:\n%s", c.p, out)
			}
		})
	}
}

func TestInstallCommandsFor_EveryPlatformProducesOutput(t *testing.T) {
	for _, p := range allPlatforms {
		out := installCommandsFor(p, "/x/y.crt")
		if len(out) == 0 {
			t.Errorf("platform %q produced no commands", p)
		}
	}
}

func TestPrintInstallHelp_AllPlatforms(t *testing.T) {
	var buf bytes.Buffer
	printInstallHelp(&buf, "/some/path/ca.crt", true, platformLinuxDebian)
	out := buf.String()
	for _, p := range allPlatforms {
		if !strings.Contains(out, p.friendly()) {
			t.Errorf("--all-platforms output missing %q\n%s", p.friendly(), out)
		}
	}
	if !strings.Contains(out, "NODE_EXTRA_CA_CERTS") {
		t.Error("runtime options block missing")
	}
}

func TestPrintInstallHelp_SinglePlatformShowsHint(t *testing.T) {
	var buf bytes.Buffer
	printInstallHelp(&buf, "/x.crt", false, platformLinuxDebian)
	out := buf.String()
	if strings.Contains(out, platformDarwin.friendly()) {
		t.Error("single-platform output should NOT include macOS section")
	}
	if !strings.Contains(out, "trollbridge ca install --all-platforms") {
		t.Error("single-platform output missing the --all-platforms hint")
	}
}

func TestCAInstallCmd_PrintsResolvedCertPath(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	// Don't write the cert; we want to exercise the "does not exist" note path.

	cmd := newCAInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--cert", certPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, certPath) {
		t.Errorf("output should name the resolved cert path:\n%s", out)
	}
	if !strings.Contains(out, "does not exist") {
		t.Errorf("output should warn when cert missing:\n%s", out)
	}
}

func TestCertFingerprint_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(certPath); err == nil {
		t.Fatal("precondition: cert should not exist")
	}
	if _, err := certFingerprint(certPath); err == nil {
		t.Error("expected error reading nonexistent cert")
	}
	// Write a non-PEM file.
	if err := os.WriteFile(certPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := certFingerprint(certPath); err == nil {
		t.Error("expected error parsing non-PEM file")
	}
}
