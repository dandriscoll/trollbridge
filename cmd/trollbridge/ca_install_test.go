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

// TestRuntimeOptionsBlock_DestinationStable closes the recurrence
// gap on issue #14: when the platform is a Linux family with a
// well-known system-trust file destination, every env-var line in
// the runtime-options block must reference that destination — not
// the source path passed in. Source paths are not cross-machine
// stable; destinations are. Sweep test, not spot-check, because the
// failure shape "missed one occurrence" is the one this rule exists
// to catch.
func TestRuntimeOptionsBlock_DestinationStable(t *testing.T) {
	const sourcePath = "/home/operator/scratch/trollbridge-ca.crt"
	cases := []struct {
		p       platform
		mustHit string
	}{
		{platformLinuxDebian, "/usr/local/share/ca-certificates/trollbridge-ca.crt"},
		{platformLinuxAlpine, "/usr/local/share/ca-certificates/trollbridge-ca.crt"},
		{platformLinuxFedora, "/etc/pki/ca-trust/source/anchors/trollbridge-ca.crt"},
		{platformLinuxArch, "/etc/ca-certificates/trust-source/anchors/trollbridge-ca.crt"},
		{platformLinuxUnknown, "/usr/local/share/ca-certificates/trollbridge-ca.crt"},
	}
	for _, c := range cases {
		t.Run(string(c.p), func(t *testing.T) {
			lines := runtimeOptionsBlock(c.p, sourcePath)
			joined := strings.Join(lines, "\n")
			if !strings.Contains(joined, c.mustHit) {
				t.Errorf("expected %q in runtime block for %s, got:\n%s", c.mustHit, c.p, joined)
			}
			// Sweep: every uncommented `export FOO=...` line MUST end
			// at the destination path, not the source.
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if !strings.HasPrefix(trimmed, "export ") {
					continue
				}
				if strings.Contains(line, sourcePath) {
					t.Errorf("env-var line still references the source path %q on %s — must use the cross-machine-stable destination %q. Line: %s",
						sourcePath, c.p, c.mustHit, line)
				}
				if !strings.Contains(line, c.mustHit) {
					t.Errorf("env-var line on %s does not reference the destination %q. Line: %s",
						c.p, c.mustHit, line)
				}
			}
		})
	}
}

// TestRuntimeOptionsBlock_NonLinuxKeepsSourceWithNote: macOS and
// Windows have no canonical file destination (keychain / cert store
// are not file paths). The block must keep the source path AND
// surface an explicit note so the operator knows what the env-vars
// reference. Also #14.
func TestRuntimeOptionsBlock_NonLinuxKeepsSourceWithNote(t *testing.T) {
	const sourcePath = "/some/abs/trollbridge-ca.crt"
	for _, p := range []platform{platformDarwin, platformWindows} {
		t.Run(string(p), func(t *testing.T) {
			lines := runtimeOptionsBlock(p, sourcePath)
			joined := strings.Join(lines, "\n")
			if !strings.Contains(joined, sourcePath) {
				t.Errorf("on %s the block should still reference the source path %q (no canonical file destination); got:\n%s",
					p, sourcePath, joined)
			}
			lower := strings.ToLower(joined)
			if !strings.Contains(lower, "current location") && !strings.Contains(lower, "absolute path") {
				t.Errorf("on %s the block must include a note explaining the source-path reference; got:\n%s", p, joined)
			}
		})
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
