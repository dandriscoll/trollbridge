package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
