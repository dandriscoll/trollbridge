package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chdirTemp chdirs the test process to a fresh temp directory and
// restores the previous cwd via t.Cleanup. Used by tests that
// exercise cwd-relative default paths.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return dir
}

// caConfigYAML writes a minimal trollbridge.yaml that names the
// CA cert/key paths under interception.ca. Returns the config path.
// Used by client-cert tests, which always go through resolveCAArgs
// with a config path (no --cert-out / --key-out flags exist).
func caConfigYAML(t *testing.T, dir, certPath, keyPath string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	body := strings.Join([]string{
		"trollbridge_version: 3",
		"proxy: lo:8080",
		"control: 0",
		"mode: default-deny",
		"controller: {auth: mtls}",
		"approvals: {timeout_seconds: 60, on_timeout: deny, max_pending: 16}",
		"interception:",
		"  ca:",
		"    cert_path: " + certPath,
		"    key_path: " + keyPath,
		"logging:",
		"  audit_path: " + filepath.Join(dir, "audit.log"),
		"  operational_path: " + filepath.Join(dir, "ops.log"),
		"",
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

// runCAInit invokes `ca init` with --cert-out / --key-out so the
// resolveCAArgs path skips config loading. Uses ecdsa-p256 for
// keygen speed.
func runCAInit(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	cmd := newCAInitCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--key-type", "ecdsa-p256",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca init: %v\n%s", err, buf.String())
	}
	return buf.String()
}

func TestCAInit_CreatesFilesAndPrintsFingerprint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	out := runCAInit(t, certPath, keyPath)

	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file missing: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key file mode = %o, want 0600", mode)
	}
	if !strings.Contains(out, "fingerprint (sha-256):") {
		t.Errorf("output missing fingerprint line:\n%s", out)
	}
}

func TestCAInit_NextStepsMentionsCAInstall(t *testing.T) {
	dir := t.TempDir()
	out := runCAInit(t, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))

	if !strings.Contains(out, "trollbridge ca install") {
		t.Errorf("ca init next-steps must mention `trollbridge ca install` (regression guard for job 056):\n%s", out)
	}
}

func TestCAInit_RefusesWhenFilesExist(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	runCAInit(t, certPath, keyPath)

	cmd := newCAInitCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--key-type", "ecdsa-p256",
	})
	if err := cmd.Execute(); err == nil {
		t.Errorf("expected ca init to refuse when files exist; got success:\n%s", buf.String())
	}
}

func TestCAInit_ForceArchivesExisting(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	firstOut := runCAInit(t, certPath, keyPath)
	firstFingerprint := extractFingerprint(t, firstOut)

	cmd := newCAInitCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--key-type", "ecdsa-p256",
		"--force",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca init --force: %v\n%s", err, buf.String())
	}
	secondFingerprint := extractFingerprint(t, buf.String())

	if firstFingerprint == "" || secondFingerprint == "" {
		t.Fatalf("could not extract both fingerprints; first=%q second=%q", firstFingerprint, secondFingerprint)
	}
	if firstFingerprint == secondFingerprint {
		t.Errorf("--force should produce a new CA; both fingerprints = %q", firstFingerprint)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	bakCount := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak") {
			bakCount++
		}
	}
	if bakCount == 0 {
		t.Errorf("expected at least one .bak archive after --force; dir contents: %v", listNames(entries))
	}
}

func TestCAExport_StdoutEmitsParseablePEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	runCAInit(t, certPath, keyPath)

	cmd := newCAExportCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--cert", certPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca export: %v\nstderr=%s", err, stderr.String())
	}

	block, rest := pem.Decode(stdout.Bytes())
	if block == nil {
		t.Fatalf("stdout is not a PEM block:\n%s", stdout.String())
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type = %q, want CERTIFICATE", block.Type)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Errorf("PEM block did not parse as x509: %v", err)
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Errorf("stdout has trailing non-PEM content:\n%s", string(rest))
	}
}

func TestCAExport_OutWritesFileAndStderrHint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	runCAInit(t, certPath, keyPath)

	outPath := filepath.Join(dir, "exported.crt")
	cmd := newCAExportCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--cert", certPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca export --out: %v\nstderr=%s", err, stderr.String())
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	want, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("--out file contents differ from source cert")
	}
	if !strings.Contains(stderr.String(), "trollbridge ca install") {
		t.Errorf("stderr should hint at `ca install` (regression guard for job 056):\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty when --out is set; got %d bytes", stdout.Len())
	}
}

func TestCARotate_RefusesWithoutForce(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	runCAInit(t, certPath, keyPath)

	cmd := newCARotateCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--key-type", "ecdsa-p256",
	})
	if err := cmd.Execute(); err == nil {
		t.Errorf("expected ca rotate to refuse without --force; got success:\n%s", buf.String())
	}
}

func TestCARotate_ForceArchivesAndChangesFingerprint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	firstFingerprint := extractFingerprint(t, runCAInit(t, certPath, keyPath))

	cmd := newCARotateCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--cert-out", certPath,
		"--key-out", keyPath,
		"--key-type", "ecdsa-p256",
		"--force",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca rotate --force: %v\n%s", err, buf.String())
	}
	secondFingerprint := extractFingerprint(t, buf.String())

	if firstFingerprint == "" || secondFingerprint == "" {
		t.Fatalf("could not extract fingerprints; first=%q second=%q", firstFingerprint, secondFingerprint)
	}
	if firstFingerprint == secondFingerprint {
		t.Errorf("rotate should produce a new CA; both fingerprints = %q", firstFingerprint)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	bakCount := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak") {
			bakCount++
		}
	}
	if bakCount == 0 {
		t.Errorf("rotate --force should archive prior files; got: %v", listNames(entries))
	}
}

func TestCAClientCert_DefaultPathsAndKeyMode(t *testing.T) {
	dir := chdirTemp(t)
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	runCAInit(t, certPath, keyPath)
	cfgPath := caConfigYAML(t, dir, certPath, keyPath)

	cmd := newCAClientCertCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"-c", cfgPath, "agent"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca client-cert: %v\n%s", err, buf.String())
	}

	if _, err := os.Stat(filepath.Join(dir, "agent.crt")); err != nil {
		t.Errorf("default cert path agent.crt missing: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatalf("default key path agent.key missing: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("client-cert key file mode = %o, want 0600", mode)
	}
}

// TestCAClientCert_HonorsConfigLeafKeyType closes issue #28: the
// client-cert RunE used to hard-code ca.KeyTypeRSA4096 and ignore
// cfg.Interception.LeafKeyType. With leaf_key_type: ecdsa-p256 in
// the config, the issued leaf key must parse as ECDSA.
func TestCAClientCert_HonorsConfigLeafKeyType(t *testing.T) {
	dir := chdirTemp(t)
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	runCAInit(t, certPath, keyPath)

	// Author a yaml with leaf_key_type explicitly ECDSA.
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	body := strings.Join([]string{
		"trollbridge_version: 3",
		"proxy: lo:8080",
		"control: 0",
		"mode: default-deny",
		"controller: {auth: mtls}",
		"approvals: {timeout_seconds: 60, on_timeout: deny, max_pending: 16}",
		"interception:",
		"  ca:",
		"    cert_path: " + certPath,
		"    key_path: " + keyPath,
		"  leaf_key_type: ecdsa-p256",
		"logging:",
		"  audit_path: " + filepath.Join(dir, "audit.log"),
		"",
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newCAClientCertCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"-c", cfgPath, "agent"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca client-cert: %v\n%s", err, buf.String())
	}

	keyPEMBytes, err := os.ReadFile(filepath.Join(dir, "agent.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEMBytes)
	if block == nil {
		t.Fatalf("could not decode key PEM:\n%s", keyPEMBytes)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS8 key: %v", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("issued leaf key type = %T, want *ecdsa.PrivateKey (config's leaf_key_type was ecdsa-p256)", key)
	}
}

func TestCAClientCert_CertOutAndKeyOutOverrides(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	runCAInit(t, certPath, keyPath)
	cfgPath := caConfigYAML(t, dir, certPath, keyPath)

	leafCert := filepath.Join(dir, "leaf.crt")
	leafKey := filepath.Join(dir, "leaf.key")

	cmd := newCAClientCertCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"-c", cfgPath,
		"--cert-out", leafCert,
		"--key-out", leafKey,
		"agent",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("ca client-cert: %v\n%s", err, buf.String())
	}

	if _, err := os.Stat(leafCert); err != nil {
		t.Errorf("--cert-out override not honored: %v", err)
	}
	info, err := os.Stat(leafKey)
	if err != nil {
		t.Fatalf("--key-out override not honored: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("client-cert key file mode = %o, want 0600", mode)
	}
}

// extractFingerprint scans cobra output for the line
// `fingerprint (sha-256): aa:bb:...` and returns the colon-hex
// portion. Returns "" when not found, which the caller treats as
// a test failure.
func extractFingerprint(t *testing.T, out string) string {
	t.Helper()
	const tag = "fingerprint (sha-256):"
	idx := strings.Index(out, tag)
	if idx < 0 {
		return ""
	}
	rest := out[idx+len(tag):]
	end := strings.IndexAny(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func listNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

