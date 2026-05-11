package controlclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
)

// TestResolveCertPaths_EnvVarsOverrideDefaults verifies the env-then-
// home-then-config precedence documented on resolveCertPaths. The
// daemon-side equivalent (TROLLBRIDGE_CONTROLLER_CERT / _KEY / _CA)
// is the operator's escape hatch for non-default install layouts;
// regression here would silently route operators back to the home
// dir defaults regardless of what they exported.
func TestResolveCertPaths_EnvVarsOverrideDefaults(t *testing.T) {
	t.Setenv("TROLLBRIDGE_CONTROLLER_CERT", "/custom/cert.pem")
	t.Setenv("TROLLBRIDGE_CONTROLLER_KEY", "/custom/key.pem")
	t.Setenv("TROLLBRIDGE_CONTROLLER_CA", "/custom/ca.pem")

	cfg := &config.Config{}
	cert, key, ca, err := resolveCertPaths(cfg)
	if err != nil {
		t.Fatalf("resolveCertPaths: %v", err)
	}
	if cert != "/custom/cert.pem" {
		t.Errorf("cert: got %q, want /custom/cert.pem", cert)
	}
	if key != "/custom/key.pem" {
		t.Errorf("key: got %q, want /custom/key.pem", key)
	}
	if ca != "/custom/ca.pem" {
		t.Errorf("ca: got %q, want /custom/ca.pem", ca)
	}
}

func TestResolveCertPaths_FallsBackToConfigCAWhenEnvUnset(t *testing.T) {
	t.Setenv("TROLLBRIDGE_CONTROLLER_CERT", "/x/cert")
	t.Setenv("TROLLBRIDGE_CONTROLLER_KEY", "/x/key")
	t.Setenv("TROLLBRIDGE_CONTROLLER_CA", "") // explicitly unset
	cfg := &config.Config{}
	cfg.Interception.CA.CertPath = "/etc/trollbridge/ca.crt"
	_, _, ca, err := resolveCertPaths(cfg)
	if err != nil {
		t.Fatalf("resolveCertPaths: %v", err)
	}
	if ca != "/etc/trollbridge/ca.crt" {
		t.Errorf("ca: got %q, want /etc/trollbridge/ca.crt (config fallback)", ca)
	}
}

func TestResolveCertPaths_ErrorsWhenCAUnknown(t *testing.T) {
	t.Setenv("TROLLBRIDGE_CONTROLLER_CERT", "/x/cert")
	t.Setenv("TROLLBRIDGE_CONTROLLER_KEY", "/x/key")
	t.Setenv("TROLLBRIDGE_CONTROLLER_CA", "")
	cfg := &config.Config{} // no interception.ca.cert_path
	_, _, _, err := resolveCertPaths(cfg)
	if err == nil {
		t.Fatal("expected error when CA path is unknown; got nil")
	}
	if !strings.Contains(err.Error(), "trollbridge CA cert path unknown") {
		t.Errorf("error message: got %q, want a 'CA cert path unknown' hint with actionable fix text", err.Error())
	}
}

func TestCertPaths_DelegatesToResolveCertPaths(t *testing.T) {
	t.Setenv("TROLLBRIDGE_CONTROLLER_CERT", "/p/cert")
	t.Setenv("TROLLBRIDGE_CONTROLLER_KEY", "/p/key")
	t.Setenv("TROLLBRIDGE_CONTROLLER_CA", "/p/ca")
	cert, key, ca, err := CertPaths(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if cert != "/p/cert" || key != "/p/key" || ca != "/p/ca" {
		t.Errorf("CertPaths: cert=%q key=%q ca=%q (env should pass through verbatim)", cert, key, ca)
	}
}

// TestPreflight_FailsClearlyWhenCertsMissing pins the failure-mode
// contract for `trollbridge attach`: when the operator cert/key file
// is absent on disk, Preflight returns an error whose message names
// the missing path AND the actionable next step. This is the literal
// path #46 fixed (the truncated TUI-footer message).
func TestPreflight_FailsClearlyWhenCertsMissing(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	// Provide a minimal CA file so the CA load path is reached AFTER
	// the cert load (which we deliberately leave missing).
	if err := os.WriteFile(caPath, []byte("not a real pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TROLLBRIDGE_CONTROLLER_CERT", filepath.Join(dir, "absent.crt"))
	t.Setenv("TROLLBRIDGE_CONTROLLER_KEY", filepath.Join(dir, "absent.key"))
	t.Setenv("TROLLBRIDGE_CONTROLLER_CA", caPath)

	err := Preflight(&config.Config{})
	if err == nil {
		t.Fatal("Preflight succeeded with absent cert files; expected error")
	}
	if !strings.Contains(err.Error(), "load operator cert") {
		t.Errorf("error message does not name 'load operator cert': %q", err.Error())
	}
	if !strings.Contains(err.Error(), "trollbridge ca client-cert") {
		t.Errorf("error message lacks actionable 'trollbridge ca client-cert' fix hint: %q", err.Error())
	}
}

func TestControllerURL_AlwaysHTTPS(t *testing.T) {
	cfg := &config.Config{}
	cfg.Control.Host = "127.0.0.1"
	cfg.Control.Port = 9443
	got := controllerURL(cfg, "/v1/holds")
	if !strings.HasPrefix(got, "https://") {
		t.Errorf("controllerURL must be https; got %q", got)
	}
	if !strings.HasSuffix(got, "/v1/holds") {
		t.Errorf("controllerURL must end with the supplied path; got %q", got)
	}
}