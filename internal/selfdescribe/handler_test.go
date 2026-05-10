package selfdescribe

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
)

func newCfgWithCA(t *testing.T, body string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trollbridge-ca.crt")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	cfg.Interception.CA.CertPath = path
	return cfg
}

func newCfgNoCA(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interception.CA.CertPath = ""
	return cfg
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "http://config.trollbridge.dev"+path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandler_IndexLists(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	for _, p := range []string{"/setup", "/setup/"} {
		w := get(t, h, p)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", p, w.Code)
		}
		body := w.Body.String()
		for _, want := range []string{"127.0.0.1:8080", "/setup/proxied-agent.md", "/setup/instructions.md", "/setup/env", "/setup/ca.crt"} {
			if !strings.Contains(body, want) {
				t.Errorf("index %s missing %q in body:\n%s", p, want, body)
			}
		}
	}
}

func TestHandler_ProxiedAgentMatchesEmbed(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/proxied-agent.md")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Errorf("content-type = %q", w.Header().Get("Content-Type"))
	}
	if string(w.Body.Bytes()) != string(proxiedAgentMD) {
		t.Errorf("body did not match embedded copy (len got %d, want %d)", w.Body.Len(), len(proxiedAgentMD))
	}
}

func TestHandler_InstructionsMatchesEmbed(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/instructions.md")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if string(w.Body.Bytes()) != string(clientSetupMD) {
		t.Errorf("body did not match embedded copy")
	}
}

func TestHandler_EnvShowsListenAddr(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/env")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"export HTTP_PROXY=http://127.0.0.1:8080",
		"export HTTPS_PROXY=http://127.0.0.1:8080",
		"unset NO_PROXY",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("env body missing %q:\n%s", want, body)
		}
	}
}

func TestHandler_CACertServed(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----\n"
	h := Handler(newCfgWithCA(t, pem), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/ca.crt")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("content-type = %q", w.Header().Get("Content-Type"))
	}
	if w.Body.String() != pem {
		t.Errorf("body mismatch")
	}
}

func TestHandler_CACertMissing404(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/ca.crt")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "TLS interception is not configured") {
		t.Errorf("404 body should explain why; got %q", w.Body.String())
	}
}

func TestHandler_CAPathConfiguredButFileMissing404(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interception.CA.CertPath = "/nonexistent/path/ca.crt"
	h := Handler(cfg, "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/ca.crt")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestHandler_UnknownPath404(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/foo")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "valid paths") {
		t.Errorf("unknown-path 404 should list valid paths; got %q", w.Body.String())
	}
}

func TestHandler_RejectsPOST(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	r := httptest.NewRequest("POST", "http://config.trollbridge.dev/setup/ca.crt", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if w.Header().Get("Allow") != "GET" {
		t.Errorf("Allow = %q, want GET", w.Header().Get("Allow"))
	}
}

func TestHandler_StampsRequestID(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup")
	if id := w.Header().Get("Trollbridge-Request-Id"); id == "" {
		t.Errorf("Trollbridge-Request-Id missing")
	}
}
