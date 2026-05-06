package redact

import (
	"net/http"
	"strings"
	"testing"
)

func TestBody_RegexReplacesAndCounts(t *testing.T) {
	cfg, err := Compile(nil, []string{`(?i)bearer [a-z0-9._-]+`}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("authn header: Bearer abc123, plus other text")
	r := cfg.Body(body, "text/plain")
	if r.RedactedFields == 0 {
		t.Errorf("expected redaction count > 0, got %d", r.RedactedFields)
	}
	if strings.Contains(string(r.Output), "abc123") {
		t.Errorf("secret leaked into output: %s", r.Output)
	}
	if !strings.Contains(string(r.Output), "<redacted>") {
		t.Errorf("expected <redacted> marker; got %s", r.Output)
	}
}

func TestBody_JSONPathReplacesNested(t *testing.T) {
	cfg, err := Compile([]string{"$.password", "$.token"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"username":"alice","password":"hunter2","token":"abc","other":1}`)
	r := cfg.Body(body, "application/json")
	if r.RedactedFields != 2 {
		t.Errorf("count: got %d, want 2", r.RedactedFields)
	}
	if strings.Contains(string(r.Output), "hunter2") || strings.Contains(string(r.Output), `"abc"`) {
		t.Errorf("secret leaked: %s", string(r.Output))
	}
}

func TestBody_SkipsJSONPathOnNonJSONContentType(t *testing.T) {
	cfg, err := Compile([]string{"$.password"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"password":"hunter2"}`)
	r := cfg.Body(body, "text/plain")
	if r.RedactedFields != 0 {
		t.Errorf("non-JSON should not be JSON-path redacted; got %d", r.RedactedFields)
	}
}

func TestHeaders_RedactsAuthorizationAndCookieAndProxyAuth(t *testing.T) {
	cfg, _ := Compile(nil, nil, nil, []string{"redact_authorization_header", "redact_cookie"})
	h := http.Header{}
	h.Set("Authorization", "Bearer XYZ")
	h.Set("Cookie", "sess=abc")
	h.Set("Proxy-Authorization", "Bearer P")
	out, count := cfg.Headers(h, nil)
	if count != 3 {
		t.Errorf("count: got %d, want 3", count)
	}
	if out.Get("Authorization") != "<redacted>" {
		t.Errorf("Authorization not redacted: %q", out.Get("Authorization"))
	}
	if out.Get("Cookie") != "<redacted>" {
		t.Errorf("Cookie not redacted: %q", out.Get("Cookie"))
	}
	if out.Get("Proxy-Authorization") != "<redacted>" {
		t.Errorf("Proxy-Authorization not redacted: %q", out.Get("Proxy-Authorization"))
	}
}

func TestHeaders_OnlyAppliesNamedModifiers(t *testing.T) {
	cfg, _ := Compile(nil, nil, nil, nil) // no default modifiers
	h := http.Header{}
	h.Set("Authorization", "Bearer XYZ")
	out, count := cfg.Headers(h, nil)
	// Authorization is NOT redacted because no modifier configured.
	if count != 0 {
		t.Errorf("count: got %d, want 0 (no modifiers configured)", count)
	}
	if out.Get("Authorization") != "Bearer XYZ" {
		t.Errorf("Authorization should pass through: %q", out.Get("Authorization"))
	}
}
