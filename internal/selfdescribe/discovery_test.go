package selfdescribe

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDiscovery_StructMarshals is the build-time guard the
// init-time panic falls back to: if the schema struct ever
// includes a non-marshalable type, this test fails first.
func TestDiscovery_StructMarshals(t *testing.T) {
	d := BuildDiscovery()
	if _, err := json.Marshal(d); err != nil {
		t.Fatalf("Discovery struct fails to marshal: %v", err)
	}
}

// TestDiscovery_InitMarshaledNonEmpty asserts the package init()
// produced a non-empty discoveryJSON, and that the bytes round-trip.
func TestDiscovery_InitMarshaledNonEmpty(t *testing.T) {
	if len(discoveryJSON) == 0 {
		t.Fatal("discoveryJSON is empty after init")
	}
	var d Discovery
	if err := json.Unmarshal(discoveryJSON, &d); err != nil {
		t.Fatalf("discoveryJSON is not valid JSON: %v\n%s", err, discoveryJSON)
	}
	if d.Version != DiscoveryVersion {
		t.Errorf("version = %q, want %q", d.Version, DiscoveryVersion)
	}
}

// TestDiscovery_RequiredFields enforces the schema completeness
// criteria from the brief: every required field is present with
// non-empty content. A missing example or status code is what
// this test exists to catch.
func TestDiscovery_RequiredFields(t *testing.T) {
	d := BuildDiscovery()

	if d.Version == "" {
		t.Error("version is empty")
	}
	if d.Name == "" {
		t.Error("name is empty")
	}
	if d.Description == "" {
		t.Error("description is empty")
	}

	// Documentation pointers must reach the magic host.
	for _, pair := range []struct{ field, value string }{
		{"proxied_agent_guide", d.Documentation.ProxiedAgentGuide},
		{"client_setup_guide", d.Documentation.ClientSetupGuide},
		{"self_describe_index", d.Documentation.SelfDescribeIndex},
		{"homepage", d.Documentation.Homepage},
	} {
		if pair.value == "" {
			t.Errorf("documentation.%s is empty", pair.field)
		}
	}
	for _, link := range []string{
		d.Documentation.ProxiedAgentGuide,
		d.Documentation.ClientSetupGuide,
		d.Documentation.SelfDescribeIndex,
	} {
		if !strings.Contains(link, MagicHost) {
			t.Errorf("documentation link does not reference the magic host: %q", link)
		}
	}

	// Status codes — both 470 and 471 must be described.
	codes := map[int]bool{}
	for _, sc := range d.StatusCodes {
		codes[sc.Code] = true
		if sc.Name == "" || sc.Semantics == "" {
			t.Errorf("status code %d missing name or semantics", sc.Code)
		}
	}
	for _, want := range []int{470, 471} {
		if !codes[want] {
			t.Errorf("status code %d not described", want)
		}
	}

	// Headers — every wire header must be enumerated.
	hdrs := map[string]bool{}
	for _, h := range d.Headers {
		hdrs[h.Name] = true
		if len(h.AppearsOn) == 0 {
			t.Errorf("header %q has empty appears_on", h.Name)
		}
		if h.Purpose == "" {
			t.Errorf("header %q has empty purpose", h.Name)
		}
	}
	for _, want := range []string{
		"Trollbridge-Request-Id",
		"Trollbridge-Reason",
		"Proxy-Status",
		"Trollbridge-Hold-Id",
		"Trollbridge-Discovery",
	} {
		if !hdrs[want] {
			t.Errorf("header %q not described", want)
		}
	}

	// Body shapes — both content-types must be named.
	if d.BodyShapes.JSON.ContentType == "" {
		t.Error("body_shapes.json.content_type is empty")
	}
	if d.BodyShapes.PlainText.ContentType == "" {
		t.Error("body_shapes.plain_text.content_type is empty")
	}

	// Audit correlation — must explain request_id linkage.
	if d.AuditCorrelation.Key == "" || d.AuditCorrelation.Description == "" {
		t.Error("audit_correlation incomplete")
	}

	// Examples — at least one for 470 and one for 471.
	if len(d.Examples) < 2 {
		t.Errorf("want >= 2 examples, got %d", len(d.Examples))
	}
	exampleResponses := strings.Join(func() []string {
		out := make([]string, 0, len(d.Examples))
		for _, ex := range d.Examples {
			out = append(out, ex.Response)
		}
		return out
	}(), "\n")
	if !strings.Contains(exampleResponses, "470") {
		t.Error("no example response carries status 470")
	}
	if !strings.Contains(exampleResponses, "471") {
		t.Error("no example response carries status 471")
	}
	if !strings.Contains(exampleResponses, "Trollbridge-Discovery:") {
		t.Error("example responses do not show Trollbridge-Discovery header — agents reading examples will miss the new header")
	}
}

// TestDiscoveryHandler_ServesJSON exercises the registered route
// and asserts the wire-shape: 200, application/json content-type,
// parseable body, version field present.
func TestDiscoveryHandler_ServesJSON(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, DiscoveryPath)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mt, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
	if err != nil || mt != "application/json" {
		t.Errorf("content-type = %q, want application/json", w.Header().Get("Content-Type"))
	}
	var d Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatalf("response body is not valid JSON: %v\n%s", err, w.Body.Bytes())
	}
	if d.Version != DiscoveryVersion {
		t.Errorf("served version = %q, want %q", d.Version, DiscoveryVersion)
	}
}

// TestDiscoveryHandler_StampsRequestID asserts the new route
// inherits the existing wrapper's request-id stamping.
func TestDiscoveryHandler_StampsRequestID(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, DiscoveryPath)
	if w.Header().Get("Trollbridge-Request-Id") == "" {
		t.Error("Trollbridge-Request-Id missing on /discovery response")
	}
}

// TestDiscoveryHandler_RejectsPOST asserts the new route inherits
// the existing wrapper's GET-only enforcement.
func TestDiscoveryHandler_RejectsPOST(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	r := httptest.NewRequest("POST", "http://"+MagicHost+DiscoveryPath, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// TestIndex_ListsDiscovery asserts the /setup index page advertises
// the new /discovery endpoint so an operator browsing the index
// finds it.
func TestIndex_ListsDiscovery(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup")
	if !strings.Contains(w.Body.String(), DiscoveryPath) {
		t.Errorf("/setup index does not list %s", DiscoveryPath)
	}
}

// TestNotFound_ListsDiscovery asserts the 404 fallback's valid-paths
// list now includes /discovery.
func TestNotFound_ListsDiscovery(t *testing.T) {
	h := Handler(newCfgNoCA(t), "127.0.0.1:8080", nil)
	w := get(t, h, "/setup/nonsense")
	if !strings.Contains(w.Body.String(), DiscoveryPath) {
		t.Errorf("/setup/nonsense 404 does not mention %s", DiscoveryPath)
	}
}
