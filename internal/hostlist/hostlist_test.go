package hostlist

import (
	"os"
	"path/filepath"
	"testing"
)

func writeList(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadOne(t *testing.T, content string) *HostList {
	t.Helper()
	p := writeList(t, content)
	h, err := LoadFiles("test", []string{p})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestParse_BasicHost(t *testing.T) {
	h := loadOne(t, "example.com\n")
	if _, ok := h.Match("", "", "example.com", 443, "/"); !ok {
		t.Error("expected exact host match")
	}
	if _, ok := h.Match("", "", "other.com", 443, "/"); ok {
		t.Error("unexpected match for unrelated host")
	}
}

func TestParse_WildcardSubdomain(t *testing.T) {
	h := loadOne(t, "*.example.com\n")
	cases := []struct {
		host string
		want bool
	}{
		{"a.example.com", true},
		{"a.b.example.com", true},
		{"example.com", false}, // bare apex NOT covered by *.foo
		{"badexample.com", false},
		{"other.com", false},
	}
	for _, c := range cases {
		_, got := h.Match("", "", c.host, 443, "/")
		if got != c.want {
			t.Errorf("host=%s: got %v, want %v", c.host, got, c.want)
		}
	}
}

func TestParse_PortExactAndAny(t *testing.T) {
	h := loadOne(t, "example.com:443\nexample.com:8080\n")
	if _, ok := h.Match("", "", "example.com", 443, "/"); !ok {
		t.Error("expected match on :443")
	}
	if _, ok := h.Match("", "", "example.com", 8080, "/"); !ok {
		t.Error("expected match on :8080")
	}
	if _, ok := h.Match("", "", "example.com", 1234, "/"); ok {
		t.Error("unexpected match on :1234")
	}

	hAny := loadOne(t, "example.com:*\n")
	if _, ok := hAny.Match("", "", "example.com", 1234, "/"); !ok {
		t.Error("wildcard port should match any")
	}

	hOmitted := loadOne(t, "example.com\n")
	if _, ok := hOmitted.Match("", "", "example.com", 9999, "/"); !ok {
		t.Error("omitted port should match any")
	}
}

func TestParse_PathExactAndPrefix(t *testing.T) {
	h := loadOne(t, "api.github.com/repos/*\napi.github.com/users\n")
	cases := []struct {
		path string
		want bool
	}{
		{"/repos/", true},
		{"/repos/foo/bar", true},
		{"/users", true},
		{"/users/alice", false}, // exact /users only
		{"/", false},
	}
	for _, c := range cases {
		_, got := h.Match("", "", "api.github.com", 443, c.path)
		if got != c.want {
			t.Errorf("path=%s: got %v want %v", c.path, got, c.want)
		}
	}
}

func TestParse_AnyHost(t *testing.T) {
	h := loadOne(t, "*\n")
	if _, ok := h.Match("", "", "a.b.c", 80, "/"); !ok {
		t.Error("bare * should match any host")
	}
}

func TestParse_AnyHostOnSpecificPort(t *testing.T) {
	h := loadOne(t, "*:9999\n")
	if _, ok := h.Match("", "", "anything", 9999, "/"); !ok {
		t.Error("expected match on any host with :9999")
	}
	if _, ok := h.Match("", "", "anything", 80, "/"); ok {
		t.Error("expected no match for wrong port")
	}
}

func TestParse_CommentsAndBlankLines(t *testing.T) {
	content := `# top comment
example.com   # trailing comment

# blank above
*.test.com
`
	h := loadOne(t, content)
	if _, ok := h.Match("", "", "example.com", 443, "/"); !ok {
		t.Error("expected example.com to match")
	}
	if _, ok := h.Match("", "", "a.test.com", 443, "/"); !ok {
		t.Error("expected *.test.com to match")
	}
	if len(h.Patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(h.Patterns))
	}
}

func TestParse_RejectsBadPort(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte("example.com:notaport\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFiles("test", []string{p}); err == nil {
		t.Error("expected parse error for bad port")
	}
}

func TestParse_RejectsMidWildcardHost(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte("api.*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFiles("test", []string{p}); err == nil {
		t.Error("expected parse error for middle-wildcard host")
	}
}

func TestParse_PatternSourceTracksFileLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	if err := os.WriteFile(p, []byte("# header\n\nexample.com\n*.test.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := LoadFiles("test", []string{p})
	if err != nil {
		t.Fatal(err)
	}
	// example.com is on line 3.
	if got := h.Patterns[0].Source; got == "" {
		t.Error("Source should be set")
	}
	if h.Patterns[0].Source != p+":3" {
		t.Errorf("Source: got %s, want %s:3", h.Patterns[0].Source, p)
	}
	if h.Patterns[1].Source != p+":4" {
		t.Errorf("Source: got %s, want %s:4", h.Patterns[1].Source, p)
	}
}

func TestNilHostList_NeverMatches(t *testing.T) {
	var h *HostList
	if _, ok := h.Match("", "", "anything", 443, "/"); ok {
		t.Error("nil HostList should not match")
	}
}

func TestEmptyList_NeverMatches(t *testing.T) {
	h := loadOne(t, "# only comments\n\n")
	if _, ok := h.Match("", "", "anything", 443, "/"); ok {
		t.Error("empty list should not match")
	}
	if len(h.Patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(h.Patterns))
	}
}

func TestParseScheme_AcceptsHttpAndHttps(t *testing.T) {
	for _, p := range []string{
		"https://api.github.com",
		"http://internal.local/v1/foo",
		"https://*.github.com/v3/*",
	} {
		if _, err := parsePattern(p); err != nil {
			t.Errorf("parsePattern(%q): %v", p, err)
		}
	}
}

func TestParseScheme_RejectsUnknown(t *testing.T) {
	for _, p := range []string{
		"ftp://x",
		"gopher://example.com",
	} {
		if _, err := parsePattern(p); err == nil {
			t.Errorf("parsePattern(%q): expected error, got nil", p)
		}
	}
}

func TestMatch_SchemeRequiredWhenSpecified(t *testing.T) {
	h := loadOne(t, "https://api.github.com\n")
	if _, ok := h.Match("", "https", "api.github.com", 443, "/"); !ok {
		t.Error("https://api.github.com should match scheme=https")
	}
	if _, ok := h.Match("", "http", "api.github.com", 443, "/"); ok {
		t.Error("https://api.github.com should NOT match scheme=http")
	}
	if _, ok := h.Match("", "", "api.github.com", 443, "/"); ok {
		t.Error("https://api.github.com should NOT match scheme=\"\" (CONNECT)")
	}
}

func TestMatch_NoSchemeMatchesAny(t *testing.T) {
	h := loadOne(t, "api.github.com\n")
	for _, scheme := range []string{"", "http", "https"} {
		if _, ok := h.Match("", scheme, "api.github.com", 443, "/"); !ok {
			t.Errorf("scheme=%q should match scheme-less pattern", scheme)
		}
	}
}

func TestMatch_URLWithPathPrefix(t *testing.T) {
	h := loadOne(t, "https://api.github.com/v3/*\n")
	if _, ok := h.Match("", "https", "api.github.com", 443, "/v3/repos"); !ok {
		t.Error("URL+path-prefix should match /v3/repos")
	}
	if _, ok := h.Match("", "https", "api.github.com", 443, "/v4/foo"); ok {
		t.Error("URL+path-prefix should NOT match /v4/foo")
	}
	if _, ok := h.Match("", "http", "api.github.com", 443, "/v3/repos"); ok {
		t.Error("scheme=http should NOT match https://... pattern")
	}
}

func TestParsePattern_MethodPrefix(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		anyMethod bool
		method    string
	}{
		{"no prefix", "api.github.com", true, ""},
		{"scheme only", "https://api.github.com", true, ""},
		{"explicit any", "* https://api.github.com", true, ""},
		{"explicit GET", "GET https://api.github.com", false, "GET"},
		{"explicit POST with path", "POST https://api.github.com/v1/users", false, "POST"},
		{"CONNECT bare host:port", "CONNECT api.github.com:443", false, "CONNECT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := loadOne(t, tc.raw+"\n")
			if len(h.Patterns) != 1 {
				t.Fatalf("expected 1 pattern, got %d", len(h.Patterns))
			}
			p := h.Patterns[0]
			if p.anyMethod != tc.anyMethod {
				t.Errorf("anyMethod = %v, want %v", p.anyMethod, tc.anyMethod)
			}
			if p.method != tc.method {
				t.Errorf("method = %q, want %q", p.method, tc.method)
			}
		})
	}
}

func TestMatch_MethodGated(t *testing.T) {
	h := loadOne(t, "GET https://api.github.com/users/*\n")
	if _, ok := h.Match("GET", "https", "api.github.com", 443, "/users/dan"); !ok {
		t.Error("GET pattern should match GET request")
	}
	if _, ok := h.Match("POST", "https", "api.github.com", 443, "/users/dan"); ok {
		t.Error("GET pattern should NOT match POST request")
	}
	if _, ok := h.Match("get", "https", "api.github.com", 443, "/users/dan"); !ok {
		t.Error("method comparison should be case-insensitive (lowercase typo)")
	}
}

func TestMatch_AnyMethodPatternMatchesAll(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
	}{
		{"api.github.com", ""},
		{"https://api.github.com", "https"},
		{"* https://api.github.com", "https"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			h := loadOne(t, tc.raw+"\n")
			for _, m := range []string{"", "GET", "POST", "DELETE", "PATCH", "CONNECT"} {
				if _, ok := h.Match(m, tc.scheme, "api.github.com", 443, "/"); !ok {
					t.Errorf("pattern %q should match method %q", tc.raw, m)
				}
			}
		})
	}
}

func TestMatch_BackwardCompat_NoMethodPatternsUnchanged(t *testing.T) {
	// Pattern files written before #85 (no method prefix) must
	// continue to match the same requests they did before. Method
	// arg passed by callers but pattern.anyMethod=true.
	h := loadOne(t, "https://api.github.com/v3/*\n")
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT"} {
		if _, ok := h.Match(method, "https", "api.github.com", 443, "/v3/users"); !ok {
			t.Errorf("pre-#85 pattern should match method %q", method)
		}
	}
}
