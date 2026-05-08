package envprint

import (
	"strings"
	"testing"

	"github.com/dandriscoll/drawbridge/internal/config"
)

func TestRender(t *testing.T) {
	cases := []struct {
		name      string
		address   string
		port      int
		wantHost  string // substring that must appear in `export HTTPS_PROXY=`
		wantHTTPS string // full HTTPS_PROXY URL
	}{
		{"wildcard ipv4", "0.0.0.0", 8080, "127.0.0.1", "http://127.0.0.1:8080"},
		{"wildcard ipv6", "::", 8080, "[::1]", "http://[::1]:8080"},
		{"empty defaults to loopback", "", 8080, "127.0.0.1", "http://127.0.0.1:8080"},
		{"literal ipv4 passes through", "10.1.2.3", 9090, "10.1.2.3", "http://10.1.2.3:9090"},
		{"hostname passes through", "drawbridge.internal", 8080, "drawbridge.internal", "http://drawbridge.internal:8080"},
		{"loopback passes through", "127.0.0.1", 8080, "127.0.0.1", "http://127.0.0.1:8080"},
		{"ipv6 literal gets bracketed", "fd00::1", 8080, "[fd00::1]", "http://[fd00::1]:8080"},
		{"already-bracketed ipv6 untouched", "[::1]", 8080, "[::1]", "http://[::1]:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				Adapter: tc.address,
				Ports:   config.Ports{Proxy: tc.port},
			}
			out := Render(cfg)
			if !strings.Contains(out, "export HTTPS_PROXY="+tc.wantHTTPS+"\n") {
				t.Errorf("missing HTTPS_PROXY=%q in output:\n%s", tc.wantHTTPS, out)
			}
			if !strings.Contains(out, "export HTTP_PROXY="+tc.wantHTTPS+"\n") {
				t.Errorf("missing HTTP_PROXY=%q in output:\n%s", tc.wantHTTPS, out)
			}
			// lowercase variants must also be present
			if !strings.Contains(out, "export https_proxy="+tc.wantHTTPS+"\n") {
				t.Errorf("missing lowercase https_proxy=%q in output:\n%s", tc.wantHTTPS, out)
			}
			if !strings.Contains(out, "export no_proxy=localhost,127.0.0.1\n") {
				t.Errorf("missing lowercase no_proxy in output:\n%s", out)
			}
			if !strings.Contains(out, "export NO_PROXY=localhost,127.0.0.1\n") {
				t.Errorf("missing NO_PROXY in output:\n%s", out)
			}
			// leading comment for self-describing eval output
			if !strings.HasPrefix(out, "# drawbridge env:") {
				t.Errorf("output should start with '# drawbridge env:' comment; got first line: %q",
					strings.SplitN(out, "\n", 2)[0])
			}
		})
	}
}

func TestRenderEvalSafe(t *testing.T) {
	// `eval "$(drawbridge env ...)"` must not break the shell. Each
	// line is either blank, a comment, or `export VAR=URL`. URLs we
	// emit are well-formed (no spaces, no quotes), so a sanity check
	// that no line contains a space-after-`export VAR=` (which would
	// create two arguments) is sufficient.
	cfg := &config.Config{Adapter: "127.0.0.1", Ports: config.Ports{Proxy: 8080}}
	out := Render(cfg)
	for i, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "export ") {
			t.Errorf("line %d is not blank/comment/export: %q", i+1, line)
			continue
		}
		// `export FOO=bar` — must be exactly one space, between
		// `export` and `FOO=...`.
		afterExport := strings.TrimPrefix(line, "export ")
		if strings.ContainsAny(afterExport, " \t") {
			t.Errorf("line %d has whitespace after export keyword: %q", i+1, line)
		}
		if !strings.Contains(afterExport, "=") {
			t.Errorf("line %d missing `=`: %q", i+1, line)
		}
	}
}
