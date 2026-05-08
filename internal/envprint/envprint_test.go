package envprint

import (
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/config"
)

func TestRender(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		port      int
		wantHTTPS string
	}{
		{"wildcard ipv4 collapses to loopback", "0.0.0.0", 8080, "http://127.0.0.1:8080"},
		{"wildcard ipv6 collapses to loopback", "::", 8080, "http://[::1]:8080"},
		{"literal ipv4 passes through", "10.1.2.3", 9090, "http://10.1.2.3:9090"},
		{"hostname passes through", "trollbridge.internal", 8080, "http://trollbridge.internal:8080"},
		{"loopback passes through", "127.0.0.1", 8080, "http://127.0.0.1:8080"},
		{"ipv6 literal gets bracketed", "fd00::1", 8080, "http://[fd00::1]:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Proxy: config.Bind{Host: tc.host, Port: tc.port}}
			out := Render(cfg)
			if !strings.Contains(out, "export HTTPS_PROXY="+tc.wantHTTPS+"\n") {
				t.Errorf("missing HTTPS_PROXY=%q in output:\n%s", tc.wantHTTPS, out)
			}
			if !strings.Contains(out, "export HTTP_PROXY="+tc.wantHTTPS+"\n") {
				t.Errorf("missing HTTP_PROXY=%q in output:\n%s", tc.wantHTTPS, out)
			}
			if !strings.Contains(out, "export https_proxy="+tc.wantHTTPS+"\n") {
				t.Errorf("missing lowercase https_proxy=%q in output:\n%s", tc.wantHTTPS, out)
			}
			if !strings.Contains(out, "export no_proxy=localhost,127.0.0.1\n") {
				t.Errorf("missing lowercase no_proxy in output:\n%s", out)
			}
			if !strings.Contains(out, "export NO_PROXY=localhost,127.0.0.1\n") {
				t.Errorf("missing NO_PROXY in output:\n%s", out)
			}
			if !strings.HasPrefix(out, "# trollbridge env:") {
				t.Errorf("output should start with '# trollbridge env:' comment; got first line: %q",
					strings.SplitN(out, "\n", 2)[0])
			}
		})
	}
}

func TestRenderEvalSafe(t *testing.T) {
	cfg := &config.Config{Proxy: config.Bind{Host: "127.0.0.1", Port: 8080}}
	out := Render(cfg)
	for i, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "export ") {
			t.Errorf("line %d is not blank/comment/export: %q", i+1, line)
			continue
		}
		afterExport := strings.TrimPrefix(line, "export ")
		if strings.ContainsAny(afterExport, " \t") {
			t.Errorf("line %d has whitespace after export keyword: %q", i+1, line)
		}
		if !strings.Contains(afterExport, "=") {
			t.Errorf("line %d missing `=`: %q", i+1, line)
		}
	}
}
