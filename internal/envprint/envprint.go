// Package envprint renders the shell `export` lines an HTTP client
// needs to route through a running drawbridge proxy. Used by the
// `drawbridge env` subcommand. Pure function over Config; no I/O.
package envprint

import (
	"fmt"
	"strings"

	"github.com/dandriscoll/drawbridge/internal/config"
)

// Render returns a multi-line string suitable for `eval "$(...)"`.
// It emits a leading comment, the proxy URL pinned to the
// loopback when the daemon binds the wildcard, and both the
// upper- and lowercase HTTPS_PROXY/HTTP_PROXY/NO_PROXY exports
// (curl, wget, and a number of other Unix tools read the
// lowercase variants only).
func Render(cfg *config.Config) string {
	proxyURL := fmt.Sprintf("http://%s", cfg.Proxy.ClientAddr())
	noProxy := "localhost,127.0.0.1"

	var b strings.Builder
	fmt.Fprintf(&b, "# drawbridge env: client exports for HTTPS_PROXY/HTTP_PROXY/NO_PROXY (proxy on %s)\n", proxyURL)
	fmt.Fprintf(&b, "export HTTPS_PROXY=%s\n", proxyURL)
	fmt.Fprintf(&b, "export HTTP_PROXY=%s\n", proxyURL)
	fmt.Fprintf(&b, "export NO_PROXY=%s\n", noProxy)
	fmt.Fprintf(&b, "export https_proxy=%s\n", proxyURL)
	fmt.Fprintf(&b, "export http_proxy=%s\n", proxyURL)
	fmt.Fprintf(&b, "export no_proxy=%s\n", noProxy)
	return b.String()
}
