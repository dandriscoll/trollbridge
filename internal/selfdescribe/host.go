package selfdescribe

import (
	"net/http"
	"strings"
)

// IsMagicHost reports whether r targets the self-describe surface.
// The check tolerates absolute-URL forward-proxy form (r.URL.Host
// populated), direct-form (r.Host populated), an optional port
// suffix, and case differences.
func IsMagicHost(r *http.Request) bool {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return false
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// Port suffix; safe because hostnames cannot contain ':'.
		host = host[:i]
	}
	return strings.EqualFold(host, MagicHost)
}
