package advisor

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// authCaptureServer is a minimal http.Handler that records the
// auth-related headers from the most recent inbound request and
// returns a valid advisor.Output JSON body.
type authCaptureServer struct {
	*httptest.Server
	lastAuth   string
	lastAPIKey string
}

func newAuthCaptureServer(t *testing.T) *authCaptureServer {
	t.Helper()
	a := &authCaptureServer{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.lastAuth = r.Header.Get("Authorization")
		a.lastAPIKey = r.Header.Get("api-key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"effect":"allow","confidence":"high","reason":"ok"}`))
	}))
	return a
}
