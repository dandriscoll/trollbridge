package selfdescribe

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/google/uuid"
)

// Handler returns an http.Handler that serves the self-describe
// routes. listenAddr is the proxy's bound address; it surfaces in
// the index and the env-export endpoint so an agent fetching from
// the proxy gets the canonical value (not whatever it happened to
// dial).
func Handler(cfg *config.Config, listenAddr string, opLog *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/setup", indexHandler(listenAddr))
	mux.HandleFunc("/setup/", indexHandler(listenAddr))
	mux.HandleFunc("/setup/proxied-agent.md", staticHandler(proxiedAgentMD, "text/markdown; charset=utf-8"))
	mux.HandleFunc("/setup/instructions.md", staticHandler(clientSetupMD, "text/markdown; charset=utf-8"))
	mux.HandleFunc("/setup/env", envHandler(listenAddr))
	mux.HandleFunc("/setup/ca.crt", caHandler(cfg))
	mux.HandleFunc(DiscoveryPath, discoveryHandler())

	// One layer of telemetry + request-id stamping wrapping every
	// route. Out of the wrapper, no in-package code touches w/r.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.NewString()
		w.Header().Set("Trollbridge-Request-Id", requestID)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			if opLog != nil {
				opLog.Debug("self-describe rejected method",
					"phase", oplog.PhaseSelfDescribe,
					"path", r.URL.Path,
					"method", r.Method,
					"request_id", requestID,
					"status", http.StatusMethodNotAllowed,
				)
			}
			return
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		mux.ServeHTTP(recorder, r)
		if opLog != nil {
			// Discovery fetches (#95) get an INFO-level event so an
			// operator running `trollbridge run` (no --verbose) sees
			// agent bootstrap traffic. Other self-describe assets
			// remain DEBUG-level (sibling cleanup deferred).
			if r.URL.Path == DiscoveryPath && recorder.status == http.StatusOK {
				opLog.Info("discovery fetched",
					"event", oplog.EventDiscoveryFetch,
					"phase", oplog.PhaseSelfDescribe,
					"path", r.URL.Path,
					"request_id", requestID,
					"status", recorder.status,
				)
			} else {
				opLog.Debug("self-describe served",
					"phase", oplog.PhaseSelfDescribe,
					"path", r.URL.Path,
					"request_id", requestID,
					"status", recorder.status,
				)
			}
		}
	})
}

func indexHandler(listenAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/setup" && r.URL.Path != "/setup/" {
			notFound(w, r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `# trollbridge self-describe

Listening on: %s

Endpoints (GET only):

- /setup/proxied-agent.md  — system-prompt fragment for proxied agents
- /setup/instructions.md   — client-setup guide
- /setup/env               — shell `+"`export`"+` lines for HTTP_PROXY / HTTPS_PROXY / NO_PROXY
- /setup/ca.crt            — CA certificate (PEM); 404 if TLS interception is disabled
- /discovery               — JSON description of the wire protocol (status codes, headers, body shapes)
`, listenAddr)
	}
}

func staticHandler(body []byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

func envHandler(listenAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		proxyURL := "http://" + listenAddr
		fmt.Fprintf(w, "export HTTP_PROXY=%s\n", proxyURL)
		fmt.Fprintf(w, "export HTTPS_PROXY=%s\n", proxyURL)
		fmt.Fprintf(w, "export http_proxy=%s\n", proxyURL)
		fmt.Fprintf(w, "export https_proxy=%s\n", proxyURL)
		fmt.Fprintln(w, `unset NO_PROXY no_proxy`)
	}
}

func caHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := caCertPath(cfg)
		if path == "" {
			caUnavailable(w, "TLS interception is not configured on this proxy")
			return
		}
		body, err := os.ReadFile(path)
		if err != nil || len(body) == 0 {
			caUnavailable(w, "TLS interception is not enabled on this proxy")
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

func caCertPath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Interception.CA.CertPath)
}

func caUnavailable(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintln(w, reason)
}

func notFound(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, "no self-describe asset at %s\n", path)
	fmt.Fprintln(w, "valid paths: /setup, /setup/proxied-agent.md, /setup/instructions.md, /setup/env, /setup/ca.crt, /discovery")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
