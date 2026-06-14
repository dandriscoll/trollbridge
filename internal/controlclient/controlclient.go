// Package controlclient is the small HTTPS client the CLI subcommands
// use to talk to the running daemon's control API. The control plane
// is mTLS-locked; this client loads the operator's client cert + key
// from disk (or env-var-overridden paths) and chains against the
// daemon's CA cert. Used by approve/deny/decisions/sessions/attach.
package controlclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dandriscoll/trollbridge/internal/config"
)

// ErrHoldNotFound is returned when the server responds 404 to a
// /v1/holds/<id>/<action> POST. Callers can inspect via errors.Is.
var ErrHoldNotFound = errors.New("hold not found")

const requestTimeout = 5 * time.Second

// Get performs a GET against the daemon's control API and returns the
// response body. Non-2xx responses become errors.
func Get(cfg *config.Config, path string) ([]byte, error) {
	url := controllerURL(cfg, path)
	cli, err := httpsClient(cfg)
	if err != nil {
		return nil, err
	}
	resp, err := cli.Get(url)
	if err != nil {
		return nil, fmt.Errorf("control API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, string(body))
	}
	return io.ReadAll(resp.Body)
}

// Post sends an empty-body POST to the daemon's control API. Used
// for endpoints whose action is encoded in the path (rules/reload,
// ca/flush-cache).
func Post(cfg *config.Config, path string, body []byte) ([]byte, error) {
	url := controllerURL(cfg, path)
	cli, err := httpsClient(cfg)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control API: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("control API: %s: %s", resp.Status, string(respBody))
	}
	return respBody, nil
}

// ListEdit performs an add or remove on the daemon's allow/deny
// list via /v1/lists/<list> (#189 — attach-mode list editing).
// method must be http.MethodPost (add) or http.MethodDelete
// (remove). list must be "allow" or "deny". Body sends a JSON
// {"pattern": pattern} payload. Returns (changed, err) — changed
// true when the daemon's YAML was mutated.
func ListEdit(cfg *config.Config, method, list, pattern string) (bool, error) {
	url := controllerURL(cfg, "/v1/lists/"+list)
	body, _ := json.Marshal(map[string]string{"pattern": pattern})
	cli, err := httpsClient(cfg)
	if err != nil {
		return false, err
	}
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return false, fmt.Errorf("control API: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("control API: %s: %s", resp.Status, string(respBody))
	}
	var out struct {
		Changed bool `json:"changed"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return false, fmt.Errorf("control API: decode response: %w", err)
	}
	return out.Changed, nil
}

// OpenMode drives /v1/open (#209): method GET reports state, POST
// opens/extends the window, DELETE closes it. All three return the
// resulting (active, until). The daemon returns 404 when open mode is
// not configured; that surfaces as a formatted error.
func OpenMode(cfg *config.Config, method string) (active bool, until time.Time, err error) {
	url := controllerURL(cfg, "/v1/open")
	cli, cerr := httpsClient(cfg)
	if cerr != nil {
		return false, time.Time{}, cerr
	}
	req, _ := http.NewRequest(method, url, nil)
	resp, derr := cli.Do(req)
	if derr != nil {
		return false, time.Time{}, fmt.Errorf("control API: %w", derr)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return false, time.Time{}, fmt.Errorf("control API: %s: %s", resp.Status, string(respBody))
	}
	var out struct {
		Active bool      `json:"active"`
		Until  time.Time `json:"until"`
	}
	if uerr := json.Unmarshal(respBody, &out); uerr != nil {
		return false, time.Time{}, fmt.Errorf("control API: decode response: %w", uerr)
	}
	return out.Active, out.Until, nil
}

// HoldAction POSTs an approve or deny against /v1/holds/<id>/<action>.
// `action` must be "approve" or "deny". On 404 it returns
// ErrHoldNotFound; other non-2xx responses become formatted errors.
// On success returns the response body.
func HoldAction(cfg *config.Config, id, action, scope, reason string) ([]byte, error) {
	url := controllerURL(cfg, "/v1/holds/"+id+"/"+action)
	body, _ := json.Marshal(map[string]string{"scope": scope, "reason": reason})
	cli, err := httpsClient(cfg)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control API: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrHoldNotFound, id)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("control API: %s: %s", resp.Status, string(respBody))
	}
	return respBody, nil
}

// controllerURL builds the daemon URL using the configured control
// bind. Always https — the controller is mTLS-only.
func controllerURL(cfg *config.Config, path string) string {
	return "https://" + cfg.Control.ClientAddr() + path
}

// Preflight tries to construct the mTLS client without sending a
// request — it loads the operator cert + key and the trollbridge
// CA, returning the same error httpsClient would return on the
// first real call. Used by `trollbridge attach` to fail loudly to
// stderr *before* the TUI takes over the screen, so the operator
// is not stuck reading a truncated footer line (#46).
func Preflight(cfg *config.Config) error {
	_, err := httpsClient(cfg)
	return err
}

// CertPaths returns the operator-cert / key / CA paths the client
// would use, applying the same env-var-then-default resolution as
// httpsClient. Returned for diagnostic messages only — callers
// must not load files directly; use Preflight to validate.
func CertPaths(cfg *config.Config) (cert, key, ca string, err error) {
	return resolveCertPaths(cfg)
}

// httpsClient returns an http.Client configured with the operator's
// client cert + the daemon's CA. Cert and CA paths come from env
// vars (TROLLBRIDGE_CONTROLLER_CERT / _KEY / _CA) or, when unset, the
// default locations (~/.trollbridge/controller-client.{crt,key} +
// the CA cert path from the config's interception block).
func httpsClient(cfg *config.Config) (*http.Client, error) {
	certPath, keyPath, caPath, err := resolveCertPaths(cfg)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load operator cert (%s + %s): %w; fix: trollbridge ca client-cert <name>", certPath, keyPath, err)
	}
	pool, err := loadCAPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("load trollbridge CA (%s): %w; fix: trollbridge ca init", caPath, err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS12,
		},
	}
	return &http.Client{Transport: tr, Timeout: requestTimeout}, nil
}

func resolveCertPaths(cfg *config.Config) (cert, key, ca string, err error) {
	cert = os.Getenv("TROLLBRIDGE_CONTROLLER_CERT")
	key = os.Getenv("TROLLBRIDGE_CONTROLLER_KEY")
	ca = os.Getenv("TROLLBRIDGE_CONTROLLER_CA")
	if cert == "" || key == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", "", "", fmt.Errorf("locate operator cert: %w", herr)
		}
		base := filepath.Join(home, ".trollbridge")
		if cert == "" {
			cert = filepath.Join(base, "controller-client.crt")
		}
		if key == "" {
			key = filepath.Join(base, "controller-client.key")
		}
	}
	if ca == "" {
		ca = cfg.Interception.CA.CertPath
	}
	if ca == "" {
		return "", "", "", fmt.Errorf("trollbridge CA cert path unknown; set interception.ca.cert_path or TROLLBRIDGE_CONTROLLER_CA")
	}
	return cert, key, ca, nil
}

func loadCAPool(caPath string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates parsed from %s", caPath)
	}
	return pool, nil
}
