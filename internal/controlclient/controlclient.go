// Package controlclient is the small HTTPS client the CLI subcommands
// use to talk to the running daemon's control API. The control plane
// is mTLS-locked; this client loads the operator's client cert + key
// from disk (or env-var-overridden paths) and chains against the
// daemon's CA cert. Used by approve/deny/decisions/sessions/tui.
package controlclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dandriscoll/drawbridge/internal/config"
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

// controllerURL builds the daemon URL using the configured adapter
// + control port. Always https — the controller is mTLS-only.
func controllerURL(cfg *config.Config, path string) string {
	host := cfg.BindHost()
	if host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	return "https://" + host + ":" + strconv.Itoa(cfg.Ports.Control) + path
}

// httpsClient returns an http.Client configured with the operator's
// client cert + the daemon's CA. Cert and CA paths come from env
// vars (DRAWBRIDGE_CONTROLLER_CERT / _KEY / _CA) or, when unset, the
// default locations (~/.drawbridge/controller-client.{crt,key} +
// the CA cert path from the config's interception block).
func httpsClient(cfg *config.Config) (*http.Client, error) {
	certPath, keyPath, caPath, err := resolveCertPaths(cfg)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load operator cert (%s + %s): %w; fix: drawbridge ca client-cert <name>", certPath, keyPath, err)
	}
	pool, err := loadCAPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("load drawbridge CA (%s): %w; fix: drawbridge ca init", caPath, err)
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
	cert = os.Getenv("DRAWBRIDGE_CONTROLLER_CERT")
	key = os.Getenv("DRAWBRIDGE_CONTROLLER_KEY")
	ca = os.Getenv("DRAWBRIDGE_CONTROLLER_CA")
	if cert == "" || key == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", "", "", fmt.Errorf("locate operator cert: %w", herr)
		}
		base := filepath.Join(home, ".drawbridge")
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
		return "", "", "", fmt.Errorf("drawbridge CA cert path unknown; set interception.ca.cert_path or DRAWBRIDGE_CONTROLLER_CA")
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
