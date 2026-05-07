// Package controlclient is the small HTTP client the CLI subcommands
// use to talk to the running daemon's control API (`/v1/holds`,
// `/v1/sessions`, etc.). It centralises the request shape so the
// approve/deny CLI commands and the new TUI share one client surface.
package controlclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	url := fmt.Sprintf("http://%s%s", cfg.Approvals.ControlListen, path)
	httpClient := &http.Client{Timeout: requestTimeout}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, string(body))
	}
	return io.ReadAll(resp.Body)
}

// HoldAction POSTs an approve or deny against /v1/holds/<id>/<action>.
// `action` must be "approve" or "deny". On 404 it returns
// ErrHoldNotFound; other non-2xx responses become formatted errors.
// On success returns the response body.
func HoldAction(cfg *config.Config, id, action, scope, reason string) ([]byte, error) {
	url := fmt.Sprintf("http://%s/v1/holds/%s/%s", cfg.Approvals.ControlListen, id, action)
	body, _ := json.Marshal(map[string]string{"scope": scope, "reason": reason})
	httpClient := &http.Client{Timeout: requestTimeout}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
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
