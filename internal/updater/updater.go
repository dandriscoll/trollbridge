// Package updater shells out to trollbridge.dev/install.sh to upgrade
// the local trollbridge binary in place. The CLI's `update` subcommand
// and the TUI console's `update` line both call Run.
package updater

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func osEnvironDefault() []string { return os.Environ() }

// URL is the canonical install.sh location. Tests override it to point
// at a local httptest server; production callers leave it as-is.
var URL = "https://trollbridge.dev/install.sh"

// Pipeline returns the shell pipeline fed to `sh -c`. install.sh
// auto-bootstraps under bash with `exec bash "$0" "$@"`; when piped
// from dash (/bin/sh on Debian/Ubuntu), $0 is the dash binary path and
// bash refuses to execute a binary, aborting with exit 126. Pipe to
// bash directly so the bootstrap is a no-op (closes #94).
func Pipeline() string {
	return "curl -fsSL " + URL + " | bash"
}

// Run executes the installer pipeline, streaming stdout/stderr to the
// caller's writers AND capturing stderr for failure classification.
// On non-zero exit, Run wraps the underlying error with the
// classification + actionable hint produced by ClassifyError. Tests
// replace Run with a recorder so callers can exercise their wiring
// without touching the network.
var Run = func(stdout, stderr io.Writer) error {
	return RunWithPrefix(stdout, stderr, "")
}

// RunWithPrefix is the prefix-aware variant of Run. When prefix is
// non-empty, it is forwarded to install.sh as TROLLBRIDGE_INSTALL_DIR
// so the binary lands in the operator-chosen directory rather than
// install.sh's default. Closes #108 part 1 (the in-repo half;
// install.sh's PATH-detection default is tracked in trollbridge-
// deploy).
//
// Tests can override this var directly the same way they override Run.
var RunWithPrefix = func(stdout, stderr io.Writer, prefix string) error {
	c := exec.Command("sh", "-c", Pipeline())
	c.Stdout = stdout
	var stderrBuf bytes.Buffer
	c.Stderr = io.MultiWriter(stderr, &stderrBuf)
	if prefix != "" {
		// Inherit the operator's environment so curl/bash see DNS,
		// proxy, and trust-store config; then layer the prefix.
		env := append([]string{}, osEnviron()...)
		env = append(env, "TROLLBRIDGE_INSTALL_DIR="+prefix)
		c.Env = env
	}
	err := c.Run()
	if err == nil {
		return nil
	}
	class, hint := ClassifyError(err, stderrBuf.String())
	return &Error{Underlying: err, Class: class, Hint: hint}
}

// osEnviron is split out so tests can swap the environment if
// needed. Production callers leave it at os.Environ.
var osEnviron = osEnvironDefault

// FailureClass tags update failures so callers (and tests) can
// branch without parsing stderr substrings. The set is closed; new
// classes only land alongside ClassifyError changes + tests.
type FailureClass string

const (
	FailureNetwork           FailureClass = "network"
	FailureBashMissing       FailureClass = "bash_missing"
	FailurePermissionDenied  FailureClass = "permission_denied"
	FailureSignatureMismatch FailureClass = "signature_mismatch"
	FailureUnknown           FailureClass = "unknown"
)

// Error wraps an update-pipeline failure with a structured class and
// a one-line hint naming the operator's next action. The CLI prints
// the hint above the underlying error so the operator does not have
// to read curl's output to know what to do.
type Error struct {
	Underlying error
	Class      FailureClass
	Hint       string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Class) + ": " + e.Underlying.Error() + " (hint: " + e.Hint + ")"
}

func (e *Error) Unwrap() error { return e.Underlying }

// ClassifyError inspects the pipeline error and captured stderr to
// pick a class + hint. Pure: no I/O. Closes #102 part 1.
func ClassifyError(_ error, capturedStderr string) (FailureClass, string) {
	se := strings.ToLower(capturedStderr)
	if strings.Contains(se, "bash_required") || strings.Contains(se, "bash: not found") {
		return FailureBashMissing, "install `bash` (apt/brew/dnf) and re-run `trollbridge update`"
	}
	if strings.Contains(se, "sha256_mismatch") || strings.Contains(se, "signature mismatch") {
		return FailureSignatureMismatch, "report at https://github.com/dandriscoll/trollbridge/issues with the SHA256 mismatch line"
	}
	if strings.Contains(se, "permission denied") || strings.Contains(se, "eacces") {
		return FailurePermissionDenied, "set `TROLLBRIDGE_INSTALL_DIR` to a writable directory (e.g. `~/.local/bin`) and re-run"
	}
	if strings.Contains(se, "could not resolve") ||
		strings.Contains(se, "connection refused") ||
		strings.Contains(se, "operation timed out") ||
		strings.Contains(se, "couldn't connect") ||
		strings.Contains(se, "curl: (6)") ||
		strings.Contains(se, "curl: (7)") ||
		strings.Contains(se, "curl: (22)") ||
		strings.Contains(se, "curl: (28)") {
		return FailureNetwork, "run `curl -v " + URL + "` to debug network reachability, then re-run `trollbridge update`"
	}
	return FailureUnknown, "re-run with `-v` for more output, or report at https://github.com/dandriscoll/trollbridge/issues"
}

// LatestReleaseURL is the GitHub redirect that resolves to the
// latest release tag. Tests override.
var LatestReleaseURL = "https://github.com/dandriscoll/trollbridge/releases/latest"

// CheckLatest returns the latest released version tag (e.g. "v0.7.6")
// without invoking the installer. Closes #102 part 2.
//
// HEADs LatestReleaseURL; the GitHub-side redirect resolves to
// `…/releases/tag/<TAG>`. Parses the tag off the final URL's path.
// Tests override LatestReleaseURL with an httptest server.
var CheckLatest = func() (string, error) {
	return checkLatestImpl(LatestReleaseURL)
}

func checkLatestImpl(url string) (string, error) {
	c := &http.Client{
		Timeout: 10 * time.Second,
		// Default policy follows up to 10 redirects. Don't override.
	}
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 && resp.StatusCode/100 != 3 {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	final := resp.Request.URL.String()
	// Path tail: `/releases/tag/<TAG>`. Robust to query/fragment.
	if i := strings.Index(final, "/releases/tag/"); i >= 0 {
		tag := final[i+len("/releases/tag/"):]
		if cut := strings.IndexAny(tag, "?#/"); cut >= 0 {
			tag = tag[:cut]
		}
		if tag == "" {
			return "", fmt.Errorf("empty tag in redirect %s", final)
		}
		return tag, nil
	}
	return "", fmt.Errorf("no /releases/tag/<TAG> in redirect %s", final)
}
