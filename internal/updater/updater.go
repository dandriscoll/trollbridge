// Package updater shells out to trollbridge.dev/install.sh to upgrade
// the local trollbridge binary in place. The CLI's `update` subcommand
// and the TUI console's `update` line both call Run.
package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// PinnedSHA256 is the expected SHA-256 (lowercase hex) of install.sh.
// The updater refuses to execute a downloaded install.sh whose hash does
// not match the pin, so a compromise of the install.sh delivery path
// cannot cause `trollbridge update` to run an unverified script.
//
// It is a var (not a const) to match this file's test-seam convention
// (URL, Run, LatestReleaseURL are all overridable vars).
//
// install.sh lives in the trollbridge-deploy repo and is deployed to
// trollbridge.dev independently of trollbridge releases, so this value
// is RECOMPUTED BY scripts/release.sh at each release. If install.sh
// changes without a matching trollbridge release, existing binaries will
// see a mismatch on `trollbridge update`; the FailureSignatureMismatch
// hint tells the operator to reinstall manually (which self-verifies the
// binary against the release SHA256SUMS).
var PinnedSHA256 = "6d83e9dd36ab72341a6ccfbfaa1c124b60fccb8f73c5b6fe9ac4bbd3aac040b0"

// Describe returns a human-facing one-liner of what an update does, for
// display in the CLI/console before Run executes. It replaces the old
// Pipeline() string now that the flow downloads-and-verifies rather than
// piping curl straight to bash.
func Describe() string {
	return "fetch + verify " + URL + " (sha256), then run it under bash"
}

// fetchTimeout bounds the install.sh download. A var (not a const) so a
// timeout test can lower it without waiting the production 30 s, matching
// this file's test-seam convention (URL, Run, PinnedSHA256 are vars).
var fetchTimeout = 30 * time.Second

// fetchInstallScript downloads install.sh from URL. Split out so the
// download path is exercised by tests via an httptest server.
func fetchInstallScript(url string) ([]byte, error) {
	c := &http.Client{Timeout: fetchTimeout}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
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
	// 1. Download install.sh. A failed download — DNS, refused
	//    connection, client timeout, or a non-2xx status such as 404 —
	//    is an operational network/availability failure, not an
	//    "unexpected" one: classify it directly as FailureNetwork (the
	//    call site knows this is the download step) rather than routing
	//    Go's http error text through ClassifyError's curl-shaped
	//    substring branches, which it would not match (→ FailureUnknown).
	//    Nothing is executed.
	body, err := fetchInstallScript(URL)
	if err != nil {
		return &Error{
			Underlying: err,
			Class:      FailureNetwork,
			Hint: "could not download " + URL + " (" + err.Error() + "). " +
				"Check network reachability with `curl -v " + URL + "` and re-run " +
				"`trollbridge update`; if it persists the install host may be down.",
		}
	}
	// 2. Verify the SHA-256 against the pin BEFORE writing or executing
	//    anything. On mismatch, execute nothing.
	got := hex.EncodeToString(sha256Sum(body))
	if !strings.EqualFold(got, PinnedSHA256) {
		_, hint := ClassifyError(nil, "signature mismatch")
		return &Error{
			Underlying: fmt.Errorf("install.sh sha256 %s does not match pinned %s", got, PinnedSHA256),
			Class:      FailureSignatureMismatch,
			Hint:       hint,
		}
	}
	// 3. Write the verified bytes to a temp file and run it under bash.
	//    Running bash against a file (rather than `curl … | bash`)
	//    guarantees install.sh's `exec bash "$0"` bootstrap is a no-op
	//    (closes #94) and survives a noexec /tmp (bash reads the file;
	//    no exec bit needed).
	f, err := os.CreateTemp("", "trollbridge-install-*.sh")
	if err != nil {
		return &Error{Underlying: err, Class: FailureUnknown, Hint: "could not create a temp file for the verified installer; check TMPDIR is writable"}
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)
	if _, err := f.Write(body); err != nil {
		f.Close()
		return &Error{Underlying: err, Class: FailureUnknown, Hint: "could not write the verified installer to a temp file; check disk/TMPDIR"}
	}
	if err := f.Chmod(0o700); err != nil {
		f.Close()
		return &Error{Underlying: err, Class: FailureUnknown, Hint: "could not chmod the verified installer temp file"}
	}
	if err := f.Close(); err != nil {
		return &Error{Underlying: err, Class: FailureUnknown, Hint: "could not finalize the verified installer temp file"}
	}

	c := exec.Command("bash", tmpPath)
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
	if err := c.Run(); err != nil {
		class, hint := ClassifyError(err, stderrBuf.String())
		return &Error{Underlying: err, Class: class, Hint: hint}
	}
	return nil
}

// sha256Sum returns the SHA-256 of b as a byte slice. Split out for
// readability at the call site.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
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
	FailureCannotExecute     FailureClass = "cannot_execute"
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
//
// Substring branches come first because they carry the most specific
// diagnostic. The exit-code-126 branch follows as a fallback for the
// "command found but cannot be executed" class (closes #94 reactivation,
// job 163) — the original #94 fix addressed one specific 126 cause
// (dash-bootstrap interpreting the dash binary as a bash script);
// recurrence surfaced that 126 has several plausible shapes, and the
// classifier needs to give the operator a useful triage hint for any
// of them when no stderr substring matches.
func ClassifyError(err error, capturedStderr string) (FailureClass, string) {
	se := strings.ToLower(capturedStderr)
	// `bash` genuinely absent from PATH: exec.Command("bash", …) fails to
	// resolve before the script runs, yielding an *exec.Error
	// (errors.Is(err, exec.ErrNotFound)) with empty stderr — none of the
	// stderr-substring branches below would fire, so without this the
	// failure misclassifies as FailureUnknown. The only program the
	// updater execs is bash, so ErrNotFound unambiguously means bash is
	// missing. errors.Is is robust to the exact message wording.
	if errors.Is(err, exec.ErrNotFound) ||
		strings.Contains(se, "bash_required") || strings.Contains(se, "bash: not found") {
		return FailureBashMissing, "install `bash` (apt/brew/dnf) and re-run `trollbridge update`"
	}
	if strings.Contains(se, "sha256_mismatch") || strings.Contains(se, "signature mismatch") {
		return FailureSignatureMismatch, "install.sh did not match the pinned checksum, so nothing was run. " +
			"If install.sh was changed recently this may be a stale pin: reinstall manually with " +
			"`curl -fsSL https://trollbridge.dev/install.sh | bash` (the script self-verifies the binary). " +
			"Otherwise this may be tampering — report at https://github.com/dandriscoll/trollbridge/issues"
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
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 126 {
		return FailureCannotExecute, "exit 126 means a command in the install pipeline could not be executed. " +
			"Common causes: (1) the installed trollbridge binary is for the wrong CPU — " +
			"run `file $(which -a trollbridge)` and compare to `uname -m` " +
			"(`which -a` lists every trollbridge on PATH, not just the first); " +
			"(2) /tmp is mounted noexec — re-run with `TMPDIR=$HOME/.cache trollbridge update`; " +
			"(3) `bash` is on PATH but not executable — `ls -l $(command -v bash)`. " +
			"If none apply, report at https://github.com/dandriscoll/trollbridge/issues with the full output."
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
