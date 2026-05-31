package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// sha256hex returns the lowercase-hex SHA-256 of b — the form
// PinnedSHA256 uses. Tests set the pin to a served stub's hash so the
// verify step passes; or to a different value to exercise rejection.
func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestRun_AcceptsInstallShBashBootstrap exercises the real shell pipeline
// against a local server serving install.sh's load-bearing bootstrap
// shape. Before #94 was fixed, Pipeline() piped to `sh` and this exact
// shape made install.sh's `exec bash "$0" "$@"` line abort with exit
// 126 on dash hosts. The test asserts the stub runs end-to-end.
func TestRun_AcceptsInstallShBashBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		// `update` short-circuits to the manual-download branch on
		// Windows before Run is invoked (see cmd/trollbridge/update.go);
		// the pipeline is unix-only by design and `sh` is not on PATH
		// on default windows-latest runners.
		t.Skip("update path is not used on Windows; pipeline is unix-only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH; cannot exercise install.sh's bash-bootstrap branch")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not on PATH; pipeline cannot run")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH; pipeline cannot run")
	}

	stub := []byte(`#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@" 2>/dev/null || { echo bash_required >&2; exit 1; }
fi
echo ok
`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(stub)
	}))
	defer srv.Close()

	prev := URL
	URL = srv.URL
	defer func() { URL = prev }()
	// The verify step refuses to run a script whose hash does not match
	// the pin; point the pin at the stub's hash so
	// the happy-path bash-bootstrap behavior is exercised.
	prevPin := PinnedSHA256
	PinnedSHA256 = sha256hex(stub)
	defer func() { PinnedSHA256 = prevPin }()

	var out bytes.Buffer
	if err := Run(&out, &out); err != nil {
		t.Fatalf("installer pipeline failed against local stub: err=%v output=%q", err, out.String())
	}
	if !strings.Contains(out.String(), "ok") {
		t.Errorf("install stub did not run to completion; got: %q", out.String())
	}
	if strings.Contains(out.String(), "bash_required") {
		t.Errorf("bash bootstrap fell through to the bash_required branch; installer is not run under bash; got: %q", out.String())
	}
}

// TestRun_RejectsTamperedScript is the load-bearing verify guard:
// when the downloaded install.sh does NOT match the pinned
// SHA-256, Run must return FailureSignatureMismatch and execute NOTHING.
// The served stub writes a marker file if it runs; the test asserts the
// marker never appears. Reverting the verify branch makes the marker
// appear (the script runs) — the negative check that proves this test
// guards the mechanism, not a coincidence.
func TestRun_RejectsTamperedScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("update path is not used on Windows; pipeline is unix-only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}

	marker := t.TempDir() + "/ran"
	stub := []byte("#!/usr/bin/env bash\ntouch " + marker + "\necho ran\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(stub)
	}))
	defer srv.Close()

	prev := URL
	URL = srv.URL
	defer func() { URL = prev }()
	prevPin := PinnedSHA256
	// A pin that deliberately does NOT match the served stub.
	PinnedSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	defer func() { PinnedSHA256 = prevPin }()

	var out bytes.Buffer
	err := Run(&out, &out)
	if err == nil {
		t.Fatalf("expected a signature-mismatch failure; got nil (output=%q)", out.String())
	}
	var ue *Error
	if !errors.As(err, &ue) {
		t.Fatalf("expected *updater.Error; got %T: %v", err, err)
	}
	if ue.Class != FailureSignatureMismatch {
		t.Errorf("class = %q, want %q", ue.Class, FailureSignatureMismatch)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Errorf("install.sh ran despite the checksum mismatch — the verify gate did not stop execution")
	}
}

// TestClassifyError_Cases covers each FailureClass branch with
// representative captured-stderr substrings. Closes #102 part 1.
func TestClassifyError_Cases(t *testing.T) {
	cases := []struct {
		name      string
		stderr    string
		wantClass FailureClass
		hintHas   string
	}{
		{"bash missing", "bash_required", FailureBashMissing, "install `bash`"},
		{"sha mismatch", "sha256_mismatch on …", FailureSignatureMismatch, "github.com/dandriscoll/trollbridge/issues"},
		{"permission denied", "/usr/local/bin: Permission denied", FailurePermissionDenied, "TROLLBRIDGE_INSTALL_DIR"},
		{"curl resolve", "curl: (6) Could not resolve host: trollbridge.dev", FailureNetwork, "curl -v"},
		{"curl timeout", "curl: (28) Operation timed out after …", FailureNetwork, "curl -v"},
		{"curl http error", "curl: (22) The requested URL returned 404", FailureNetwork, "curl -v"},
		{"unknown", "something weird happened", FailureUnknown, "report at"},
		{"empty stderr", "", FailureUnknown, "report at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, hint := ClassifyError(nil, tc.stderr)
			if class != tc.wantClass {
				t.Errorf("class = %q, want %q", class, tc.wantClass)
			}
			if !strings.Contains(hint, tc.hintHas) {
				t.Errorf("hint = %q, want substring %q", hint, tc.hintHas)
			}
		})
	}
}

// TestClassifyError_ExitCode126_EmptyStderr locks the recurrence-driven
// fix from job 163: when the install pipeline exits 126 with no
// recognizable stderr, the classifier must return FailureCannotExecute
// and a hint that names the three concrete operator next-actions.
// Closes #94 (reactivation).
func TestClassifyError_ExitCode126_EmptyStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("update pipeline is unix-only; no /bin/sh on default windows runners")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH; cannot synthesize an *exec.ExitError")
	}
	exitErr := exec.Command("sh", "-c", "exit 126").Run()
	if exitErr == nil {
		t.Fatal("expected *exec.ExitError from `sh -c 'exit 126'`; got nil")
	}
	class, hint := ClassifyError(exitErr, "")
	if class != FailureCannotExecute {
		t.Errorf("class = %q, want %q", class, FailureCannotExecute)
	}
	// Lock the three concrete next-actions into the hint without
	// brittling on exact wording.
	for _, want := range []string{"uname -m", "TMPDIR", "ls -l"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint missing %q substring; got: %q", want, hint)
		}
	}
}

// TestClassifyError_ExitCode126_HintListsAllPathMatches locks #122:
// the wrong-CPU clause must inspect every trollbridge on PATH, not
// just the first. `command -v trollbridge` resolves only the first
// match, so an operator with multiple installs gets a hint pointing
// at a binary that may not be the one that failed; `which -a` lists
// them all. The negative substring is the load-bearing assertion —
// it fails if the clause regresses to `command -v trollbridge`.
func TestClassifyError_ExitCode126_HintListsAllPathMatches(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("update pipeline is unix-only")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH; cannot synthesize an *exec.ExitError")
	}
	exitErr := exec.Command("sh", "-c", "exit 126").Run()
	if exitErr == nil {
		t.Fatal("expected *exec.ExitError from `sh -c 'exit 126'`; got nil")
	}
	_, hint := ClassifyError(exitErr, "")
	if !strings.Contains(hint, "which -a trollbridge") {
		t.Errorf("hint must tell the operator to inspect every trollbridge on PATH (`which -a trollbridge`); got: %q", hint)
	}
	if strings.Contains(hint, "command -v trollbridge") {
		t.Errorf("hint regressed to `command -v trollbridge`, which inspects only the first PATH match (#122); got: %q", hint)
	}
}

// TestClassifyError_ExitCode126_SubstringWinsForSpecificStderr locks the
// priority order: a 126 with a recognizable stderr substring keeps its
// more-specific class. Prevents a future refactor from demoting the
// substring branches behind the exit-code branch.
func TestClassifyError_ExitCode126_SubstringWinsForSpecificStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("update pipeline is unix-only")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	exitErr := exec.Command("sh", "-c", "exit 126").Run()
	if exitErr == nil {
		t.Fatal("expected *exec.ExitError; got nil")
	}
	class, _ := ClassifyError(exitErr, "/usr/local/bin: Permission denied")
	if class != FailurePermissionDenied {
		t.Errorf("class = %q, want %q (substring branch must win over exit-code branch)", class, FailurePermissionDenied)
	}
}

// TestRun_ClassifiesExitCode126 is the subprocess deployment-contract
// test for the new branch: the actual pipeline running a stub that
// exits 126 must surface FailureCannotExecute through the *updater.Error
// wrapper, not just through the in-process classifier. Mirrors
// TestRun_AcceptsInstallShBashBootstrap's runtime layer (sh + curl +
// bash) so a future regression of the classifier-wiring path is caught
// at the same grain as the original #94 fix.
func TestRun_ClassifiesExitCode126(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("update path is not used on Windows; pipeline is unix-only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not on PATH")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	stub := []byte("#!/usr/bin/env bash\nexit 126\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(stub)
	}))
	defer srv.Close()

	prev := URL
	URL = srv.URL
	defer func() { URL = prev }()
	prevPin := PinnedSHA256
	PinnedSHA256 = sha256hex(stub)
	defer func() { PinnedSHA256 = prevPin }()

	var out bytes.Buffer
	err := Run(&out, &out)
	if err == nil {
		t.Fatalf("expected pipeline to fail with exit 126; output=%q", out.String())
	}
	var ue *Error
	if !errors.As(err, &ue) {
		t.Fatalf("expected *updater.Error wrap; got %T: %v", err, err)
	}
	if ue.Class != FailureCannotExecute {
		t.Errorf("class = %q, want %q", ue.Class, FailureCannotExecute)
	}
	if !strings.Contains(ue.Hint, "exit 126") {
		t.Errorf("hint should name exit 126 explicitly; got: %q", ue.Hint)
	}
}

// TestCheckLatest_ParsesTagFromRedirect drives CheckLatest against a
// local httptest server that mimics the GitHub `/releases/latest` →
// `/releases/tag/<TAG>` redirect chain. Closes #102 part 2.
func TestCheckLatest_ParsesTagFromRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/v9.9.9", http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/v9.9.9", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := LatestReleaseURL
	LatestReleaseURL = srv.URL + "/releases/latest"
	defer func() { LatestReleaseURL = prev }()

	got, err := CheckLatest()
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if got != "v9.9.9" {
		t.Errorf("got tag = %q, want %q", got, "v9.9.9")
	}
}

// TestCheckLatest_NoTagInRedirect surfaces the failure mode when
// the upstream stops following the /releases/tag/<TAG> shape.
func TestCheckLatest_NoTagInRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/somewhere/else", http.StatusFound)
	})
	mux.HandleFunc("/somewhere/else", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	prev := LatestReleaseURL
	LatestReleaseURL = srv.URL + "/releases/latest"
	defer func() { LatestReleaseURL = prev }()

	_, err := CheckLatest()
	if err == nil {
		t.Fatal("expected error for non-/releases/tag/ redirect; got nil")
	}
	if !strings.Contains(err.Error(), "/releases/tag/") {
		t.Errorf("error message should name the missing /releases/tag/ shape; got: %v", err)
	}
}
