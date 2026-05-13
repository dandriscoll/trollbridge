package updater

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

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

	var out bytes.Buffer
	if err := Run(&out, &out); err != nil {
		t.Fatalf("installer pipeline failed against local stub: err=%v output=%q", err, out.String())
	}
	if !strings.Contains(out.String(), "ok") {
		t.Errorf("install stub did not run to completion; got: %q", out.String())
	}
	if strings.Contains(out.String(), "bash_required") {
		t.Errorf("bash bootstrap fell through to the bash_required branch; pipeline is not piping to bash; got: %q", out.String())
	}
}

// TestPipeline_PipesToBash pins the load-bearing fix for #94 at the
// string level — even on hosts where the subprocess test is skipped,
// any reversion to `| sh` fails this test.
func TestPipeline_PipesToBash(t *testing.T) {
	got := Pipeline()
	if !strings.HasSuffix(got, "| bash") {
		t.Errorf("Pipeline() must end in `| bash` (closes #94); got: %q", got)
	}
	if strings.HasSuffix(got, "| sh") {
		t.Errorf("Pipeline() must not pipe to `sh`: install.sh's bash bootstrap aborts under dash with exit 126; got: %q", got)
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
