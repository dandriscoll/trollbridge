package updater

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The subprocess test matrix for issue #205. Each case drives the REAL
// RunWithPrefix pipeline (httptest + real `bash`), not the Run override,
// so it exercises the same runtime an operator hits. Assertions
// distinguish operational FailureClasses (network / bash_missing /
// permission_denied / cannot_execute) from the catch-all FailureUnknown
// ("unexpected") — the issue's load-bearing requirement.

// operationalClasses is the set of FailureClasses that carry an
// actionable operator hint. Anything outside it (FailureUnknown) is an
// "unexpected" failure with only the generic report-this hint.
var operationalClasses = map[FailureClass]struct{}{
	FailureNetwork:           {},
	FailureBashMissing:       {},
	FailurePermissionDenied:  {},
	FailureSignatureMismatch: {},
	FailureCannotExecute:     {},
}

// assertOperational fails the test if err is not an *Error whose Class
// is operational (i.e. not FailureUnknown). want pins the exact class.
func assertOperational(t *testing.T, err error, want FailureClass) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an operational %q failure; got nil", want)
	}
	var ue *Error
	if !errors.As(err, &ue) {
		t.Fatalf("expected *updater.Error; got %T: %v", err, err)
	}
	if _, ok := operationalClasses[ue.Class]; !ok {
		t.Errorf("class = %q is not operational (looks like an unexpected/unknown failure); want %q", ue.Class, want)
	}
	if ue.Class != want {
		t.Errorf("class = %q, want %q", ue.Class, want)
	}
}

// serveStub stands up an httptest server returning script, points URL at
// it, and pins PinnedSHA256 to the stub's hash so the verify step passes.
// Returns a cleanup func.
func serveStub(t *testing.T, script []byte) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(script)
	}))
	prevURL, prevPin := URL, PinnedSHA256
	URL = srv.URL
	PinnedSHA256 = sha256hex(script)
	return func() {
		URL, PinnedSHA256 = prevURL, prevPin
		srv.Close()
	}
}

func skipIfNoUnixTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("update path is unix-only; not exercised on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH; cannot exercise the pipeline")
	}
}

// TestRunWithPrefix_TmpdirHonored: the verified installer is written
// under $TMPDIR and run by reading it with `bash <file>` (the property
// that makes a noexec /tmp survivable). Privilege-free.
func TestRunWithPrefix_TmpdirHonored(t *testing.T) {
	skipIfNoUnixTools(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// The stub prints its own path ($0) — i.e. the verified installer's
	// temp path. We assert it lives under the TMPDIR we set.
	cleanup := serveStub(t, []byte("#!/usr/bin/env bash\necho \"PATH0=$0\"\n"))
	defer cleanup()

	var out bytes.Buffer
	if err := RunWithPrefix(&out, &out, ""); err != nil {
		t.Fatalf("pipeline failed under custom TMPDIR: %v (out=%q)", err, out.String())
	}
	line := out.String()
	idx := strings.Index(line, "PATH0=")
	if idx < 0 {
		t.Fatalf("stub did not run / print its path; out=%q", line)
	}
	got := strings.TrimSpace(line[idx+len("PATH0="):])
	// Resolve symlinks on both sides (macOS /tmp -> /private/tmp).
	gotDir, _ := filepath.EvalSymlinks(filepath.Dir(got))
	wantDir, _ := filepath.EvalSymlinks(tmp)
	if gotDir != wantDir {
		t.Errorf("verified installer was written to %q (dir %q); want it under TMPDIR %q", got, gotDir, wantDir)
	}
}

// TestRun_BashMissing_ClassifiedOperational: when `bash` is not on PATH,
// the pipeline must surface the operational FailureBashMissing, not the
// generic FailureUnknown. Pre-fix this returned FailureUnknown because
// exec.Command("bash", …) yields *exec.Error (not *exec.ExitError) with
// empty stderr, matching no ClassifyError branch.
func TestRun_BashMissing_ClassifiedOperational(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("update path is unix-only")
	}
	// An empty PATH makes exec.Command("bash", …) fail to resolve bash.
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)
	cleanup := serveStub(t, []byte("#!/usr/bin/env bash\necho ok\n"))
	defer cleanup()

	var out bytes.Buffer
	err := RunWithPrefix(&out, &out, "")
	assertOperational(t, err, FailureBashMissing)
}

// TestRunWithPrefix_PrefixHonoredEndToEnd: the operator's --prefix
// reaches install.sh as TROLLBRIDGE_INSTALL_DIR, observed from INSIDE
// the child process.
func TestRunWithPrefix_PrefixHonoredEndToEnd(t *testing.T) {
	skipIfNoUnixTools(t)
	cleanup := serveStub(t, []byte("#!/usr/bin/env bash\necho \"DIR=$TROLLBRIDGE_INSTALL_DIR\"\n"))
	defer cleanup()

	prefix := filepath.Join(t.TempDir(), "operator-chosen-bin")
	var out bytes.Buffer
	if err := RunWithPrefix(&out, &out, prefix); err != nil {
		t.Fatalf("pipeline failed: %v (out=%q)", err, out.String())
	}
	if !strings.Contains(out.String(), "DIR="+prefix) {
		t.Errorf("install.sh did not see TROLLBRIDGE_INSTALL_DIR=%q; out=%q", prefix, out.String())
	}
}

// TestRun_Download404_ClassifiedOperational: a 404 on install.sh is an
// operational network/availability failure, not FailureUnknown, and
// nothing is executed.
func TestRun_Download404_ClassifiedOperational(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	prevURL := URL
	URL = srv.URL
	defer func() { URL = prevURL }()

	var out bytes.Buffer
	err := RunWithPrefix(&out, &out, "")
	assertOperational(t, err, FailureNetwork)
}

// TestRun_DownloadTimeout_ClassifiedOperational: a download that exceeds
// the fetch timeout is operational (FailureNetwork). Uses the
// fetchTimeout seam so the test is fast.
func TestRun_DownloadTimeout_ClassifiedOperational(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block // hang past the client timeout
	}))
	defer srv.Close()
	defer close(block)

	prevURL, prevTO := URL, fetchTimeout
	URL = srv.URL
	fetchTimeout = 150 * time.Millisecond
	defer func() { URL, fetchTimeout = prevURL, prevTO }()

	var out bytes.Buffer
	err := RunWithPrefix(&out, &out, "")
	assertOperational(t, err, FailureNetwork)
}
