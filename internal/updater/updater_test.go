package updater

import (
	"bytes"
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
