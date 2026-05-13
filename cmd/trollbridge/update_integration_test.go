//go:build e2e

// Opt-in integration test: exercise `trollbridge update` against the
// real trollbridge.dev/install.sh. Closes #109.
//
// Gated on TROLLBRIDGE_INTEGRATION=1 so it runs only on demand
// (manually or in a separate CI lane that has network egress and
// accepts the time/cost). Skips otherwise.
//
// What it catches: drift in install.sh's URL, protocol, tarball
// naming, or signature verification — none of which the in-process
// pipeline tests can see, because those tests serve a stub from a
// local httptest server.
//
// Side effects: writes a fresh binary into a tempdir via
// TROLLBRIDGE_INSTALL_DIR, leaving the operator's $PATH binary
// untouched. Reads the network. Takes ~10-20s on a typical link.
//
// Run with:
//
//	TROLLBRIDGE_INTEGRATION=1 go test -tags=e2e \
//	    -run TestE2E_UpdateAgainstRealInstallSh ./cmd/trollbridge/...

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestE2E_UpdateAgainstRealInstallSh(t *testing.T) {
	if os.Getenv("TROLLBRIDGE_INTEGRATION") != "1" {
		t.Skip("set TROLLBRIDGE_INTEGRATION=1 to opt in to network-bound install.sh integration")
	}
	if runtime.GOOS == "windows" {
		t.Skip("update path is not used on Windows; install.sh is unix-only")
	}
	for _, bin := range []string{"bash", "curl", "sh", "tar"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("integration test requires %q on PATH; not found", bin)
		}
	}

	// Isolated install destination — the real installer would
	// otherwise write into ~/.local/bin or /usr/local/bin and
	// clobber the operator's binary.
	dir := t.TempDir()
	installDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", installDir, err)
	}
	t.Setenv("TROLLBRIDGE_INSTALL_DIR", installDir)

	// Run `trollbridge update` directly via the binary built by
	// TestMain — this exercises the wired CLI end-to-end (curl
	// fetches install.sh, install.sh resolves the right tarball
	// for the host arch, verifies SHA256, extracts, and writes
	// the binary into TROLLBRIDGE_INSTALL_DIR).
	cmd := exec.Command(e2eBinary, "update")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"TROLLBRIDGE_INSTALL_DIR="+installDir,
	)
	// Be generous on integration latency: SHA verification + tarball
	// download + extract on a slow link can run a while.
	timer := time.AfterFunc(60*time.Second, func() {
		_ = cmd.Process.Kill()
	})
	defer timer.Stop()
	if err := cmd.Run(); err != nil {
		t.Fatalf("`trollbridge update` against real install.sh failed: %v", err)
	}

	// Verify the installed binary exists, is executable, and reports
	// a version that looks like a release tag.
	installed := filepath.Join(installDir, "trollbridge")
	info, err := os.Stat(installed)
	if err != nil {
		t.Fatalf("stat %s: %v", installed, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("installed binary is not executable; mode=%o", info.Mode())
	}
	out, err := exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("%s version: %v\n%s", installed, err, out)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		t.Errorf("`trollbridge version` produced no output")
	}
	// Sanity: every release tag we cut starts with "trollbridge" and
	// contains a digit. Don't pin the exact format — tests should
	// not have to chase version-string formatting churn.
	if !strings.Contains(v, "trollbridge") {
		t.Errorf("version output does not contain 'trollbridge'; got: %q", v)
	}
	hasDigit := false
	for _, ch := range v {
		if ch >= '0' && ch <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		t.Errorf("version output has no digit; got: %q (likely install.sh drift)", v)
	}
}
