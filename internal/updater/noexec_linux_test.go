//go:build linux

package updater

import (
	"bytes"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// TestRunWithPrefix_NoexecTmpdirSurvives is the deployment-contract test
// for the noexec-TMPDIR property (#205, the #94 lineage): the updater
// runs the verified installer with `bash <file>` precisely so it
// survives a /tmp mounted noexec — bash READS the file, no exec bit
// needed. This test mounts a real noexec tmpfs, points $TMPDIR at it,
// and asserts the pipeline SUCCEEDS.
//
// Mounting requires CAP_SYS_ADMIN; the unprivileged developer/CI sandbox
// cannot do it, so the test SKIPS (recorded) when euid != 0. It runs in
// a root CI lane — the gate per GO.md's "exercise the runtime or record
// the follow-up" rule. Build-tagged linux so the three-OS workflow still
// compiles on Windows/macOS.
func TestRunWithPrefix_NoexecTmpdirSurvives(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("noexec mount needs root (CAP_SYS_ADMIN); recorded as a privileged/CI-only contract test")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	dir := t.TempDir()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOEXEC, ""); err != nil {
		t.Skipf("could not mount noexec tmpfs at %s: %v", dir, err)
	}
	defer func() { _ = syscall.Unmount(dir, 0) }()
	t.Setenv("TMPDIR", dir)

	// A direct exec of a file on this mount would fail with EACCES; the
	// updater must instead read it via bash and succeed.
	cleanup := serveStub(t, []byte("#!/usr/bin/env bash\necho ok\n"))
	defer cleanup()

	var out bytes.Buffer
	if err := RunWithPrefix(&out, &out, ""); err != nil {
		t.Fatalf("pipeline failed on a noexec TMPDIR; the `bash <file>` read path should survive it: %v (out=%q)", err, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("ok")) {
		t.Errorf("stub did not run to completion on noexec TMPDIR; out=%q", out.String())
	}
}
