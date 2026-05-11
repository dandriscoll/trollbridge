//go:build linux

package tui_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestRenderPTY_BordersAppearOnRealTerminal closes the PTY-render gap
// filed across jobs 091 / 092 / 093 / 094 / 098 (per
// 100-trollbridge-tui-borders-and-daemon-mode/001-research.md history).
// On recurrence, GO.md mandates the closure rather than another file-and-defer.
//
// Mechanics: open /dev/ptmx, configure the slave, exec
// `trollbridge run` with stdin/stdout/stderr bound to the slave, read
// from the master, assert that rounded-corner box-drawing runes and
// the cyan focused-pane escape appear in the rendered output.
//
// The test is Linux-only (TIOCSPTLCK / TIOCGPTN are Linux-specific
// ioctls); macOS PTY allocation goes through grantpt/unlockpt/ptsname
// which is a separate code path. On environments where /dev/ptmx is
// unavailable (sandbox, jail, container without /dev/ptmx mount) the
// test t.Skipf — the framework remains in place; the next maintainer
// flips the gate by running where a PTY is allocatable.
func TestRenderPTY_BordersAppearOnRealTerminal(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skipf("PTY unavailable (/dev/ptmx): %v", err)
	}

	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v", err)
	}
	defer master.Close()

	// Unlock the slave side and discover its pts number.
	var unlock int32 = 0
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, master.Fd(),
		unix.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		t.Skipf("TIOCSPTLCK: %v", errno)
	}
	var ptsNum int32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, master.Fd(),
		unix.TIOCGPTN, uintptr(unsafe.Pointer(&ptsNum))); errno != 0 {
		t.Skipf("TIOCGPTN: %v", errno)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", ptsNum)
	slave, err := os.OpenFile(slavePath, os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open slave %s: %v", slavePath, err)
	}
	defer slave.Close()

	// Positive PTY round-trip check before spending time on the
	// binary build + subprocess startup. Sandboxes that expose
	// /dev/ptmx but cannot move bytes through it (issue #69) skip
	// here cleanly instead of failing late on a partial render.
	ptySmokeOrSkip(t, master, slave)

	repoRoot := findRepoRoot(t)
	binPath := filepath.Join(t.TempDir(), "trollbridge")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/trollbridge")
	build.Dir = repoRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, string(out))
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "trollbridge.yaml")
	auditPath := filepath.Join(dir, "audit.jsonl")
	proxyLn, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	_, proxyPort, _ := net.SplitHostPort(proxyAddr)

	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-deny
logging:
  audit_path: %s
approvals:
  timeout_seconds: 2
  on_timeout: deny
`, proxyPort, auditPath)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "run", "--config", cfgPath)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
	})

	// Read PTY master with an 8 s deadline; collect ~64 KB.
	if err := master.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Skipf("SetDeadline on PTY master: %v", err)
	}
	buf := make([]byte, 0, 65536)
	tmp := make([]byte, 4096)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && len(buf) < cap(buf) {
		_ = master.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := master.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		// Stop early once we have all four corners.
		s := string(buf)
		if strings.Contains(s, "╭") && strings.Contains(s, "╮") &&
			strings.Contains(s, "╰") && strings.Contains(s, "╯") {
			break
		}
	}

	out := string(buf)
	for _, want := range []string{"╭", "╮", "╰", "╯"} {
		if !strings.Contains(out, want) {
			t.Errorf("PTY render missing corner %q; %d bytes captured", want, len(buf))
		}
	}
	if !strings.Contains(out, "approvals") {
		t.Errorf("PTY render missing 'approvals' label; %d bytes captured", len(buf))
	}
	if !strings.Contains(out, "\x1b[36m") {
		t.Errorf("PTY render missing cyan focused-pane escape; %d bytes captured", len(buf))
	}
}

// ptySmokeOrSkip runs a tiny write/read round-trip on the freshly-
// allocated PTY pair to validate that the environment can actually
// move bytes through ptmx within a reasonable deadline. Some sandboxes
// expose /dev/ptmx and accept the unlock/getpt ioctls but then time
// out on the first real read or write — issue #69 is the recurrent
// failure shape. When the round-trip fails, we t.Skipf with the
// captured error so the test is a clean skip in those environments;
// CI runners with a functional PTY still exercise the test body.
//
// The smoke check writes one byte to master, reads it back from
// slave with a 500 ms deadline. Both the write and the read must
// succeed within the deadline; either failure produces a skip.
func ptySmokeOrSkip(t *testing.T, master, slave *os.File) {
	t.Helper()
	const probe byte = 'P'
	// Strict per-op deadlines on master AND slave — write goes to
	// master, slave receives.
	if err := master.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Skipf("PTY smoke: SetWriteDeadline on master: %v", err)
	}
	if _, err := master.Write([]byte{probe}); err != nil {
		t.Skipf("PTY smoke: master.Write timed out or failed (likely a non-functional ptmx in this environment): %v", err)
	}
	if err := slave.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Skipf("PTY smoke: SetReadDeadline on slave: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := slave.Read(buf); err != nil {
		t.Skipf("PTY smoke: slave.Read timed out or failed: %v", err)
	}
	if buf[0] != probe {
		t.Skipf("PTY smoke: round-trip mismatch (got %q, want %q) — kernel PTY discipline misbehaving in this environment", buf[0], probe)
	}
	// Clear both deadlines so the real test body uses its own
	// timeouts; subsequent SetDeadline calls in the test body
	// supersede these.
	_ = master.SetDeadline(time.Time{})
	_ = slave.SetDeadline(time.Time{})
}

// findRepoRoot walks up from the test's CWD until it sees go.mod.
// Matches the helper in internal/server/subprocess_test.go but lives
// in this package to avoid a cross-package test dep.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod ascending from %s", cwd)
	return ""
}
