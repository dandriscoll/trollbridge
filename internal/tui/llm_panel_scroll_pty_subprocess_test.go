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

// TestLLMPanelPTY_ScrollAcrossSyntheticDigests closes #160: the
// TUI's LLM-digest panel supports up/down scrolling, but unit tests
// cover only the offset computation — no subprocess test exercises
// the full input → render → visible-row path. This test does, by:
//
//   - launching the binary with TROLLBRIDGE_TEST_INJECT_DIGESTS=30
//     in env (advisor.New pre-fills the digest ring with 30
//     deterministic synthetic digests, hosts synth-host-001 through
//     synth-host-030);
//   - allocating a PTY and running `trollbridge run` against it;
//   - sending '3' to open the LLM panel and asserting the newest
//     synthetic host (synth-host-030.example) is rendered with the
//     selection bar (`┃`);
//   - sending Down repeatedly and asserting on each step that the
//     expected next-older host is rendered with the selection bar.
//
// A failure here means scroll dispatch or render math is broken in
// a way that unit tests cannot see (the per-render selection-bar
// placement, the anchor-at-bottom scroll math, or the
// reconcileDigestSelection cross-tick affinity).
//
// Skips cleanly on PTY-unavailable runners (matches the
// established pattern in render_pty_subprocess_test.go).
func TestLLMPanelPTY_ScrollAcrossSyntheticDigests(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skipf("PTY unavailable (/dev/ptmx): %v", err)
	}

	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v", err)
	}
	defer master.Close()

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

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, "run", "--config", cfgPath)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	// Inject 30 synthetic digests via the test-only env hook
	// (advisor.New parses TROLLBRIDGE_TEST_INJECT_DIGESTS). #160.
	cmd.Env = append(os.Environ(), "TROLLBRIDGE_TEST_INJECT_DIGESTS=30")
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

	// Drain the initial render until the approvals chrome appears.
	if err := master.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Skipf("SetDeadline on PTY master: %v", err)
	}
	drained := make([]byte, 0, 65536)
	tmp := make([]byte, 4096)
	settle := time.Now().Add(5 * time.Second)
	for time.Now().Before(settle) {
		_ = master.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _ := master.Read(tmp)
		if n > 0 {
			drained = append(drained, tmp[:n]...)
		}
		if strings.Contains(string(drained), "approvals") {
			break
		}
	}
	if !strings.Contains(string(drained), "approvals") {
		t.Skipf("TUI never rendered approvals chrome on PTY (sandbox?); %d bytes captured", len(drained))
	}

	// Send '3' to open the LLM panel. The reducer auto-selects the
	// newest digest (m.Digests[len-1] = synth-host-030) and sets
	// DigestExpanded=true, so the URL line of the expanded detail
	// block carries `synth-host-030.example` with the `┃` prefix.
	if _, err := master.Write([]byte{'3'}); err != nil {
		t.Skipf("write '3': %v", err)
	}

	// Assert the newest synthetic host is selected after the open.
	// Per the reducer: DigestSelected = synth-host-030 (newest).
	if err := waitForSelectedHost(master, "synth-host-030.example", 8*time.Second); err != nil {
		t.Fatalf("after '3' (open LLM panel): %v", err)
	}

	// Send Down five times; each step moves selection to the next
	// older digest in display order. Newest-first display means
	// Down 1 → synth-host-029, Down 2 → synth-host-028, etc.
	for step := 1; step <= 5; step++ {
		// Down arrow is ESC [ B (CSI B).
		if _, err := master.Write([]byte{0x1b, '[', 'B'}); err != nil {
			t.Fatalf("step %d: write Down: %v", step, err)
		}
		wantHost := fmt.Sprintf("synth-host-%03d.example", 30-step)
		if err := waitForSelectedHost(master, wantHost, 5*time.Second); err != nil {
			t.Fatalf("after Down x%d: %v", step, err)
		}
	}
}

// waitForSelectedHost reads from master until a rendered line
// contains BOTH the expected host substring AND the selection-bar
// rune `┃` (U+2503). Returns nil on match; non-nil error on
// deadline. The dual-criterion catches the host appearing only in
// a non-selected compact row (false-positive shape).
func waitForSelectedHost(master *os.File, wantHost string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 0, 131072)
	tmp := make([]byte, 4096)
	for time.Now().Before(deadline) {
		_ = master.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := master.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if hasSelectedHost(buf, wantHost) {
			return nil
		}
	}
	return fmt.Errorf("did not observe selection bar on line containing %q within %v\n%d bytes captured; tail:\n%q",
		wantHost, timeout, len(buf), tailString(string(buf), 1024))
}

// hasSelectedHost reports whether any line in buf contains both
// wantHost AND the selection-bar rune `┃`. Splits on '\n' and
// '\r' to handle the terminal's CR/LF rendering.
func hasSelectedHost(buf []byte, wantHost string) bool {
	s := string(buf)
	// Normalize CR to LF for splitting; the terminal emits both
	// during scroll redraws.
	s = strings.ReplaceAll(s, "\r", "\n")
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, wantHost) && strings.Contains(line, "┃") {
			return true
		}
	}
	return false
}
