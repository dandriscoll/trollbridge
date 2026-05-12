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

// TestLLMPanelPTY_OpensWithNewLegend closes the runtime-classification
// gap for #81. The reducer + render-buffer tests cover the new
// keybindings in-process; this test verifies that pressing '3' in a
// real TTY actually surfaces the new LLM-panel legend on screen.
// It does not exercise Enter/expand/modal — those require digests
// in the ring (the advisor would have to fire), which means
// generating proxied traffic. Coverage above that line is the
// optimisation layer; this test is the foundation: bytes reach the
// terminal as designed.
//
// Mechanics mirror TestRenderPTY_BordersAppearOnRealTerminal:
// allocate a PTY, exec `trollbridge run`, write '3' to master, read
// the next render frame, assert the new legend tokens appear.
func TestLLMPanelPTY_OpensWithNewLegend(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
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

	// Drain the initial render. We don't assert on it — just wait
	// for the TUI to settle before sending '3'.
	if err := master.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Skipf("SetDeadline on PTY master: %v", err)
	}
	drained := make([]byte, 0, 65536)
	tmp := make([]byte, 4096)
	settle := time.Now().Add(2 * time.Second)
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

	// Send '3' to open the LLM panel.
	if err := master.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Skipf("SetWriteDeadline on master: %v", err)
	}
	if _, err := master.Write([]byte{'3'}); err != nil {
		t.Skipf("master.Write '3': %v", err)
	}

	// Read the next render frame; assert the new legend tokens.
	buf := make([]byte, 0, 65536)
	deadline := time.Now().Add(5 * time.Second)
	want := []string{"llm", "Enter", "Esc", "nav"}
	for time.Now().Before(deadline) && len(buf) < cap(buf) {
		_ = master.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, _ := master.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		s := string(buf)
		allFound := true
		for _, w := range want {
			if !strings.Contains(s, w) {
				allFound = false
				break
			}
		}
		if allFound {
			break
		}
	}

	out := string(buf)
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("PTY render after '3' missing legend token %q; %d bytes captured\nfirst 800: %q",
				w, len(buf), first(out, 800))
		}
	}
}

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
