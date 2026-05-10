//go:build linux

package tui_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestSinglePressCtrlCExits closes #48: a single ^C in the operator
// TUI must terminate the proxy. Pre-fix the TUI exited cleanly on
// the first byte but the parent's ListenAndServe stayed blocked
// because raw-mode stdin captured the byte and the kernel never saw
// a SIGINT — the fix passes the parent context's CancelFunc into the
// TUI so RunOperator can take down the daemon on quit.
//
// Mechanics (mirrors render_pty_subprocess_test.go): allocate a PTY,
// exec `trollbridge run` against the slave, write a single \x03 to
// the master, assert the process exits within 5 s.
func TestSinglePressCtrlCExits(t *testing.T) {
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
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()

	// Wait for the TUI to render — that's the signal that the
	// operator UI goroutine is up and reading stdin. We watch for
	// the rounded-corner box-drawing rune which only appears once
	// the bordered chrome is drawn.
	if err := master.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Skipf("SetDeadline: %v", err)
	}
	{
		buf := make([]byte, 0, 16384)
		tmp := make([]byte, 4096)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = master.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, _ := master.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				if containsAll(buf, []string{"╭", "approvals"}) {
					break
				}
			}
		}
		if !containsAll(buf, []string{"╭"}) {
			t.Skipf("TUI never rendered chrome on PTY (sandbox?); %d bytes captured", len(buf))
		}
	}

	// Send a single Ctrl-C.
	if _, err := master.Write([]byte{0x03}); err != nil {
		t.Fatalf("write Ctrl-C: %v", err)
	}

	// The process MUST exit within 5 s. Pre-fix it would block until
	// a second \x03 reached the (now-cooked) terminal as a real
	// SIGINT — i.e. forever, because we only sent one.
	exitDeadline := time.Now().Add(5 * time.Second)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
		// PASS
	case <-time.After(time.Until(exitDeadline)):
		t.Fatalf("process did not exit within 5 s of single Ctrl-C; #48 has regressed (or PTY raw-mode propagation broke)")
	}
}

func containsAll(haystack []byte, needles []string) bool {
	s := string(haystack)
	for _, n := range needles {
		if len(n) == 0 {
			continue
		}
		if !contains(s, n) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
