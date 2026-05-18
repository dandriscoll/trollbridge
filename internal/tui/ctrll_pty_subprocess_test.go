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

// TestCtrlLEmitsHardClearSequence closes #159: the TUI's Ctrl-L
// handler must emit the hard-clear ANSI sequence `\x1b[2J\x1b[3J`
// to the terminal — not just dispatch the keypress internally.
// Unit tests assert the dispatcher routes the key; this subprocess
// pty test confirms the bytes actually reach the terminal.
//
// Mechanics mirror ctrlc_pty_subprocess_test.go: allocate a PTY,
// exec `trollbridge run` against the slave, wait for the TUI to
// render its chrome, then write a single \x0c (Ctrl-L) to the
// master and scan the output for the hard-clear prefix.
func TestCtrlLEmitsHardClearSequence(t *testing.T) {
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
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}()

	// Wait for the TUI to render — same chrome-watch as the Ctrl-C
	// test. Skip out of the test on a sandbox PTY that never paints.
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

	// Send a single Ctrl-L.
	if _, err := master.Write([]byte{0x0c}); err != nil {
		t.Fatalf("write Ctrl-L: %v", err)
	}

	// Scan for the hard-clear sequence. Read at most a few seconds.
	const hardClear = "\x1b[2J\x1b[3J"
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 0, 32768)
	tmp := make([]byte, 4096)
	for time.Now().Before(deadline) {
		_ = master.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := master.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if strings.Contains(string(buf), hardClear) {
				return // PASS
			}
		}
	}
	t.Fatalf("did not observe hard-clear sequence \\x1b[2J\\x1b[3J within 5 s of Ctrl-L\n%d bytes captured; tail:\n%q",
		len(buf), tailString(string(buf), 512))
}

func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
