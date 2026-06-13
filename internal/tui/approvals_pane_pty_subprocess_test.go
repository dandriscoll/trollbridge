//go:build linux

package tui_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

// TestApprovalsPanePTY_CoalescedHoldRendersSingleCountedRow closes #207:
// the operator approvals pane has no terminal-subprocess (pty) E2E, so a
// regression in the render layer *below* DisplayedOps — the pane painter
// (formatPendingCard → formatOpRow → brailleCounter) — can reintroduce a
// visual duplicate (N rows instead of one counted row) without failing
// the reducer unit tests, which assert the DisplayedOps data structure
// rather than the rendered pane.
//
// Mechanics: boot `trollbridge run` on a real pty in mode=default-ask;
// drive N identical proxied GETs that all hit ask_user and are held —
// request coalescing (#206) folds them onto ONE hold id, so the pane must
// paint a SINGLE pending row carrying a Braille count glyph
// (brailleCounter(Count>=2) ∈ ⠁⠃⠇⠏⠟⠿⡿⣿). If the fold regressed, the host
// would paint N times each with a blank count cell and no glyph — so the
// glyph assertion fails closed.
//
// Linux-only (TIOCSPTLCK / TIOCGPTN are Linux-specific); macOS pty
// allocation is a separate grantpt/unlockpt path. Where /dev/ptmx is
// absent or cannot move bytes (sandbox, #69 shape), the test t.Skipf —
// CI's `-tags=e2e` ubuntu lane exercises the body on a functional pty.
func TestApprovalsPanePTY_CoalescedHoldRendersSingleCountedRow(t *testing.T) {
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

	// Validate the pty can actually move bytes before paying for the
	// build + subprocess startup (sandboxes that expose /dev/ptmx but
	// time out on real I/O — #69 — skip cleanly here).
	ptySmokeOrSkip(t, master, slave)

	// Size the terminal generously so the pending row has room for the
	// URL and the count column (a 0x0 default could clip the glyph).
	_ = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ,
		&unix.Winsize{Row: 40, Col: 120})

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

	// default-ask holds every request; timeout_seconds long so the holds
	// stay pending (never deny-timeout) for the whole pane-read window.
	cfgYAML := fmt.Sprintf(`proxy: lo:%s
control: 0
mode: default-ask
logging:
  audit_path: %s
approvals:
  timeout_seconds: 30
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
	})

	// Readiness: the oplog is suppressed on the pty in TUI mode, so we
	// cannot grep `event=listening` off the master. Dial the proxy port
	// until it accepts a connection.
	if !waitProxyReady(t, proxyAddr, 5*time.Second) {
		t.Skipf("proxy never came up on %s (likely no usable runtime here)", proxyAddr)
	}

	// Drive N identical held requests concurrently. They block (held);
	// we never wait on them — the subprocess teardown unwinds them. A
	// single client + one URL means one anonymous identity and one
	// dedupKey, so all N coalesce onto one hold (#206).
	const n = 8
	const heldHost = "h.test"
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(mustParseURL(t, "http://"+proxyAddr)),
			MaxConnsPerHost:     0,
			MaxIdleConnsPerHost: n,
		},
		Timeout: 25 * time.Second,
	}
	for i := 0; i < n; i++ {
		go func() {
			resp, err := client.Get("http://" + heldHost + "/")
			if err == nil {
				_ = resp.Body.Close()
			}
		}()
	}

	// Read the pty master until the pane paints the held host AND a
	// Braille count glyph (proving >=2 requests folded into one counted
	// row), or the deadline elapses.
	braille := []string{"⠁", "⠃", "⠇", "⠏", "⠟", "⠿", "⡿", "⣿"}
	var buf []byte
	tmp := make([]byte, 4096)
	deadline := time.Now().Add(12 * time.Second)
	sawHost, sawGlyph := false, false
	for time.Now().Before(deadline) {
		_ = master.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		nr, _ := master.Read(tmp)
		if nr > 0 {
			buf = append(buf, tmp[:nr]...)
		}
		s := string(buf)
		sawHost = strings.Contains(s, heldHost)
		sawGlyph = false
		for _, g := range braille {
			if strings.Contains(s, g) {
				sawGlyph = true
				break
			}
		}
		if sawHost && sawGlyph {
			return // pass
		}
	}

	out := string(buf)
	if !sawHost {
		t.Errorf("pane never showed held host %q; %d bytes captured:\n%s", heldHost, len(buf), out)
	}
	if !sawGlyph {
		t.Errorf("pane never showed a Braille coalesce-count glyph — the %d coalesced holds did "+
			"not fold into one counted row (render-layer regression?); %d bytes captured:\n%s",
			n, len(buf), out)
	}
}

// waitProxyReady polls a TCP dial against addr until it connects or the
// deadline elapses.
func waitProxyReady(t *testing.T, addr string, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 250*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse url %q: %v", s, err)
	}
	return u
}
