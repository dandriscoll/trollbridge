// Package console implements the operator command surface invoked
// from inside the unified TUI in internal/tui. Backend.Execute runs
// one command line at a time and writes its output to the supplied
// writer; the TUI's console pane drives it from raw-mode keystrokes.
//
// Every mutation flows through internal/configwrite (yaml-Node-level
// edits that preserve comments outside the lists subtree). After a
// successful write the supplied OnReload callback re-parses the file
// and updates the running matcher.
package console

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/hostlist"
)

// updateGOOS is read in place of runtime.GOOS so tests can pick the
// Windows branch of `update` without cross-compiling. Production
// callers leave it at runtime.GOOS. Mirrors the CLI plumbing in
// cmd/trollbridge/update.go.
var updateGOOS = runtime.GOOS

// updateRunner shells out to the install.sh pipeline and streams
// installer output. Replaced in tests with a recorder so the
// shell-out path can be exercised without touching the network.
// Mirrors the CLI plumbing in cmd/trollbridge/update.go (closes #78).
var updateRunner = func(stdout, stderr io.Writer) error {
	c := exec.Command("sh", "-c", "curl -fsSL https://trollbridge.dev/install.sh | sh")
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

// Backend executes one operator command line at a time. The TUI's
// console pane creates a Backend per session and calls Execute on
// each Enter keystroke.
type Backend struct {
	// ConfigPath is the path to trollbridge.yaml. Mutations rewrite
	// it in place via configwrite. Empty in attach mode.
	ConfigPath string

	// OnReload is invoked after each successful list mutation so the
	// running daemon can re-parse the config and refresh its
	// in-memory matcher. Nil in attach mode.
	OnReload func()

	// OnTest, when non-nil, is invoked when the operator types
	// `test <url>`. The callback formats and prints its result; a
	// returned error is surfaced as `test: <err>`.
	OnTest func(out io.Writer, urlArg string) error

	// OnDoctor, when non-nil, is invoked when the operator types
	// `doctor`. Same conventions as OnTest.
	OnDoctor func(out io.Writer) error

	// LocalOnly = true means commands that touch local state
	// (allow/deny/remove/list/reload/test/doctor) are available.
	// LocalOnly = false (attach mode) routes those commands to a
	// one-line "not available in attach mode" hint instead of
	// silently failing.
	LocalOnly bool
}

// Execute runs one command line and writes its output to out. The
// caller has already trimmed surrounding whitespace; an empty line
// is treated as a no-op. Returns true when the operator asked to
// quit (the TUI then exits the alt-screen).
func (b *Backend) Execute(out io.Writer, line string) (quit bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	cmd, arg := splitCmd(line)
	switch strings.ToLower(cmd) {
	case "allow":
		b.runLocal(out, "allow", func() { b.addPattern(out, "allow", arg) })
	case "deny":
		b.runLocal(out, "deny", func() { b.addPattern(out, "deny", arg) })
	case "remove", "rm":
		b.runLocal(out, "remove", func() { b.removePattern(out, arg) })
	case "list", "ls":
		b.runLocal(out, "list", func() { b.listEntries(out, arg) })
	case "reload":
		b.runLocal(out, "reload", func() { b.triggerReload() })
	case "test":
		b.runTest(out, arg)
	case "doctor":
		b.runDoctor(out)
	case "update":
		b.runUpdate(out)
	case "help", "?":
		b.printHelp(out)
	case "quit", "exit":
		return true
	default:
		fmt.Fprintf(out, "unknown command %q — type `help` for the list\n", cmd)
	}
	return false
}

// IsInteractive returns true when the supplied file is a terminal
// (and therefore safe to drive a UI from).
func IsInteractive(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func (b *Backend) runLocal(out io.Writer, name string, fn func()) {
	if !b.LocalOnly {
		fmt.Fprintf(out, "%s: not available in attach mode — run on the proxy host\n", name)
		return
	}
	fn()
}

func (b *Backend) runTest(out io.Writer, arg string) {
	if !b.LocalOnly {
		fmt.Fprintln(out, "test: not available in attach mode — run on the proxy host")
		return
	}
	if b.OnTest == nil {
		fmt.Fprintln(out, "test: not wired — start the daemon with `trollbridge run` to enable")
		return
	}
	arg = strings.TrimSpace(arg)
	if arg == "" {
		fmt.Fprintln(out, "usage: test <url> — sends one request through this proxy and prints the response")
		return
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(out, "test: panic: %v\n", r)
		}
	}()
	if err := b.OnTest(out, arg); err != nil {
		fmt.Fprintf(out, "test: %s\n", err)
	}
}

func (b *Backend) runDoctor(out io.Writer) {
	if !b.LocalOnly {
		fmt.Fprintln(out, "doctor: not available in attach mode — run on the proxy host")
		return
	}
	if b.OnDoctor == nil {
		fmt.Fprintln(out, "doctor: not wired — start the daemon with `trollbridge run` to enable")
		return
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(out, "doctor: panic: %v\n", r)
		}
	}()
	if err := b.OnDoctor(out); err != nil {
		fmt.Fprintf(out, "doctor: %s\n", err)
	}
}

// runUpdate streams the install.sh pipeline into the console
// scrollback. Available in both LocalOnly (run) and attach modes —
// updating the local binary is host-local regardless of where the
// daemon runs. The running daemon keeps its loaded text until
// restart; the success message names that explicitly.
func (b *Backend) runUpdate(out io.Writer) {
	if updateGOOS == "windows" {
		fmt.Fprintln(out, "Auto-update is not yet supported on Windows.")
		fmt.Fprintln(out, "Download the latest release from https://github.com/dandriscoll/trollbridge/releases/latest")
		return
	}
	fmt.Fprintln(out, "running: curl -fsSL https://trollbridge.dev/install.sh | sh")
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(out, "update: panic: %v\n", r)
		}
	}()
	if err := updateRunner(out, out); err != nil {
		fmt.Fprintf(out, "update: %s\n", err)
		return
	}
	fmt.Fprintln(out, "update complete — restart trollbridge to use the new binary")
}

func (b *Backend) addPattern(out io.Writer, label, pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		fmt.Fprintf(out, "usage: %s <pattern>\n", label)
		return
	}
	if err := hostlist.ValidatePattern(pattern); err != nil {
		fmt.Fprintf(out, "invalid pattern: %s\n", err)
		return
	}
	if b.ConfigPath == "" {
		fmt.Fprintln(out, "no config path configured (cannot persist mutation)")
		return
	}
	var (
		changed bool
		err     error
	)
	switch label {
	case "allow":
		changed, err = configwrite.AddAllow(b.ConfigPath, pattern)
	case "deny":
		changed, err = configwrite.AddDeny(b.ConfigPath, pattern)
	}
	if err != nil {
		fmt.Fprintf(out, "write %s: %s\n", b.ConfigPath, err)
		return
	}
	if !changed {
		fmt.Fprintf(out, "%s already in %s list\n", pattern, label)
		return
	}
	count := b.countList(label)
	fmt.Fprintf(out, "added %s to %s (%d entries total)\n", pattern, label, count)
	b.triggerReload()
}

func (b *Backend) removePattern(out io.Writer, pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		fmt.Fprintln(out, "usage: remove <pattern>")
		return
	}
	if b.ConfigPath == "" {
		fmt.Fprintln(out, "no config path configured")
		return
	}
	removedAllow, err := configwrite.RemoveAllow(b.ConfigPath, pattern)
	if err != nil {
		fmt.Fprintf(out, "write %s: %s\n", b.ConfigPath, err)
		return
	}
	removedDeny, err := configwrite.RemoveDeny(b.ConfigPath, pattern)
	if err != nil {
		fmt.Fprintf(out, "write %s: %s\n", b.ConfigPath, err)
		return
	}
	switch {
	case removedAllow && removedDeny:
		fmt.Fprintf(out, "removed %s from allow and deny\n", pattern)
	case removedAllow:
		fmt.Fprintf(out, "removed %s from allow\n", pattern)
	case removedDeny:
		fmt.Fprintf(out, "removed %s from deny\n", pattern)
	default:
		fmt.Fprintf(out, "%s not found in any list\n", pattern)
		return
	}
	b.triggerReload()
}

func (b *Backend) listEntries(out io.Writer, arg string) {
	arg = strings.ToLower(strings.TrimSpace(arg))
	cfg, err := config.Load(b.ConfigPath)
	if err != nil {
		fmt.Fprintf(out, "load %s: %s\n", b.ConfigPath, err)
		return
	}
	switch arg {
	case "", "all":
		printList(out, "allow", cfg.Lists.Allow)
		printList(out, "deny", cfg.Lists.Deny)
	case "allow":
		printList(out, "allow", cfg.Lists.Allow)
	case "deny":
		printList(out, "deny", cfg.Lists.Deny)
	default:
		fmt.Fprintln(out, "usage: list [allow|deny|all]")
	}
}

func printList(out io.Writer, name string, entries []string) {
	fmt.Fprintf(out, "%s:\n", name)
	count := 0
	for _, e := range entries {
		t := strings.TrimSpace(e)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fmt.Fprintf(out, "  %s\n", e)
		count++
	}
	fmt.Fprintf(out, "(%d entries)\n", count)
}

func (b *Backend) countList(label string) int {
	cfg, err := config.Load(b.ConfigPath)
	if err != nil {
		return -1
	}
	var entries []string
	switch label {
	case "allow":
		entries = cfg.Lists.Allow
	case "deny":
		entries = cfg.Lists.Deny
	}
	n := 0
	for _, e := range entries {
		t := strings.TrimSpace(e)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		n++
	}
	return n
}

func (b *Backend) triggerReload() {
	if b.OnReload != nil {
		b.OnReload()
	}
}

func (b *Backend) printHelp(out io.Writer) {
	if b.LocalOnly {
		fmt.Fprint(out, `commands:
  allow <pattern>    add to lists.allow in trollbridge.yaml
  deny <pattern>     add to lists.deny in trollbridge.yaml
  remove <pattern>   remove from either list
  list [allow|deny]  show current entries
  reload             re-parse trollbridge.yaml into the running matcher
  test <url>         send one request through this proxy and print result
  doctor             run the same checks as `+"`trollbridge doctor`"+`
  update             update the local trollbridge binary via trollbridge.dev/install.sh
  help               this text
  quit | exit        leave the UI (the proxy keeps running)
`)
		return
	}
	fmt.Fprint(out, `commands available in attach mode:
  update             update the local trollbridge binary via trollbridge.dev/install.sh
  help               this text
  quit | exit        close the attach session

list editing, test, doctor, and reload run on the proxy host —
open them with `+"`trollbridge run`"+` there.
`)
}

func splitCmd(line string) (string, string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return line[:i], strings.TrimSpace(line[i:])
	}
	return line, ""
}
