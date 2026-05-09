// Package console implements trollbridge's interactive operator REPL.
// It runs only when stdin is a tty so that systemd/Docker
// deployments are unaffected. Commands edit `lists.allow` and
// `lists.deny` inside trollbridge.yaml via internal/configwrite (a
// yaml-Node-level edit that preserves comments outside the lists
// subtree); after a successful write the supplied OnReload callback
// re-parses the file and updates the running matcher.
package console

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/hostlist"
)

// Config holds the inputs the console needs from the rest of the
// system.
type Config struct {
	// ConfigPath is the path to trollbridge.yaml. Mutations rewrite
	// it in place via configwrite.
	ConfigPath string

	// OnReload is invoked after each successful list mutation so
	// the running daemon can re-parse the config and refresh its
	// in-memory matcher.
	OnReload func()

	// In, Out are the IO streams. Defaults to os.Stdin / os.Stdout
	// when not set.
	In  io.Reader
	Out io.Writer

	// Prompt is the line shown at each iteration.
	Prompt string

	// OnTest, when non-nil, is invoked when the operator types
	// `test <url>` at the prompt. Issue #31. The console hands
	// `urlArg` (everything after the command) to the callback;
	// `out` is the same writer the rest of the REPL prints to.
	// The callback is responsible for formatting and printing
	// its result; returned errors are surfaced as `test: <err>`.
	OnTest func(out io.Writer, urlArg string) error

	// OnDoctor, when non-nil, is invoked when the operator types
	// `doctor` at the prompt. Issue #31. Same conventions as OnTest.
	OnDoctor func(out io.Writer) error
}

// Run starts the REPL. Returns when stdin closes (EOF) or ctx is
// done. Safe to call from a goroutine.
func Run(ctx context.Context, cfg Config) error {
	if cfg.In == nil {
		cfg.In = os.Stdin
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}
	if cfg.Prompt == "" {
		cfg.Prompt = "trollbridge> "
	}

	c := &repl{cfg: cfg}
	return c.loop(ctx)
}

// IsInteractive returns true when the supplied file is a terminal
// (and therefore safe to drive a REPL from).
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

type repl struct {
	cfg Config
}

func (c *repl) loop(ctx context.Context) error {
	c.printf("trollbridge console — type `help` for commands, Ctrl-D to exit.\n")
	c.printPrompt()

	scanner := bufio.NewScanner(c.cfg.In)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			c.printPrompt()
			continue
		}
		if c.handle(line) {
			return nil
		}
		c.printPrompt()
	}
	return scanner.Err()
}

// handle returns true when the REPL should exit.
func (c *repl) handle(line string) bool {
	cmd, arg := splitCmd(line)
	switch strings.ToLower(cmd) {
	case "allow":
		c.addPattern("allow", arg)
	case "deny":
		c.addPattern("deny", arg)
	case "remove", "rm":
		c.removePattern(arg)
	case "list", "ls":
		c.listEntries(arg)
	case "reload":
		c.triggerReload()
	case "test":
		c.runTestSafely(arg)
	case "doctor":
		c.runDoctorSafely()
	case "help", "?":
		c.printHelp()
	case "quit", "exit":
		return true
	default:
		c.printf("unknown command %q — type `help` for the list\n", cmd)
	}
	return false
}

// runTestSafely invokes the OnTest callback and recovers from a
// panic so a network bug in the test path cannot kill the REPL
// goroutine. The callback is supplied by `cmd run` and bridges to
// the same `runTest` body the CLI uses.
func (c *repl) runTestSafely(arg string) {
	if c.cfg.OnTest == nil {
		c.printf("test: not wired — start the daemon with `trollbridge run` to enable\n")
		return
	}
	arg = strings.TrimSpace(arg)
	if arg == "" {
		c.printf("usage: test <url> — sends one request through this proxy and prints the response\n")
		return
	}
	defer func() {
		if r := recover(); r != nil {
			c.printf("test: panic: %v\n", r)
		}
	}()
	if err := c.cfg.OnTest(c.cfg.Out, arg); err != nil {
		c.printf("test: %s\n", err)
	}
}

// runDoctorSafely invokes the OnDoctor callback with the same
// recover semantics as runTestSafely.
func (c *repl) runDoctorSafely() {
	if c.cfg.OnDoctor == nil {
		c.printf("doctor: not wired — start the daemon with `trollbridge run` to enable\n")
		return
	}
	defer func() {
		if r := recover(); r != nil {
			c.printf("doctor: panic: %v\n", r)
		}
	}()
	if err := c.cfg.OnDoctor(c.cfg.Out); err != nil {
		c.printf("doctor: %s\n", err)
	}
}

func (c *repl) addPattern(label, pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		c.printf("usage: %s <pattern>\n", label)
		return
	}
	if err := hostlist.ValidatePattern(pattern); err != nil {
		c.printf("invalid pattern: %s\n", err)
		return
	}
	if c.cfg.ConfigPath == "" {
		c.printf("no config path configured (cannot persist mutation)\n")
		return
	}
	var (
		changed bool
		err     error
	)
	switch label {
	case "allow":
		changed, err = configwrite.AddAllow(c.cfg.ConfigPath, pattern)
	case "deny":
		changed, err = configwrite.AddDeny(c.cfg.ConfigPath, pattern)
	}
	if err != nil {
		c.printf("write %s: %s\n", c.cfg.ConfigPath, err)
		return
	}
	if !changed {
		c.printf("%s already in %s list\n", pattern, label)
		return
	}
	count := c.countList(label)
	c.printf("added %s to %s (%d patterns total)\n", pattern, label, count)
	c.triggerReload()
}

func (c *repl) removePattern(pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		c.printf("usage: remove <pattern>\n")
		return
	}
	if c.cfg.ConfigPath == "" {
		c.printf("no config path configured\n")
		return
	}
	removedAllow, err := configwrite.RemoveAllow(c.cfg.ConfigPath, pattern)
	if err != nil {
		c.printf("write %s: %s\n", c.cfg.ConfigPath, err)
		return
	}
	removedDeny, err := configwrite.RemoveDeny(c.cfg.ConfigPath, pattern)
	if err != nil {
		c.printf("write %s: %s\n", c.cfg.ConfigPath, err)
		return
	}
	switch {
	case removedAllow && removedDeny:
		c.printf("removed %s from allow and deny\n", pattern)
	case removedAllow:
		c.printf("removed %s from allow\n", pattern)
	case removedDeny:
		c.printf("removed %s from deny\n", pattern)
	default:
		c.printf("%s not found in any list\n", pattern)
		return
	}
	c.triggerReload()
}

func (c *repl) listEntries(arg string) {
	arg = strings.ToLower(strings.TrimSpace(arg))
	cfg, err := config.Load(c.cfg.ConfigPath)
	if err != nil {
		c.printf("load %s: %s\n", c.cfg.ConfigPath, err)
		return
	}
	switch arg {
	case "", "all":
		c.printList("allow", cfg.Lists.Allow)
		c.printList("deny", cfg.Lists.Deny)
	case "allow":
		c.printList("allow", cfg.Lists.Allow)
	case "deny":
		c.printList("deny", cfg.Lists.Deny)
	default:
		c.printf("usage: list [allow|deny|all]\n")
	}
}

func (c *repl) printList(name string, entries []string) {
	c.printf("%s:\n", name)
	count := 0
	for _, e := range entries {
		t := strings.TrimSpace(e)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		c.printf("  %s\n", e)
		count++
	}
	c.printf("(%d patterns)\n", count)
}

func (c *repl) countList(label string) int {
	cfg, err := config.Load(c.cfg.ConfigPath)
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

func (c *repl) triggerReload() {
	if c.cfg.OnReload != nil {
		c.cfg.OnReload()
	}
}

func (c *repl) printHelp() {
	c.printf(`commands:
  allow <pattern>    add to lists.allow in trollbridge.yaml
  deny <pattern>     add to lists.deny in trollbridge.yaml
  remove <pattern>   remove from either list
  list [allow|deny]  show current patterns
  reload             re-parse trollbridge.yaml into the running matcher
  test <url>         send one request through this proxy and print result
  doctor             run the same checks as `+"`trollbridge doctor`"+`
  help               this text
  quit | exit        leave the console (the proxy keeps running)
`)
}

func splitCmd(line string) (string, string) {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return line[:i], strings.TrimSpace(line[i:])
	}
	return line, ""
}

func (c *repl) printf(format string, args ...any) {
	fmt.Fprintf(c.cfg.Out, format, args...)
}

func (c *repl) printPrompt() { c.printf("%s", c.cfg.Prompt) }
