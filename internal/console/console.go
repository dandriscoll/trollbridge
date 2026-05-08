// Package console implements drawbridge's interactive operator REPL.
// It runs only when stdin is a tty so that systemd/Docker
// deployments are unaffected. Commands edit `lists.allow` and
// `lists.deny` inside drawbridge.yaml via internal/configwrite (a
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

	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/configwrite"
	"github.com/dandriscoll/drawbridge/internal/hostlist"
)

// Config holds the inputs the console needs from the rest of the
// system.
type Config struct {
	// ConfigPath is the path to drawbridge.yaml. Mutations rewrite
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
		cfg.Prompt = "drawbridge> "
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
	c.printf("drawbridge console — type `help` for commands, Ctrl-D to exit.\n")
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
	case "help", "?":
		c.printHelp()
	case "quit", "exit":
		return true
	default:
		c.printf("unknown command %q — type `help` for the list\n", cmd)
	}
	return false
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
  allow <pattern>    add to lists.allow in drawbridge.yaml
  deny <pattern>     add to lists.deny in drawbridge.yaml
  remove <pattern>   remove from either list
  list [allow|deny]  show current patterns
  reload             re-parse drawbridge.yaml into the running matcher
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
