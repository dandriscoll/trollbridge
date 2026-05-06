// Package console implements drawbridge's interactive operator REPL.
// It runs only when stdin is a tty so that systemd/Docker
// deployments are unaffected. Commands edit allow.txt / deny.txt
// (the only mutation paths besides direct file edits); the file
// watcher picks up the change and reloads.
package console

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dandriscoll/drawbridge/internal/hostlist"
)

// Config holds the inputs the console needs from the rest of the
// system.
type Config struct {
	AllowPaths []string // file path(s); first is the write target
	DenyPaths  []string

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
		c.addPattern("allow", c.cfg.AllowPaths, arg)
	case "deny":
		c.addPattern("deny", c.cfg.DenyPaths, arg)
	case "remove", "rm":
		c.removePattern(arg)
	case "list", "ls":
		c.listEntries(arg)
	case "reload":
		c.printf("ok (the file watcher reloads on mtime change automatically; no manual reload needed)\n")
	case "help", "?":
		c.printHelp()
	case "quit", "exit":
		return true
	default:
		c.printf("unknown command %q — type `help` for the list\n", cmd)
	}
	return false
}

func (c *repl) addPattern(label string, paths []string, pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		c.printf("usage: %s <pattern>\n", label)
		return
	}
	if err := hostlist.ValidatePattern(pattern); err != nil {
		c.printf("invalid pattern: %s\n", err)
		return
	}
	if len(paths) == 0 {
		c.printf("no %s file configured\n", label)
		return
	}
	target := paths[0]
	lines, err := hostlist.ReadLines(target)
	if err != nil {
		c.printf("read %s: %s\n", target, err)
		return
	}
	updated, added := hostlist.AppendUnique(lines, pattern)
	if !added {
		c.printf("%s already in %s\n", pattern, target)
		return
	}
	if err := hostlist.WriteLines(target, updated); err != nil {
		c.printf("write %s: %s\n", target, err)
		return
	}
	c.printf("added %s to %s (%d patterns total)\n", pattern, target, countPatterns(updated))
}

func (c *repl) removePattern(pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		c.printf("usage: remove <pattern>\n")
		return
	}
	totalRemoved := 0
	for _, group := range [][]string{c.cfg.AllowPaths, c.cfg.DenyPaths} {
		for _, p := range group {
			lines, err := hostlist.ReadLines(p)
			if err != nil {
				c.printf("read %s: %s\n", p, err)
				continue
			}
			updated, removed := hostlist.RemoveMatching(lines, pattern)
			if removed {
				totalRemoved++
				if err := hostlist.WriteLines(p, updated); err != nil {
					c.printf("write %s: %s\n", p, err)
					continue
				}
				c.printf("removed %s from %s\n", pattern, p)
			}
		}
	}
	if totalRemoved == 0 {
		c.printf("%s not found in any configured list\n", pattern)
	}
}

func (c *repl) listEntries(arg string) {
	arg = strings.ToLower(strings.TrimSpace(arg))
	groups := []struct {
		name  string
		paths []string
	}{}
	switch arg {
	case "", "all":
		groups = append(groups,
			struct {
				name  string
				paths []string
			}{"allow", c.cfg.AllowPaths},
			struct {
				name  string
				paths []string
			}{"deny", c.cfg.DenyPaths})
	case "allow":
		groups = append(groups, struct {
			name  string
			paths []string
		}{"allow", c.cfg.AllowPaths})
	case "deny":
		groups = append(groups, struct {
			name  string
			paths []string
		}{"deny", c.cfg.DenyPaths})
	default:
		c.printf("usage: list [allow|deny|all]\n")
		return
	}
	for _, g := range groups {
		c.printf("%s:\n", g.name)
		count := 0
		for _, p := range g.paths {
			lines, err := hostlist.ReadLines(p)
			if err != nil {
				c.printf("  read %s: %s\n", p, err)
				continue
			}
			for _, ln := range lines {
				t := strings.TrimSpace(ln)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				c.printf("  %s\n", ln)
				count++
			}
		}
		c.printf("(%d patterns)\n", count)
	}
}

func (c *repl) printHelp() {
	c.printf(`commands:
  allow <pattern>    add to the first configured allow file
  deny <pattern>     add to the first configured deny file
  remove <pattern>   remove from any configured list (case-insensitive)
  list [allow|deny]  show current patterns
  reload             (no-op; the watcher reloads automatically)
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

func countPatterns(lines []string) int {
	n := 0
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		n++
	}
	return n
}

func (c *repl) printf(format string, args ...any) {
	fmt.Fprintf(c.cfg.Out, format, args...)
}

func (c *repl) printPrompt() { c.printf("%s", c.cfg.Prompt) }
