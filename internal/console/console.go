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
	"runtime"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/hostlist"
	"github.com/dandriscoll/trollbridge/internal/updater"
)

// updateGOOS is read in place of runtime.GOOS so tests can pick the
// Windows branch of `update` without cross-compiling. Production
// callers leave it at runtime.GOOS. Mirrors the CLI plumbing in
// cmd/trollbridge/update.go.
var updateGOOS = runtime.GOOS

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

	// Remote, when non-nil and LocalOnly is false, replaces the
	// "not available in attach mode" stub for the allow / deny /
	// remove verbs with a HTTP-mediated mutation against the
	// proxy's control plane (#189). The attach.go callsite wires
	// this; the in-process daemon leaves it nil (LocalOnly is true
	// there and the local configwrite path is taken).
	Remote RemoteListWriter
}

// RemoteListWriter is the surface console.Backend uses to perform
// list mutations in attach mode (#189). The concrete
// implementation lives in cmd/trollbridge and wraps the
// controlclient HTTP call.
type RemoteListWriter interface {
	AddAllow(pattern string) (bool, error)
	AddDeny(pattern string) (bool, error)
	RemoveAllow(pattern string) (bool, error)
	RemoveDeny(pattern string) (bool, error)
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
		if b.runRemote(out, "allow", "add", arg) {
			break
		}
		b.runLocal(out, "allow", func() { b.addPattern(out, "allow", arg) })
	case "deny":
		if b.runRemote(out, "deny", "add", arg) {
			break
		}
		b.runLocal(out, "deny", func() { b.addPattern(out, "deny", arg) })
	case "remove", "rm":
		// Remote-remove ambiguity: the local `remove <pattern>` is
		// list-agnostic (strips from whichever list contains the
		// pattern). The remote API needs the list named. For attach
		// v1, fall through to "not available" when Remote is wired —
		// operators run `remove` from the URLs pane keyboard surface
		// which already knows the list (`x` on a selected entry).
		// Filed in 008 if operator feedback indicates the typed
		// `remove <pattern>` verb is wanted remotely too.
		b.runLocal(out, "remove", func() { b.removePattern(out, arg) })
	case "move", "mv":
		b.runLocal(out, "move", func() { b.movePattern(out, arg) })
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

// runRemote dispatches an allow / deny / remove verb to the
// proxy's control-plane endpoints in attach mode (#189). Used by
// the allow / deny / remove paths when b.Remote is wired. Returns
// without writing when b.Remote is nil — the caller should fall
// back to runLocal's "not available in attach mode" stub.
func (b *Backend) runRemote(out io.Writer, list, verb, pattern string) (handled bool) {
	if b.LocalOnly || b.Remote == nil {
		return false
	}
	var (
		changed bool
		err     error
	)
	switch verb {
	case "add":
		if list == "allow" {
			changed, err = b.Remote.AddAllow(pattern)
		} else {
			changed, err = b.Remote.AddDeny(pattern)
		}
	case "remove":
		if list == "allow" {
			changed, err = b.Remote.RemoveAllow(pattern)
		} else {
			changed, err = b.Remote.RemoveDeny(pattern)
		}
	}
	if err != nil {
		fmt.Fprintf(out, "%s %s (remote): %s\n", verb, list, err)
		return true
	}
	if !changed {
		fmt.Fprintf(out, "%s already in %s list (remote no-op)\n", pattern, list)
		return true
	}
	switch verb {
	case "add":
		fmt.Fprintf(out, "added %s to %s (via proxy)\n", pattern, list)
	case "remove":
		fmt.Fprintf(out, "removed %s from %s (via proxy)\n", pattern, list)
	}
	return true
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
	fmt.Fprintln(out, "running: "+updater.Pipeline())
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(out, "update: panic: %v\n", r)
		}
	}()
	if err := updater.Run(out, out); err != nil {
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
	// Consolidate-then-add via the single operator-action primitive
	// (#179, #194): the operator allowing a pattern that is still on
	// deny would otherwise leave the URL on both lists and deny wins
	// on reload, silently no-op'ing the approve. Routing through
	// OperatorApprove / OperatorDeny converges this code path with
	// the daemon's hold-queue persist callback on the same primitive,
	// so a single rule governs every operator-action write.
	var removeErr error
	switch label {
	case "allow":
		_, changed, removeErr, err = configwrite.OperatorApprove(b.ConfigPath, pattern)
	case "deny":
		_, changed, removeErr, err = configwrite.OperatorDeny(b.ConfigPath, pattern)
	}
	if removeErr != nil {
		fmt.Fprintf(out, "write %s: %s\n", b.ConfigPath, removeErr)
		return
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

// AcceptGeneralization applies an accepted generalization from the TUI
// card (#170/#173): it removes the more-specific source entries and
// adds the generalized pattern to `list`, atomically, then reloads.
// Mirrors movePattern's compound-write + reload shape. Called via the
// console worker (serialized) so it cannot race another list write.
func (b *Backend) AcceptGeneralization(out io.Writer, list, pattern string, sources []string) {
	if !b.LocalOnly {
		fmt.Fprintln(out, "generalize: not available in attach mode — run on the proxy host")
		return
	}
	if b.ConfigPath == "" {
		fmt.Fprintln(out, "no config path configured (cannot persist mutation)")
		return
	}
	changed, err := configwrite.Generalize(b.ConfigPath, list, pattern, sources)
	if err != nil {
		fmt.Fprintf(out, "write %s: %s\n", b.ConfigPath, err)
		return
	}
	if !changed {
		fmt.Fprintf(out, "%s already in %s list\n", pattern, list)
		return
	}
	fmt.Fprintf(out, "generalized → added %s to %s; pruned redundant entries it now covers\n", pattern, list)
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

// movePattern moves a pattern from one list to the other atomically:
// if the operator wrote `move allow <pat>` the pattern is removed
// from the deny list (if present) and added to the allow list. This
// is the verb behind the URLs panel's `a` (approve) and `d` (deny)
// keystrokes (#86), and matches the operator's mental model that
// approve/deny migrates an entry between sides.
func (b *Backend) movePattern(out io.Writer, arg string) {
	side, pattern := splitCmd(arg)
	side = strings.ToLower(strings.TrimSpace(side))
	pattern = strings.TrimSpace(pattern)
	if side != "allow" && side != "deny" {
		fmt.Fprintln(out, "usage: move allow|deny <pattern>")
		return
	}
	if pattern == "" {
		fmt.Fprintln(out, "usage: move allow|deny <pattern>")
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
		otherRemoved bool
		added        bool
		removeErr    error
		addErr       error
	)
	// Route through the consolidate-then-add primitive so movePattern
	// shares one implementation with addPattern and the run/quickstart
	// persist callbacks (#194 / #200 invariant 2). Behavior is
	// identical to the previous inline RemoveOpposite + AddSide pair.
	if side == "allow" {
		otherRemoved, added, removeErr, addErr = configwrite.OperatorApprove(b.ConfigPath, pattern)
	} else {
		otherRemoved, added, removeErr, addErr = configwrite.OperatorDeny(b.ConfigPath, pattern)
	}
	if removeErr != nil {
		fmt.Fprintf(out, "write %s: %s\n", b.ConfigPath, removeErr)
		return
	}
	if addErr != nil {
		fmt.Fprintf(out, "write %s: %s\n", b.ConfigPath, addErr)
		return
	}
	switch {
	case otherRemoved && added:
		fmt.Fprintf(out, "moved %s to %s\n", pattern, side)
	case added:
		fmt.Fprintf(out, "added %s to %s (%d entries total)\n", pattern, side, b.countList(side))
	case otherRemoved:
		fmt.Fprintf(out, "%s already in %s; removed from other list\n", pattern, side)
	default:
		fmt.Fprintf(out, "%s already in %s\n", pattern, side)
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
  move allow|deny <pattern>  move a pattern between lists atomically
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
