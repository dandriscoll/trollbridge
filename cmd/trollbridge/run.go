package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/server"
	"github.com/dandriscoll/trollbridge/internal/tui"
	"github.com/dandriscoll/trollbridge/internal/types"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func newRunCmd() *cobra.Command {
	var configPath string
	var noConsole bool
	var verbose bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the proxy in the foreground.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return &configErr{err}
			}

			// Resolve operational log level: --log-level flag > env >
			// --verbose alias > config (no field today; future) >
			// default info.
			levelVar := new(slog.LevelVar)
			levelVar.Set(slog.LevelInfo)
			if resolvedLogLevel != nil {
				levelVar.Set(*resolvedLogLevel)
			} else if verbose {
				levelVar.Set(slog.LevelDebug)
			}

			// Resolve operational sink: relative paths land alongside
			// the config file (mirrors ResolveAllowFiles).
			opPath := cfg.Logging.OperationalPath
			if opPath != "" && opPath != oplog.StderrSink && !filepath.IsAbs(opPath) {
				opPath = filepath.Join(filepath.Dir(configPath), opPath)
			}
			opLog, err := oplog.New(opPath, levelVar)
			if err != nil {
				return &configErr{err}
			}

			// Log the absolute path of the config file we actually
			// loaded (#45). When two trollbridge.yaml files exist
			// (cwd-local and ~/.config/), this single INFO line
			// removes the entire class of "I edited config X but the
			// proxy uses config Y" diagnostic friction.
			absConfigPath, absErr := filepath.Abs(configPath)
			if absErr != nil {
				absConfigPath = configPath
			}
			opLog.Info("config loaded",
				"event", oplog.EventConfigLoaded,
				"path", absConfigPath,
				"mode", string(cfg.Mode),
			)

			engine, err := policy.NewEngine(
				cfg.Mode,
				cfg.ResolveIncludePaths(configPath),
				policy.Phase1KnownModifiers(),
			)
			if err != nil {
				return &configErr{err}
			}
			auditLogger, err := audit.New(
				cfg.Logging.AuditPath,
				cfg.Logging.AuditBufferSize,
				audit.OverflowMode(cfg.Logging.AuditOverflow),
			)
			if err != nil {
				return &runtimeErr{err}
			}
			auditLogger.SetOpLog(opLog)
			srv, err := server.NewWithLoggers(cfg, engine, auditLogger, opLog)
			if err != nil {
				return &runtimeErr{err}
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			// Fast-path lists are inline in trollbridge.yaml's
			// `lists.allow` / `lists.deny`. The console pane writes
			// new patterns back to the file via configwrite and
			// triggers an in-process re-parse via the OnReload hook.
			if err := srv.SetLists(cfg.Lists.Allow, cfg.Lists.Deny); err != nil {
				return &configErr{err}
			}

			// Persist manual approve/deny decisions back to
			// lists.allow / lists.deny in trollbridge.yaml (closes
			// #49). Wired at the queue layer so that both in-process
			// (TUI) and attach-mode (mTLS control plane) approvals
			// converge here. The callback runs on the proxy host
			// (the queue lives in the daemon process), so the
			// proxy-host-vs-consumer-host distinction is satisfied
			// automatically.
			absPersistPath, persistErr := filepath.Abs(configPath)
			if persistErr != nil {
				absPersistPath = configPath
			}
			srv.Queue().SetDecisionPersist(func(req *types.RequestEvent, effect types.Effect, source string) {
				pattern := derivePersistPattern(req)
				if pattern == "" {
					return
				}
				var (
					changed bool
					werr    error
					event   string
					reason  string
				)
				switch effect {
				case types.EffectAllow:
					changed, werr = configwrite.AddAllow(absPersistPath, pattern)
					event = oplog.EventAllowlistAdded
					reason = "manual_approval"
				case types.EffectDeny:
					changed, werr = configwrite.AddDeny(absPersistPath, pattern)
					event = oplog.EventDenylistAdded
					reason = "manual_denial"
				default:
					return
				}
				if werr != nil {
					opLog.Warn("list persist failure",
						"event", oplog.EventListPersistFailure,
						"pattern", pattern,
						"source", source,
						"reason", reason,
						"error", werr.Error(),
						"config_path", absPersistPath)
					return
				}
				if !changed {
					return
				}
				opLog.Info("list persisted",
					"event", event,
					"pattern", pattern,
					"source", source,
					"reason", reason,
					"host", req.Host,
					"port", req.Port,
					"config_path", absPersistPath)
				freshCfg, lerr := config.Load(configPath)
				if lerr != nil {
					opLog.Error("list-reload re-parse failed",
						"event", oplog.EventAllowlistReloadFailure,
						"error", lerr.Error())
					return
				}
				_ = srv.ReloadListsFromConfig(freshCfg)
			})

			// SIGHUP triggers YAML rule reload.
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			go func() {
				for range hup {
					if err := engine.Reload(); err != nil {
						opLog.Error("rule reload failed", "event", oplog.EventRuleReloadFailure, "error", err.Error())
					} else {
						opLog.Info("rules reloaded", "event", oplog.EventRuleReload, "version", engine.RuleSetVersion())
					}
				}
			}()

			// Operator UI: the unified two-pane TUI when stdin is a
			// tty. The console pane reuses the same Backend that drove
			// the line-based REPL; it now runs character-by-character
			// inside the alt-screen UI alongside the approvals pane.
			tuiActive := !noConsole && console.IsInteractive(os.Stdin)
			installMode := "daemon"
			uiKind := "none"
			if tuiActive {
				installMode = "interactive"
				uiKind = "tty"
			}
			if !noConsole && console.IsInteractive(os.Stdin) {
				backend := &console.Backend{
					ConfigPath: configPath,
					LocalOnly:  true,
					OnReload: func() {
						freshCfg, err := config.Load(configPath)
						if err != nil {
							opLog.Error("list-reload re-parse failed",
								"event", oplog.EventAllowlistReloadFailure,
								"error", err.Error())
							return
						}
						_ = srv.ReloadListsFromConfig(freshCfg)
					},
					OnTest:   replTestFn(configPath),
					OnDoctor: replDoctorFn(configPath),
				}
				welcome := buildRunWelcome(srv.Addr(), string(cfg.Mode))
				// While the TUI holds the alt-screen, route operational
				// logs away from stderr so per-request INFO / WARN
				// lines do not corrupt the rendered frames (closes #56).
				// Only redirect when the operator did not explicitly
				// pick a path — an explicit file path is honored as-is.
				if cfg.Logging.OperationalPath == "" || cfg.Logging.OperationalPath == oplog.StderrSink {
					tuiLogPath := filepath.Join(os.TempDir(),
						fmt.Sprintf("trollbridge-%d.log", os.Getpid()))
					if f, openErr := os.OpenFile(tuiLogPath,
						os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); openErr == nil {
						if oplog.SwapWriter(opLog, f) {
							welcome += "\noperational log: " + tuiLogPath
							defer f.Close()
						} else {
							f.Close()
						}
					}
				}
				go func() {
					defer func() {
						if r := recover(); r != nil {
							opLog.Warn("operator UI crashed",
								"event", oplog.EventOperatorUIError,
								"error", fmt.Sprintf("%v", r))
						}
					}()
					if err := tui.RunOperator(ctx, tui.NewInProcessClientWithAdvisor(srv.Queue(), srv.Ops(), srv.Advisor()), os.Stdin, os.Stdout, backend, welcome, cancel, tui.Options{ChimeEnabled: cfg.TUI.Alerts.ChimeEnabled()}); err != nil {
						opLog.Warn("operator UI exited",
							"event", oplog.EventOperatorUIError,
							"error", err.Error())
					}
				}()
			}

			// Startup record: one INFO line naming the run mode so an
			// operator tailing the oplog (especially under systemd
			// where there is no operator UI) can answer "what is this
			// process?" from the first record. install_mode names the
			// operator-UI axis (interactive | daemon); ui names the
			// terminal axis (tty | none); default_decision and
			// on_timeout name the security-policy posture so a
			// default-ask + ui=none + on_timeout=deny deployment is
			// unambiguous in a single line. Key naming: install_mode
			// (not mode) avoids colliding with the existing mode= key
			// on event=config_loaded and event=listening, which carry
			// cfg.Mode (default-deny|allow|ask) — three lines fire
			// microseconds apart and a single key would carry two
			// ontologies.
			startupAttrs := []any{
				"event", oplog.EventStartup,
				"version", server.Version,
				"install_mode", installMode,
				"ui", uiKind,
				"default_decision", string(cfg.Mode),
				"approvals", "in-process",
				"on_timeout", cfg.Approvals.OnTimeout,
			}
			if !cfg.Control.Disabled() {
				startupAttrs = append(startupAttrs, "attach_endpoint", cfg.Control.Addr())
			}
			opLog.Info("startup", startupAttrs...)

			opLog.Info("listening",
				"event", oplog.EventListening,
				"addr", srv.Addr(),
				"mode", cfg.Mode,
				"rules", len(engine.Rules()),
				"rule_set_version", engine.RuleSetVersion(),
			)
			if !cfg.Control.Disabled() {
				opLog.Info("control listening",
					"event", oplog.EventControlListening,
					"addr", cfg.Control.Addr(),
				)
			}

			// Banner content has moved into the operator UI's console
			// pane scrollback for TTY runs (so the operator sees it
			// inside the same screen as the prompt). Keep the banner
			// path for non-tty stdin + TTY stdout — useful in scripts
			// that wrap `run` and want the listen address visible.
			if isStdoutTTY() && (noConsole || !console.IsInteractive(os.Stdin)) {
				printRunStartupBanner(cmd.OutOrStdout(), srv.Addr(), string(cfg.Mode))
				if noConsole {
					fmt.Fprintln(cmd.OutOrStdout(), "Daemon mode (--no-console): operator UI suppressed.")
					fmt.Fprintln(cmd.OutOrStdout(), "Drive approvals from another host via 'trollbridge attach', or rely on")
					fmt.Fprintln(cmd.OutOrStdout(), "approvals.timeout_seconds / approvals.signal_after_seconds.")
				}
			}

			serveErr := srv.ListenAndServe(ctx)
			// Symmetric counterpart to event=startup: one INFO line on
			// graceful exit so an operator tailing the oplog (especially
			// under systemd, journalctl, or k8s where the process is
			// not in the foreground) can answer "did the proxy stop
			// cleanly or get killed?" Wires the previously dead
			// oplog.EventShutdown constant. Fires regardless of
			// serveErr — the daemon is exiting either way; the field
			// distinguishes clean (no err) from error exit.
			shutdownAttrs := []any{
				"event", oplog.EventShutdown,
				"version", server.Version,
				"install_mode", installMode,
			}
			if serveErr != nil {
				shutdownAttrs = append(shutdownAttrs, "error", serveErr.Error())
			}
			opLog.Info("shutdown", shutdownAttrs...)

			if serveErr != nil {
				return &runtimeErr{serveErr}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml (default: $TROLLBRIDGE_CONFIG, then ./trollbridge.yaml)")
	cmd.Flags().BoolVar(&noConsole, "no-console", false, "disable the operator UI even when stdin is a TTY (use for daemon-mode deployments; drive approvals via 'trollbridge attach' or approvals.timeout_seconds / approvals.signal_after_seconds)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "alias for --log-level=debug; emits per-request lifecycle records on the operational log")
	return cmd
}

// replTestFn returns a closure that the console pane invokes for
// `test <url>` (issue #31). Mirrors the CLI's runTest pipeline,
// minus the audit-log decision correlation: the REPL is in-process
// with the same daemon writing the audit log, so racing the polling
// reader against the just-written entry would be flaky and add zero
// information versus the response. Body is bounded to a friendly
// snippet so a chatty endpoint does not flood the prompt.
func replTestFn(configPath string) func(io.Writer, string) error {
	return func(out io.Writer, urlArg string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		method := "GET"
		urlStr := strings.TrimSpace(urlArg)
		if i := strings.IndexAny(urlStr, " \t"); i > 0 {
			head := urlStr[:i]
			rest := strings.TrimSpace(urlStr[i:])
			if isHTTPMethod(head) {
				method = strings.ToUpper(head)
				urlStr = rest
			}
		}
		req, err := buildTestRequest(urlStr, method, nil, "", "")
		if err != nil {
			return err
		}
		return runTest(context.Background(), out, cfg, req, testOpts{
			// 512 bytes / 3 lines keeps the response body from
			// pushing status, decision, reason, and hint lines off
			// the small console pane (closes #40). Operators who
			// need the full body run `trollbridge test <url> --raw`
			// or `--show-body N` from a regular shell.
			ShowBody:     512,
			MaxBodyLines: 3,
			// MaxHeaders mirrors the body cap for the response-header
			// block — 10+ headers on a typical production endpoint
			// scroll status / decision off the small pane. The shell
			// CLI does not set MaxHeaders; default 0 = unlimited.
			MaxHeaders: 4,
			Timeout:    15 * time.Second,
			NoDecision: true,
			ConfigPath: configPath,
		})
	}
}

// replDoctorFn returns the closure invoked for the console pane's
// `doctor` command. It re-uses the CLI doctor implementation by
// spinning up a fresh cobra command and binding its stdout/stderr
// to the writer the TUI passes in.
func replDoctorFn(configPath string) func(io.Writer) error {
	return func(out io.Writer) error {
		cmd := newDoctorCmd()
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs([]string{"-c", configPath})
		return cmd.Execute()
	}
}

func isHTTPMethod(s string) bool {
	switch strings.ToUpper(s) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// isStdoutTTY reports whether the process's stdout is a terminal.
// Wrapped as a var so tests can substitute a static value.
var isStdoutTTY = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// buildRunWelcome renders the "you're up — try this next" content
// that used to print as a banner before run blocked. The same lines
// now go into the operator UI's console-pane scrollback so the
// operator sees them inside the alt-screen layout.
func buildRunWelcome(addr, mode string) string {
	var buf bytes.Buffer
	printRunStartupBanner(&buf, addr, mode)
	return buf.String()
}

// printRunStartupBanner writes the run startup content to out. It is
// used for non-tty stdin + TTY stdout (where the operator UI is not
// drawn, but the operator wanted to see the listen address) and as
// the source of the welcome scrollback inside the operator UI.
func printRunStartupBanner(out io.Writer, addr, mode string) {
	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	w("trollbridge is listening on %s (mode: %s).\n", addr, mode)
	w("\n")
	if mode == "default-deny" {
		w("Note: default-deny means your first request will be declined (HTTP 470).\n")
		w("That is the proxy enforcing the policy, not a bug. To allow a host,\n")
		w("either add it to lists.allow in trollbridge.yaml or, in this UI,\n")
		w("type: allow <hostname>\n")
		w("\n")
	}
	w("In another terminal, try:\n")
	w("  trollbridge test https://example.com\n")
	w("\n")
	w("Or wire up any HTTP client:\n")
	w("  eval \"$(trollbridge env)\" && curl -sI https://example.com\n")
	w("\n")
	w("Stop with Ctrl-C.\n")
}

// derivePersistPattern returns the lists.allow / lists.deny pattern
// that should be written when an operator manually approves or denies
// the held request `req`. The user picked "full URL for now" — until
// LLM-driven generalization lands as a follow-up, the pattern is the
// most-specific form the request supports:
//
//   - CONNECT (HTTPS pass-through, no path): "<host>:<port>"
//     matches the typed-REPL `allow api.github.com:443` precedent.
//   - intercepted HTTPS or plain HTTP: "<scheme>://<host>:<port><path>"
//     where <scheme> is "http" or "https" (collapsing the internal
//     "https-tunneled" / "https-intercepted" telemetry strings).
//
// The narrow grain means a sibling path on the same host re-prompts;
// that is the explicit trade — operator chose "full URL" to ship now
// and surface generalization as a follow-up enhancement (#49 comment
// trail).
func derivePersistPattern(req *types.RequestEvent) string {
	if req == nil || req.Host == "" {
		return ""
	}
	host := req.Host
	port := req.Port
	if req.Method == "CONNECT" || req.Path == "" {
		if port == 0 {
			return host
		}
		return fmt.Sprintf("%s:%d", host, port)
	}
	scheme := req.Scheme
	switch scheme {
	case "https-tunneled", "https-intercepted":
		scheme = "https"
	case "":
		scheme = "http"
	}
	if port != 0 {
		return fmt.Sprintf("%s://%s:%d%s", scheme, host, port, req.Path)
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, req.Path)
}
