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
	"github.com/dandriscoll/trollbridge/internal/configwatch"
	"github.com/dandriscoll/trollbridge/internal/configwrite"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/approvals"
	"github.com/dandriscoll/trollbridge/internal/server"
	"github.com/dandriscoll/trollbridge/internal/suggestion"
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

			// Early stderr logger for failures that happen before the
			// configured operational logger can be built (#128).
			// oplog.New with StderrSink writes to os.Stderr and cannot
			// fail (no file is opened) — the error is safely ignored;
			// TestNew_StderrSinkNeverErrors pins that invariant.
			startupLog, _ := oplog.New(oplog.StderrSink, nil)

			cfg, err := config.Load(configPath)
			if err != nil {
				startupLog.Error("config load failed",
					"event", oplog.EventConfigLoadFailure,
					"path", configPath,
					"error", err.Error(),
				)
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
				startupLog.Error("operational log init failed",
					"event", oplog.EventConfigLoadFailure,
					"path", opPath,
					"error", err.Error(),
				)
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
				opLog.Error("startup failed",
					"event", oplog.EventStartupFailure,
					"stage", "policy",
					"paths", cfg.ResolveIncludePaths(configPath),
					"error", err.Error(),
				)
				return &configErr{err}
			}
			auditLogger, err := audit.New(
				cfg.Logging.AuditPath,
				cfg.Logging.AuditBufferSize,
				audit.OverflowMode(cfg.Logging.AuditOverflow),
			)
			if err != nil {
				opLog.Error("startup failed",
					"event", oplog.EventStartupFailure,
					"stage", "audit",
					"audit_path", cfg.Logging.AuditPath,
					"error", err.Error(),
				)
				return &runtimeErr{err}
			}
			auditLogger.SetOpLog(opLog)
			// Config validator already ensured the level string is
			// legal; a parse error here would be a programmer
			// mistake, not an operator one. The test-only
			// TROLLBRIDGE_TEST_FAIL_STAGE=audit_level env hook
			// (#166) lets the e2e suite exercise the post-validator
			// branch by forcing an unparseable level here.
			levelStr := cfg.Logging.AuditLevel
			if os.Getenv("TROLLBRIDGE_TEST_FAIL_STAGE") == "audit_level" {
				levelStr = "__test_invalid_level__"
			}
			lvl, err := audit.ParseLevel(levelStr)
			if err != nil {
				opLog.Error("startup failed",
					"event", oplog.EventStartupFailure,
					"stage", "audit_level",
					"audit_level", cfg.Logging.AuditLevel,
					"error", err.Error(),
				)
				return &runtimeErr{err}
			}
			auditLogger.SetLevel(lvl)
			// #143 part b: when the audit-level filter is engaged,
			// emit one INFO startup notice so an operator who later
			// looks at the audit log and sees fewer entries than
			// expected sees the cause inline.
			if lvl != audit.LevelAll {
				opLog.Info("audit-level filter engaged",
					"event", "audit_level_filter_active",
					"audit_level", lvl.String(),
					"note", "static-policy entries are filtered out; see audit.LevelFiltered() / `trollbridge logs review` for the full set")
			}
			// #166: test-only hook lets the e2e suite exercise the
			// stage=server branch without crafting a config that
			// passes earlier stages but fails server.New*.
			if os.Getenv("TROLLBRIDGE_TEST_FAIL_STAGE") == "server" {
				err := fmt.Errorf("forced server-stage failure via TROLLBRIDGE_TEST_FAIL_STAGE")
				opLog.Error("startup failed",
					"event", oplog.EventStartupFailure,
					"stage", "server",
					"error", err.Error(),
				)
				return &runtimeErr{err}
			}
			srv, err := server.NewWithLoggers(cfg, engine, auditLogger, opLog)
			if err != nil {
				opLog.Error("startup failed",
					"event", oplog.EventStartupFailure,
					"stage", "server",
					"error", err.Error(),
				)
				return &runtimeErr{err}
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			// Fast-path lists are inline in trollbridge.yaml's
			// `lists.allow` / `lists.deny`. The console pane writes
			// new patterns back to the file via configwrite and
			// triggers an in-process re-parse via the OnReload hook.
			// #166: test-only hook forces a lists-stage failure for
			// the e2e suite without needing a malformed pattern that
			// the config-load also rejects.
			if os.Getenv("TROLLBRIDGE_TEST_FAIL_STAGE") == "lists" {
				err := fmt.Errorf("forced lists-stage failure via TROLLBRIDGE_TEST_FAIL_STAGE")
				opLog.Error("startup failed",
					"event", oplog.EventStartupFailure,
					"stage", "lists",
					"allow_count", len(cfg.Lists.Allow),
					"deny_count", len(cfg.Lists.Deny),
					"error", err.Error(),
				)
				return &configErr{err}
			}
			if err := srv.SetLists(cfg.Lists.Allow, cfg.Lists.Deny); err != nil {
				opLog.Error("startup failed",
					"event", oplog.EventStartupFailure,
					"stage", "lists",
					"allow_count", len(cfg.Lists.Allow),
					"deny_count", len(cfg.Lists.Deny),
					"error", err.Error(),
				)
				return &configErr{err}
			}

			// External-edit watcher: declared here (before the
			// DecisionPersist + console OnReload closures) so both
			// configwrite paths can call yamlWatcher.MarkReloaded
			// to suppress the redundant external-reload fire on
			// internal writes (closes #80). Started further down,
			// after engine and other dependencies are ready.
			yamlWatcher := configwatch.New(configPath)

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
				// #193 defense-in-depth: alignment principle §1 — the LLM
				// advisor's verdicts must never write to lists.allow /
				// lists.deny. queue.go ResolveByAdvisor was patched to
				// never fire this callback for advisor decisions, but
				// this guard rejects the write at the callback layer
				// too, so a future re-wiring of advisor → persistCb is
				// caught and surfaced (WARN) instead of silently
				// mutating the operator's lists.
				if source == "llm-advisor" {
					opLog.Warn("advisor list mutation refused",
						"event", oplog.EventAdvisorListMutationRefused,
						"effect", string(effect),
						"source", source,
						"host", req.Host,
						"reason", "alignment_principle_1_lists_are_human_only")
					return
				}
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
				// #194: route through OperatorApprove / OperatorDeny so
				// the pattern is removed from the OPPOSITE list before
				// being added to the target list. AddAllow / AddDeny
				// alone leave the pattern on both lists and deny wins
				// on reload (silently no-op'ing the operator's action).
				// The consolidate-then-add primitive is the single
				// load-bearing write path for operator actions; see
				// internal/configwrite/configwrite.go OperatorApprove
				// doc for caller discipline.
				var (
					removed     bool
					removeErr   error
				)
				switch effect {
				case types.EffectAllow:
					removed, changed, removeErr, werr = configwrite.OperatorApprove(absPersistPath, pattern)
					event = oplog.EventAllowlistAdded
					reason = "manual_approval"
				case types.EffectDeny:
					removed, changed, removeErr, werr = configwrite.OperatorDeny(absPersistPath, pattern)
					event = oplog.EventDenylistAdded
					reason = "manual_denial"
				default:
					return
				}
				if removeErr != nil {
					opLog.Warn("list consolidation remove failure",
						"event", oplog.EventListPersistFailure,
						"pattern", pattern,
						"source", source,
						"reason", reason,
						"error", removeErr.Error(),
						"config_path", absPersistPath)
					// Best-effort: continue to the add. Pattern may end
					// up on both lists if the add succeeds, but failing
					// the whole persist would lose the operator's intent
					// entirely. The structural test guards against the
					// happy-path case.
				}
				_ = removed // currently informational; could be logged at INFO if useful
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
				_ = reloadAfterInternalWrite(srv, configPath, yamlWatcher, opLog)
			})

			// SIGHUP triggers YAML rule reload.
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			go func() {
				for range hup {
					err := engine.Reload()
					if err != nil {
						opLog.Error("rule reload failed", "event", oplog.EventRuleReloadFailure, "error", err.Error())
					} else {
						opLog.Info("rules reloaded", "event", oplog.EventRuleReload, "version", engine.RuleSetVersion())
					}
					srv.RecordReload("rules", err)
				}
			}()

			// External edits to trollbridge.yaml trigger an in-process
			// reload of lists and rules (closes #80). The watcher
			// itself was declared earlier so configwrite closures
			// could capture it; here we start the poll loop.
			go func() {
				_ = yamlWatcher.Start(ctx, func() {
					opLog.Info("config file change detected — reloading",
						"event", "config_change_detected",
						"config_path", configPath)
					freshCfg, err := config.Load(configPath)
					if err != nil {
						opLog.Error("list-reload re-parse failed",
							"event", oplog.EventAllowlistReloadFailure,
							"error", err.Error())
						// Re-parse failure shadows lists+rules+config below;
						// surface as a "lists" reload failure since that
						// was the next step in the cascade. The TUI badge
						// fires until the operator fixes the file.
						srv.RecordReload("lists", err)
						return
					}
					listsErr := srv.ReloadListsFromConfig(freshCfg)
					if listsErr != nil {
						opLog.Error("list reload failed",
							"event", oplog.EventAllowlistReloadFailure,
							"error", listsErr.Error())
					}
					srv.RecordReload("lists", listsErr)
					rulesErr := engine.Reload()
					if rulesErr != nil {
						opLog.Error("rule reload failed",
							"event", oplog.EventRuleReloadFailure, "error", rulesErr.Error())
					} else {
						opLog.Info("rules reloaded",
							"event", oplog.EventRuleReload,
							"version", engine.RuleSetVersion())
					}
					srv.RecordReload("rules", rulesErr)
					// Hot-reload the per-section knobs that don't
					// require a restart (#111). Mode, approvals
					// timing, and forwarder timeouts get picked up
					// without a daemon bounce.
					srv.ReloadConfig(freshCfg)
					srv.RecordReload("config", nil)
				})
			}()

			// Quiet-moment suggestion lifecycle (#168). The Manager
			// owns the detector + advisor ask + accept/decline +
			// decline-row YAML write. Tick every 5s; the manager's
			// quiet predicate gates the expensive work.
			sugMgr := suggestion.New(
				absPersistPath,
				srv.Cfg,
				queueAdapter{q: srv.Queue()},
				listsAdapter{cfgGetter: srv.Cfg},
				advisorAdapter{srv.Advisor()},
				writerAdapter{},
				func() {
					_ = reloadAfterInternalWrite(srv, configPath, yamlWatcher, opLog)
				},
				opLog,
			)
			srv.SetInboundHook(sugMgr.NoteInbound)
			// Pattern-suggestion wiring (#203 follow-up). The
			// recognizer comes from the server's pattern registry;
			// rulesPath is the first configured include file (or
			// empty, in which case Manager surfaces a clear error
			// on accept).
			sugMgr.SetPatternRecognizer(patternRecognizerAdapter{srv: srv})
			if includes := srv.Cfg().ResolveIncludePaths(configPath); len(includes) > 0 {
				sugMgr.SetRulesPath(includes[0])
			}
			srv.Control().SetSuggestion(suggestion.ControlAdapter{M: sugMgr})
			// #209: expose open mode over the control plane so an
			// attach-mode operator can open/extend/close it. The server
			// itself satisfies control.OpenModeProvider.
			srv.Control().SetOpenMode(srv)
			// #189: wire the list-edit writer so attach-mode operators
			// can mutate allow/deny via /v1/lists/allow + /deny. Each
			// mutation reloads the in-memory matcher / suggestion view
			// (reloadAfterInternalWrite) to match the in-process
			// operator path's reload semantics.
			srv.Control().SetListWriter(listWriterAdapter{
				path:    absPersistPath,
				reload:  func() { _ = reloadAfterInternalWrite(srv, configPath, yamlWatcher, opLog) },
				opLog:   opLog,
			})
			go func() {
				t := time.NewTicker(5 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						sugMgr.Tick(ctx)
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
						srv.RecordReload("lists",
							reloadAfterInternalWrite(srv, configPath, yamlWatcher, opLog))
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
					inproc := tui.WithOpenMode(tui.NewInProcessClientWithSuggestion(srv.Queue(), srv.Ops(), srv.Advisor(), srv, tuiSuggestionAdapter{m: sugMgr}), srv)
					histAdapter := tuiHistoryAdapter{h: srv.Engine().History()}
					if err := tui.RunOperator(ctx, inproc, os.Stdin, os.Stdout, backend, welcome, cancel, tui.Options{
						ChimeEnabled: cfg.TUI.Alerts.ChimeEnabled(),
						History:      histAdapter,
					}); err != nil {
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
// the held request `req`. The pattern is the most-specific form the
// request supports, with the request's method prefixed so operators
// can later generalise across methods through the TUI's post-approve
// prompt (#85):
//
//   - CONNECT (HTTPS pass-through, no path): "CONNECT <host>:<port>"
//   - intercepted HTTPS or plain HTTP:
//     "<METHOD> <scheme>://<host>:<port><path>"
//     where <scheme> is "http" or "https" (collapsing the internal
//     "https-tunneled" / "https-intercepted" telemetry strings).
//
// Pre-#85 callers wrote the bare host or URL — those patterns
// continue to match any method (hostlist.Pattern.anyMethod=true).
func derivePersistPattern(req *types.RequestEvent) string {
	if req == nil || req.Host == "" {
		return ""
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	host := req.Host
	port := req.Port
	if method == "CONNECT" || req.Path == "" {
		if port == 0 {
			return method + " " + host
		}
		return fmt.Sprintf("%s %s:%d", method, host, port)
	}
	scheme := req.Scheme
	switch scheme {
	case "https-tunneled", "https-intercepted":
		scheme = "https"
	case "":
		scheme = "http"
	}
	if port != 0 {
		return fmt.Sprintf("%s %s://%s:%d%s", method, scheme, host, port, req.Path)
	}
	return fmt.Sprintf("%s %s://%s%s", method, scheme, host, req.Path)
}


// queueAdapter satisfies suggestion.QueueProvider with the daemon's
// approvals queue.
type queueAdapter struct{ q *approvals.Queue }

func (a queueAdapter) Pending() []suggestion.QueueSnapshot {
	pending := a.q.Pending()
	out := make([]suggestion.QueueSnapshot, 0, len(pending))
	for _, p := range pending {
		out = append(out, suggestion.QueueSnapshot{ID: p.ID})
	}
	return out
}

// reloadAfterInternalWrite re-parses the config the daemon itself just wrote
// and refreshes BOTH the in-memory matcher (ReloadListsFromConfig) and the
// cfg pointer the rest of the daemon reads (ReloadConfig), then tells the
// external-edit watcher we already reloaded so it does not re-fire on our own
// write (#80). Refreshing s.cfg is load-bearing: the suggestion engine reads
// its lists via srv.Cfg(); a matcher-only reload leaves it scanning stale
// lists and re-offering an already-accepted generalization (#183). Returns the
// lists-reload error for callers that record reload status.
func reloadAfterInternalWrite(srv *server.Server, configPath string, w *configwatch.Watcher, opLog *slog.Logger) error {
	freshCfg, err := config.Load(configPath)
	if err != nil {
		opLog.Error("list-reload re-parse failed",
			"event", oplog.EventAllowlistReloadFailure, "error", err.Error())
		return err
	}
	listsErr := srv.ReloadListsFromConfig(freshCfg)
	srv.ReloadConfig(freshCfg)
	w.MarkReloaded()
	return listsErr
}

// listsAdapter exposes the daemon's live config.Lists to the
// suggestion package via a config getter — re-reads every Tick so
// external edits land without a restart.
type listsAdapter struct{ cfgGetter func() *config.Config }

func (a listsAdapter) CurrentLists() ([]string, []string, []config.DeclinedSuggestion) {
	c := a.cfgGetter()
	if c == nil {
		return nil, nil, nil
	}
	return c.Lists.Allow, c.Lists.Deny, c.Lists.DeclinedSuggestions
}

// patternRecognizerAdapter wires the server's built-in pattern
// registry to the suggestion package (#203 follow-up). Keeps the
// suggestion package free of an internal/server import.
type patternRecognizerAdapter struct {
	srv *server.Server
}

func (a patternRecognizerAdapter) Recognize(host string, port int, scheme, path string) (string, map[string]string, bool) {
	return a.srv.RecognizePattern(host, port, scheme, path)
}

// writerAdapter wraps internal/configwrite for the suggestion
// package — keeps the package free of a direct configwrite import.
type writerAdapter struct{}

func (writerAdapter) Generalize(path, list, pat string, sources []string) (bool, error) {
	return configwrite.Generalize(path, list, pat, sources)
}
func (writerAdapter) AddDeclinedSuggestion(path string, src, axes []string, at string) (bool, error) {
	return configwrite.AddDeclinedSuggestion(path, configwrite.DeclinedSuggestion{
		SourceEntries: src,
		AxesDeclined:  axes,
		DeclinedAt:    at,
	})
}
func (writerAdapter) AcceptPatternSuggestion(rulesPath, listsPath, list, ruleID, pattern string, components map[string]string, method, effect string, sources []string) (bool, bool, error) {
	return configwrite.AcceptPatternSuggestion(rulesPath, listsPath, list, configwrite.PatternRule{
		ID:          ruleID,
		Description: "auto-suggested from " + pattern + " pattern detector",
		Pattern:     pattern,
		Components:  components,
		Method:      method,
		Effect:      effect,
	}, sources)
}

// tuiSuggestionAdapter adapts the suggestion.Manager to the TUI's
// SuggestionSource so the embedded `trollbridge run` UI can surface and
// resolve quiet-moment suggestions in-process (#172). It reuses
// suggestion.ControlAdapter for the Manager→row conversion (incl. the
// axes-remaining count) so the in-process and HTTP surfaces stay
// identical.
type tuiSuggestionAdapter struct{ m *suggestion.Manager }

func (a tuiSuggestionAdapter) ActiveSuggestion() *tui.Suggestion {
	row := suggestion.ControlAdapter{M: a.m}.Active()
	if row == nil {
		return nil
	}
	return &tui.Suggestion{
		ID:                row.SuggestionID,
		Axis:              row.Axis,
		List:              row.List,
		SourceEntries:     row.SourceEntries,
		SuggestedPattern:  row.SuggestedPattern,
		Reason:            row.Reason,
		AxesRemaining:     row.AxesRemaining,
		PatternName:       row.PatternName,
		PatternComponents: row.PatternComponents,
		PatternMethod:     row.PatternMethod,
	}
}

func (a tuiSuggestionAdapter) AcceptSuggestion(id string) error {
	return a.m.Accept(context.Background(), id)
}

func (a tuiSuggestionAdapter) DeclineSuggestion(id string) error {
	return a.m.Decline(context.Background(), id)
}

func (a tuiSuggestionAdapter) SuggestNow() *tui.Suggestion {
	a.m.SuggestNow(context.Background())
	return a.ActiveSuggestion()
}

// tuiHistoryAdapter satisfies tui.DecisionHistorySource over the
// policy engine's sliding-window decision history (closes #192).
// The TUI consults it at row-render time to wrap rows whose
// current decision contradicts a recent prior decision on the
// same host.
type tuiHistoryAdapter struct{ h *policy.History }

func (a tuiHistoryAdapter) PriorOppositeEffect(host, currentEffect string) bool {
	if a.h == nil || host == "" || currentEffect == "" {
		return false
	}
	return a.h.HasOppositeEffect(host, currentEffect)
}

// listWriterAdapter satisfies control.ListWriter on the proxy
// side (#189). Routes add operations through OperatorApprove /
// OperatorDeny (the consolidate-then-add primitive from #194) so
// attach-mode mutations and in-process operator mutations
// produce identical YAML outcomes. Calls reload after every
// successful write so the in-memory matcher / suggestion view /
// cfg.Cfg() observer all see the new state.
type listWriterAdapter struct {
	path   string
	reload func()
	opLog  *slog.Logger
}

func (a listWriterAdapter) AddAllow(pattern string) (bool, error) {
	_, changed, _, err := configwrite.OperatorApprove(a.path, pattern)
	if err != nil {
		return false, err
	}
	if changed && a.reload != nil {
		a.reload()
	}
	a.logMutation("allow_added", pattern, changed)
	return changed, nil
}

func (a listWriterAdapter) AddDeny(pattern string) (bool, error) {
	_, changed, _, err := configwrite.OperatorDeny(a.path, pattern)
	if err != nil {
		return false, err
	}
	if changed && a.reload != nil {
		a.reload()
	}
	a.logMutation("deny_added", pattern, changed)
	return changed, nil
}

func (a listWriterAdapter) RemoveAllow(pattern string) (bool, error) {
	changed, err := configwrite.RemoveAllow(a.path, pattern)
	if err != nil {
		return false, err
	}
	if changed && a.reload != nil {
		a.reload()
	}
	a.logMutation("allow_removed", pattern, changed)
	return changed, nil
}

func (a listWriterAdapter) RemoveDeny(pattern string) (bool, error) {
	changed, err := configwrite.RemoveDeny(a.path, pattern)
	if err != nil {
		return false, err
	}
	if changed && a.reload != nil {
		a.reload()
	}
	a.logMutation("deny_removed", pattern, changed)
	return changed, nil
}

func (a listWriterAdapter) logMutation(action, pattern string, changed bool) {
	if a.opLog == nil {
		return
	}
	event := oplog.EventAllowlistAdded
	switch action {
	case "deny_added":
		event = oplog.EventDenylistAdded
	case "allow_removed", "deny_removed":
		// Reuse the list-mutation event class so operators can
		// grep allowlist_added / denylist_added for the
		// canonical mutation surface. The action field carries
		// the direction.
		event = oplog.EventAllowlistAdded
		if action == "deny_removed" {
			event = oplog.EventDenylistAdded
		}
	}
	a.opLog.Info("list persisted (attach)",
		"event", event,
		"pattern", pattern,
		"source", "attach",
		"reason", action,
		"changed", changed,
		"config_path", a.path,
	)
}

// advisorAdapter wraps advisor.Service so the suggestion package
// can mock it. Pre-existing Service methods are unchanged.
type advisorAdapter struct{ svc *advisor.Service }

func (a advisorAdapter) Suggest(ctx context.Context, in advisor.SuggestionInput) (advisor.SuggestionOutput, time.Duration, error) {
	if a.svc == nil {
		// No advisor configured — fall back to the deterministic
		// path (mirrors the in-service nil-provider behavior).
		return advisor.SuggestionOutput{}, 0, advisor.ErrDisabled
	}
	return a.svc.Suggest(ctx, in)
}
