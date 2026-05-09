package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/server"
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
			// `lists.allow` / `lists.deny`. The console REPL writes
			// new patterns back to the file via configwrite and
			// triggers an in-process re-parse via console.Config.
			if err := srv.SetLists(cfg.Lists.Allow, cfg.Lists.Deny); err != nil {
				return &configErr{err}
			}

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

			// Console REPL when stdin is a tty. REPL mutations write
			// back to trollbridge.yaml and trigger an in-process
			// re-parse of the lists.
			if !noConsole && console.IsInteractive(os.Stdin) {
				go func() {
					_ = console.Run(ctx, console.Config{
						ConfigPath: configPath,
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
					})
				}()
			}

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

			if isStdoutTTY() {
				printRunStartupBanner(cmd.OutOrStdout(), srv.Addr(), string(cfg.Mode))
			}

			if err := srv.ListenAndServe(ctx); err != nil {
				return &runtimeErr{err}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml (default: $TROLLBRIDGE_CONFIG, then ./trollbridge.yaml)")
	cmd.Flags().BoolVar(&noConsole, "no-console", false, "disable the interactive console even when stdin is a tty")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "alias for --log-level=debug; emits per-request lifecycle records on the operational log")
	return cmd
}

// isStdoutTTY reports whether the process's stdout is a terminal.
// Wrapped as a var so tests can substitute a static value.
var isStdoutTTY = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// printRunStartupBanner writes a one-screen "you're up — try this
// next" block to out, suitable for human operators who just ran
// `trollbridge run` on a terminal. The banner names the listen
// address, the policy mode (so a default-deny operator knows why
// their first curl will be refused), and copy-pasteable next-step
// commands.
//
// The function is suppressed by the caller when stdout is not a
// TTY; the structured "listening" log line still fires for
// log-consumers in non-TTY environments.
func printRunStartupBanner(out io.Writer, addr, mode string) {
	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	w("\n")
	w("trollbridge is listening on %s (mode: %s).\n", addr, mode)
	w("\n")
	if mode == "default-deny" {
		// Closes #16: a first-time operator under default-deny will
		// see their first request declined. Tell them up front that
		// the decline is the policy doing its job, and how to allow
		// the host they want to test.
		w("Note: default-deny means your first request will be declined (HTTP 470).\n")
		w("That is the proxy enforcing the policy, not a bug. To allow a host,\n")
		w("either add it to lists.allow in trollbridge.yaml or, in this REPL,\n")
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
	w("\n")
}
