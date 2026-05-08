package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/dandriscoll/drawbridge/internal/audit"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/console"
	"github.com/dandriscoll/drawbridge/internal/oplog"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/server"
	"github.com/spf13/cobra"
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

			// Fast-path lists are inline in drawbridge.yaml's
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
			// back to drawbridge.yaml and trigger an in-process
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

			if err := srv.ListenAndServe(ctx); err != nil {
				return &runtimeErr{err}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml (default: $DRAWBRIDGE_CONFIG, then $XDG_CONFIG_HOME/drawbridge/drawbridge.yaml)")
	cmd.Flags().BoolVar(&noConsole, "no-console", false, "disable the interactive console even when stdin is a tty")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "alias for --log-level=debug; emits per-request lifecycle records on the operational log")
	return cmd
}
