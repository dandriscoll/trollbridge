package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/dandriscoll/trollbridge/internal/audit"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/console"
	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/server"
	"github.com/spf13/cobra"
)

// newQuickstartCmd implements `trollbridge quickstart`: write a
// minimum-setup default config (if absent) and immediately start
// the proxy. Targets the "30-second start" flow named in issue #17.
//
// The flavor of the default config is the same as `init`'s static
// template with one tweak — controller: 0 — because the quickstart
// is for laptop dev where the operator does not yet have a CA and
// does not want to run as root. Without a controller there is no
// mTLS dependency, so no CA is required.
//
// The operator who wants the full proxy posture (controller mTLS,
// TLS interception) runs `trollbridge init` and `trollbridge ca
// init` instead. Quickstart is the on-ramp, not the destination.
func newQuickstartCmd() *cobra.Command {
	var configPath string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "quickstart",
		Short: "Write a default trollbridge.yaml (if absent) and start the proxy in one step.",
		Long: `Quickstart is the on-ramp for the "30-second start" flow.

If trollbridge.yaml does not exist in the current directory (or at
$TROLLBRIDGE_CONFIG, if set), quickstart writes a minimum-setup
default — the same as ` + "`trollbridge init --non-interactive`" + ` would
write, with the controller surface disabled so no CA is required.
Then it starts the proxy in the foreground, exactly as
` + "`trollbridge run`" + ` would.

The default mode is default-deny. Your first request through the
proxy will be declined (HTTP 470) — the startup banner names this
and tells you how to allow a host.

For the full proxy posture (controller mTLS, TLS interception),
run ` + "`trollbridge init`" + ` and ` + "`sudo trollbridge ca init`" + ` instead.
Quickstart is the on-ramp, not the destination.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			out := cmd.OutOrStdout()

			created := false
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
					return &runtimeErr{err}
				}
				body := quickstartConfigYAML()
				if err := os.WriteFile(configPath, []byte(body), 0o640); err != nil {
					return &runtimeErr{err}
				}
				fmt.Fprintf(out, "trollbridge quickstart: wrote %s\n", configPath)
				created = true
			} else if err != nil {
				return &runtimeErr{err}
			}
			if !created {
				fmt.Fprintf(out, "trollbridge quickstart: using existing %s\n", configPath)
			}

			return runProxyLoop(cmd, configPath, verbose)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml (default: $TROLLBRIDGE_CONFIG, then ./trollbridge.yaml)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "alias for --log-level=debug")
	return cmd
}

// quickstartConfigYAML is the static default written by quickstart
// when no trollbridge.yaml exists. Differs from `init`'s static
// default by one line: control is disabled so no CA is required to
// start the daemon.
func quickstartConfigYAML() string {
	body := defaultConfigYAML
	// Disable the controller so no CA is required at startup. The
	// operator who wants the controller runs `trollbridge init` +
	// `sudo trollbridge ca init` for the full posture.
	body = strings.Replace(body, "control: lo:8081", "control: 0", 1)
	return body
}

// runProxyLoop is the shared body between `run` and `quickstart`.
// It loads the config, builds the server, prints the startup
// banner on a TTY, and blocks until the context is cancelled.
//
// Factoring this out lets both commands share the operational
// behavior without duplicating the wiring; quickstart's only added
// behavior is the maybe-write-config step before the loop.
func runProxyLoop(cmd *cobra.Command, configPath string, verbose bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return &configErr{err}
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(slog.LevelInfo)
	if resolvedLogLevel != nil {
		levelVar.Set(*resolvedLogLevel)
	} else if verbose {
		levelVar.Set(slog.LevelDebug)
	}

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

	if err := srv.SetLists(cfg.Lists.Allow, cfg.Lists.Deny); err != nil {
		return &configErr{err}
	}

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

	if console.IsInteractive(os.Stdin) {
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
}
