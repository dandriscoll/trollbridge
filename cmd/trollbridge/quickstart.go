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
	"github.com/dandriscoll/trollbridge/internal/tui"
	"github.com/spf13/cobra"
)

// newQuickstartCmd implements `trollbridge quickstart`: write a
// minimum-setup user-mode default config (if absent) and
// immediately start the proxy. Targets the "30-second start" flow
// named in issue #17.
//
// quickstart is explicitly the user-mode on-ramp: every path
// anchors at cwd, the operator runs as themselves, no sudo at any
// step. The controller surface is disabled in the rendered yaml
// so no CA is required at startup.
//
// The operator who wants the full daemon-mode posture (systemd
// unit, controller mTLS, TLS interception) runs `trollbridge init`
// and picks install mode = daemon, then `sudo -u trollbridge
// trollbridge ca init`. Quickstart is the on-ramp, not the
// destination.
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

For the full daemon-mode posture (systemd unit, controller mTLS,
TLS interception), run ` + "`trollbridge init`" + ` and pick install
mode = daemon, then ` + "`sudo -u trollbridge trollbridge ca init`" + `.
Quickstart is the on-ramp, not the destination.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			out := cmd.OutOrStdout()

			created := false
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				configDir := filepath.Dir(configPath)
				if err := os.MkdirAll(configDir, 0o750); err != nil {
					return &runtimeErr{err}
				}
				absDir, abserr := filepath.Abs(configDir)
				if abserr != nil {
					absDir = configDir
				}
				body := quickstartConfigYAML(absDir)
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

// quickstartConfigYAML is the user-mode default written by
// `trollbridge quickstart` when no trollbridge.yaml exists.
// Differs from `init`'s static template:
//   - controller is disabled (no CA required at startup);
//   - cert / key / audit / llm-key paths anchor at the absolute
//     init-dir path passed in (matches user-mode init's
//     branch-on-installMode behavior).
func quickstartConfigYAML(absDir string) string {
	body := defaultConfigYAML
	// Disable the controller so no CA is required at startup.
	body = strings.Replace(body, "control: lo:8081", "control: 0", 1)
	// Anchor proxy-host paths at the operator's init dir.
	body = strings.Replace(body, "    cert_path: "+DefaultCACertPath, "    cert_path: "+filepath.Join(absDir, "trollbridge-ca.crt"), 1)
	body = strings.Replace(body, "    key_path:  "+DefaultCAKeyPath, "    key_path:  "+filepath.Join(absDir, "trollbridge-ca.key"), 1)
	body = strings.Replace(body, "  audit_path:        /var/log/trollbridge/audit.jsonl", "  audit_path:        "+filepath.Join(absDir, "trollbridge.audit.jsonl"), 1)
	body = strings.Replace(body, "  api_key_path: /etc/trollbridge/llm.key", "  api_key_path: "+filepath.Join(absDir, "llm.key"), 1)
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
		go func() {
			defer func() {
				if r := recover(); r != nil {
					opLog.Warn("operator UI crashed",
						"event", oplog.EventOperatorUIError,
						"error", fmt.Sprintf("%v", r))
				}
			}()
			if err := tui.RunOperator(ctx, cfg, os.Stdin, os.Stdout, backend, welcome); err != nil {
				opLog.Warn("operator UI exited",
					"event", oplog.EventOperatorUIError,
					"error", err.Error())
			}
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

	if isStdoutTTY() && !console.IsInteractive(os.Stdin) {
		printRunStartupBanner(cmd.OutOrStdout(), srv.Addr(), string(cfg.Mode))
	}

	if err := srv.ListenAndServe(ctx); err != nil {
		return &runtimeErr{err}
	}
	return nil
}
