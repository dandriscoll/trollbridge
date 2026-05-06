package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/console"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/server"
	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	var configPath string
	var noConsole bool
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
			engine, err := policy.NewEngine(
				cfg.Mode,
				cfg.ResolveIncludePaths(configPath),
				policy.Phase1KnownModifiers(),
			)
			if err != nil {
				return &configErr{err}
			}
			srv, err := server.New(cfg, engine)
			if err != nil {
				return &runtimeErr{err}
			}

			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			// Fast-path lists with file-modification watcher.
			allowPaths := cfg.ResolveAllowFiles(configPath)
			denyPaths := cfg.ResolveDenyFiles(configPath)
			if err := srv.WatchAndReload(ctx, allowPaths, denyPaths); err != nil {
				return &configErr{err}
			}

			// SIGHUP triggers YAML rule reload.
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			go func() {
				for range hup {
					if err := engine.Reload(); err != nil {
						fmt.Fprintln(os.Stderr, "drawbridge: rule reload failed:", err)
					} else {
						fmt.Fprintln(os.Stderr, "drawbridge: rules reloaded;",
							"version", engine.RuleSetVersion())
					}
				}
			}()

			// Console REPL when stdin is a tty.
			if !noConsole && console.IsInteractive(os.Stdin) {
				go func() {
					_ = console.Run(ctx, console.Config{
						AllowPaths: allowPaths,
						DenyPaths:  denyPaths,
					})
				}()
			}

			fmt.Fprintf(os.Stderr, "drawbridge: listening on %s, mode=%s, rules=%d (v%s)\n",
				srv.Addr(), cfg.Mode, len(engine.Rules()), engine.RuleSetVersion())

			if err := srv.ListenAndServe(ctx); err != nil {
				return &runtimeErr{err}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml (default: $DRAWBRIDGE_CONFIG, then $XDG_CONFIG_HOME/drawbridge/drawbridge.yaml)")
	cmd.Flags().BoolVar(&noConsole, "no-console", false, "disable the interactive console even when stdin is a tty")
	return cmd
}
