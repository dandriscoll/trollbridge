package main

import (
	"errors"
	"log/slog"
	"os"

	"github.com/dandriscoll/drawbridge/internal/oplog"
	"github.com/spf13/cobra"
)

// resolvedLogLevel is set in PersistentPreRunE on the root command
// from (in precedence order) the --log-level flag, the
// `--verbose`/`-v` alias on subcommands that opt in, the
// DRAWBRIDGE_LOG_LEVEL env var, and otherwise nil. nil means "let
// the config file decide; if the config has nothing, default Info."
// Subcommands that need the resolved level read this variable when
// constructing the operational logger.
var resolvedLogLevel *slog.Level

// configError, runtimeError, etc. are sentinel error wrappers used
// by exitCodeFor to map errors to the design's exit-code matrix.
type configErr struct{ err error }
type runtimeErr struct{ err error }
type holdNotFoundErr struct{ err error }

func (e *configErr) Error() string         { return e.err.Error() }
func (e *configErr) Unwrap() error         { return e.err }
func (e *runtimeErr) Error() string        { return e.err.Error() }
func (e *runtimeErr) Unwrap() error        { return e.err }
func (e *holdNotFoundErr) Error() string   { return e.err.Error() }
func (e *holdNotFoundErr) Unwrap() error   { return e.err }

func exitCodeFor(err error) int {
	var ce *configErr
	var re *runtimeErr
	var he *holdNotFoundErr
	switch {
	case errors.As(err, &ce):
		return 1
	case errors.As(err, &re):
		return 2
	case errors.As(err, &he):
		return 3
	}
	return 1
}

func defaultConfigPath() string {
	if v := os.Getenv("DRAWBRIDGE_CONFIG"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v + "/drawbridge/drawbridge.yaml"
	}
	if v := os.Getenv("HOME"); v != "" {
		return v + "/.config/drawbridge/drawbridge.yaml"
	}
	return "drawbridge.yaml"
}

func newRootCmd() *cobra.Command {
	var logLevelFlag string
	cmd := &cobra.Command{
		Use:   "drawbridge",
		Short: "An LLM-powered HTTP/HTTPS proxy for agents.",
		Long: `drawbridge is an HTTP/HTTPS forward proxy that gives agents
network access under deterministic, auditable, policy-governed
conditions. See DESIGN.md for the full specification.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			// Precedence: --log-level flag > DRAWBRIDGE_LOG_LEVEL env > nil
			// (let the config / default decide downstream).
			resolvedLogLevel = nil
			if c.Flags().Changed("log-level") {
				lv, err := oplog.ParseLevel(logLevelFlag)
				if err != nil {
					return &configErr{err}
				}
				resolvedLogLevel = &lv
				return nil
			}
			if env := os.Getenv("DRAWBRIDGE_LOG_LEVEL"); env != "" {
				lv, err := oplog.ParseLevel(env)
				if err != nil {
					return &configErr{err}
				}
				resolvedLogLevel = &lv
			}
			return nil
		},
	}
	cmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "",
		"operational log level (debug|info|warn|error); also DRAWBRIDGE_LOG_LEVEL env (default info)")

	// Phase 5: command groupings per DESIGN.md §13.5.
	const (
		groupOperate   = "operate"
		groupConfigure = "configure"
		groupAudit     = "audit"
		groupCA        = "ca"
	)
	cmd.AddGroup(
		&cobra.Group{ID: groupOperate, Title: "Operate:"},
		&cobra.Group{ID: groupConfigure, Title: "Configure:"},
		&cobra.Group{ID: groupAudit, Title: "Audit:"},
		&cobra.Group{ID: groupCA, Title: "Manage CA:"},
	)

	op := func(c *cobra.Command, group string) *cobra.Command {
		c.GroupID = group
		return c
	}

	cmd.AddCommand(
		op(newRunCmd(), groupOperate),
		op(newSelftestCmd(), groupOperate),
		op(newTestCmd(), groupOperate),
		op(newVersionCmd(), groupOperate),

		op(newInitCmd(), groupConfigure),
		op(newValidateCmd(), groupConfigure),
		op(newDoctorCmd(), groupConfigure),
		op(newRulesCmd(), groupConfigure),
		op(newEnvCmd(), groupConfigure),

		op(newDecisionsCmd(), groupAudit),
		op(newLogsCmd(), groupAudit),
		op(newSessionsCmd(), groupAudit),
		op(newApproveCmd(), groupAudit),
		op(newDenyCmd(), groupAudit),
		op(newTUICmd(), groupAudit),

		op(newCACmd(), groupCA),
	)
	return cmd
}
