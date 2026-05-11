package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/server"
	"github.com/spf13/cobra"
)

// resolvedLogLevel is set in PersistentPreRunE on the root command
// from (in precedence order) the --log-level flag, the
// `--verbose`/`-v` alias on subcommands that opt in, the
// TROLLBRIDGE_LOG_LEVEL env var, and otherwise nil. nil means "let
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

// drawbridgeRenamedEnvVars maps every legacy DRAWBRIDGE_* env name
// to the trollbridge replacement. The drawbridge → trollbridge
// rename (commit f068448) shipped without a compat shim by intent;
// this list exists only so warnLegacyDrawbridgeEnv can tell an
// operator which legacy var they have set and what to set instead.
var drawbridgeRenamedEnvVars = []struct {
	old, new string
}{
	{"DRAWBRIDGE_LOG_LEVEL", "TROLLBRIDGE_LOG_LEVEL"},
	{"DRAWBRIDGE_CONFIG", "TROLLBRIDGE_CONFIG"},
	{"DRAWBRIDGE_CONTROLLER_CERT", "TROLLBRIDGE_CONTROLLER_CERT"},
	{"DRAWBRIDGE_CONTROLLER_KEY", "TROLLBRIDGE_CONTROLLER_KEY"},
	{"DRAWBRIDGE_CONTROLLER_CA", "TROLLBRIDGE_CONTROLLER_CA"},
}

// warnLegacyDrawbridgeEnv emits a one-shot stderr warning for any
// legacy DRAWBRIDGE_* env var the operator still has set (where the
// corresponding TROLLBRIDGE_* is unset). The legacy vars are NOT
// honored — silent fall-through to defaults is the failure shape the
// warning prevents (issue #26). lookup is injected for testability.
func warnLegacyDrawbridgeEnv(out io.Writer, lookup func(string) (string, bool)) {
	var legacy []struct{ old, new string }
	for _, p := range drawbridgeRenamedEnvVars {
		if _, set := lookup(p.old); !set {
			continue
		}
		if _, newSet := lookup(p.new); newSet {
			// Operator already set the new name; assume the legacy
			// var is leftover and don't nag about it.
			continue
		}
		legacy = append(legacy, p)
	}
	if len(legacy) == 0 {
		return
	}
	fmt.Fprintln(out, "warning: legacy DRAWBRIDGE_* environment variables detected; trollbridge does not honor them.")
	fmt.Fprintln(out, "         the drawbridge → trollbridge rename did not ship a compat shim. unset or rename:")
	for _, p := range legacy {
		fmt.Fprintf(out, "           %s → %s\n", p.old, p.new)
	}
}

// defaultConfigPath returns the path used when no -c flag is given.
// trollbridge is a deployed proxy, not a user application — its config
// lives with the deployment (cwd) rather than under the operator's XDG
// tree. TROLLBRIDGE_CONFIG remains an explicit operator override (used
// by packaging units like packaging/systemd/trollbridge.service).
func defaultConfigPath() string {
	if v := os.Getenv("TROLLBRIDGE_CONFIG"); v != "" {
		return v
	}
	return "trollbridge.yaml"
}

func newRootCmd() *cobra.Command {
	var logLevelFlag string
	cmd := &cobra.Command{
		Use:   "trollbridge",
		Short: "An LLM-powered HTTP/HTTPS proxy for agents.",
		Long: `trollbridge is an HTTP/HTTPS forward proxy that gives agents
network access under deterministic, auditable, policy-governed
conditions. See DESIGN.md for the full specification.`,
		// Version + template wire `trollbridge --version` (and `-v`)
		// as aliases for the existing `trollbridge version` subcommand.
		// Template matches version.go's "trollbridge <ver>\n" so
		// scripts that parse either form see identical output (#44).
		Version:       server.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			warnLegacyDrawbridgeEnv(c.ErrOrStderr(), os.LookupEnv)

			// Precedence: --log-level flag > TROLLBRIDGE_LOG_LEVEL env > nil
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
			if env := os.Getenv("TROLLBRIDGE_LOG_LEVEL"); env != "" {
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
		"operational log level (debug|info|warn|error); also TROLLBRIDGE_LOG_LEVEL env (default info)")
	cmd.SetVersionTemplate("trollbridge {{.Version}}\n")

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
		op(newQuickstartCmd(), groupOperate),
		op(newRunCmd(), groupOperate),
		op(newSelftestCmd(), groupOperate),
		op(newTestCmd(), groupOperate),
		op(newUpdateCmd(), groupOperate),
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
		op(newAttachCmd(), groupAudit),

		op(newCACmd(), groupCA),
	)
	return cmd
}
