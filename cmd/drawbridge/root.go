package main

import (
	"errors"
	"os"

	"github.com/spf13/cobra"
)

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
	cmd := &cobra.Command{
		Use:   "drawbridge",
		Short: "An LLM-powered HTTP/HTTPS proxy for agents.",
		Long: `drawbridge is an HTTP/HTTPS forward proxy that gives agents
network access under deterministic, auditable, policy-governed
conditions. See DESIGN.md for the full specification.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(
		newRunCmd(),
		newInitCmd(),
		newValidateCmd(),
		newDecisionsCmd(),
		newRulesCmd(),
		newLogsCmd(),
		newApproveCmd(),
		newDenyCmd(),
		newSessionsCmd(),
		newCACmd(),
		newVersionCmd(),
	)
	return cmd
}
