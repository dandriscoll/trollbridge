package main

import (
	"encoding/json"
	"fmt"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/hostlist"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/spf13/cobra"
)

// validateJSONReport is the schema emitted by `trollbridge validate
// --json`. Stable contract for operators wiring config-lint into
// their own CI (closes #127). One object per invocation: on success
// `ok=true` and the descriptive fields are populated; on failure
// `ok=false` and `error.message` carries the parse/load error.
type validateJSONReport struct {
	OK              bool                   `json:"ok"`
	Config          string                 `json:"config"`
	Mode            string                 `json:"mode,omitempty"`
	RuleSetVersion  string                 `json:"rule_set_version,omitempty"`
	Rules           *validateJSONRuleStats `json:"rules,omitempty"`
	Lists           *validateJSONListStats `json:"lists,omitempty"`
	KnownModifiers  []string               `json:"known_modifiers,omitempty"`
	Error           *validateJSONError     `json:"error,omitempty"`
}

type validateJSONRuleStats struct {
	Count int `json:"count"`
}

type validateJSONListStats struct {
	Allow int `json:"allow"`
	Deny  int `json:"deny"`
}

type validateJSONError struct {
	Message string `json:"message"`
}

func newValidateCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration and rule set.",
		Long: `Validate the configuration and rule set.

By default emits a human-readable summary. With --json, emits a single
JSON object on stdout describing the validation outcome — operators
can bind this from their own CI.

Exit codes (stable contract):
  0  configuration and rule set parse cleanly.
  1  any validation failure (file not found, YAML parse error,
     unknown key under strict decoding, list parse error, …).

The JSON shape is:
  { "ok": bool,
    "config": "<path>",
    "mode": "...", "rule_set_version": "...",
    "rules": {"count": N},
    "lists": {"allow": N, "deny": N},
    "known_modifiers": [...],
    "error": {"message": "..."}            // only when ok=false
  }`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			report := validateJSONReport{Config: configPath}

			// Helper: emit failure JSON (if requested) and return the
			// configErr that drives the exit code.
			emitFailure := func(err error) error {
				if asJSON {
					report.OK = false
					report.Error = &validateJSONError{Message: err.Error()}
					_ = json.NewEncoder(cmd.OutOrStdout()).Encode(report)
				}
				return &configErr{err}
			}

			cfg, err := config.Load(configPath)
			if err != nil {
				return emitFailure(err)
			}
			engine, err := policy.NewEngine(
				cfg.Mode,
				cfg.ResolveIncludePaths(configPath),
				policy.Phase1KnownModifiers(),
			)
			if err != nil {
				return emitFailure(err)
			}
			allow, err := hostlist.LoadInline("allow", "trollbridge.yaml:lists.allow", cfg.Lists.Allow)
			if err != nil {
				return emitFailure(err)
			}
			deny, err := hostlist.LoadInline("deny", "trollbridge.yaml:lists.deny", cfg.Lists.Deny)
			if err != nil {
				return emitFailure(err)
			}

			if asJSON {
				report.OK = true
				report.Mode = cfg.Mode
				report.RuleSetVersion = engine.RuleSetVersion()
				report.Rules = &validateJSONRuleStats{Count: len(engine.Rules())}
				report.Lists = &validateJSONListStats{Allow: len(allow.Patterns), Deny: len(deny.Patterns)}
				report.KnownModifiers = policy.Phase1KnownModifiers()
				return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"trollbridge validate: OK\n"+
					"  config:    %s\n"+
					"  mode:      %s\n"+
					"  allowlist: %d entries\n"+
					"  denylist:  %d entries\n"+
					"  rules:     %d (version %s)\n"+
					"  known modifiers: %v\n",
				configPath, cfg.Mode,
				len(allow.Patterns), len(deny.Patterns),
				len(engine.Rules()), engine.RuleSetVersion(),
				policy.Phase1KnownModifiers())
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit a single JSON object on stdout (success or failure)")
	return cmd
}
