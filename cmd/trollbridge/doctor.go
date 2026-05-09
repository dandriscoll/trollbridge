package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/hostlist"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/types"
	"github.com/spf13/cobra"
)

// doctorAdvisor lets tests inject a fake advisor.Provider.
var doctorAdvisor advisor.Provider

func newDoctorCmd() *cobra.Command {
	var configPath string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the YAML and test the LLM connection.",
		Long: `Doctor is a pre-flight check: it loads trollbridge.yaml, parses the
rule files and lists, and — when llm.enabled — performs a real
classification call against the configured provider with a synthetic
input. Each check prints a status line; non-zero exit on any FAIL.

With --verbose, doctor emits connection-level events (DNS lookup,
TCP connect, TLS handshake) around the LLM call so an operator
chasing a timeout can attribute the cost to network setup vs.
provider response time.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "trollbridge doctor:")

			cfg, err := config.Load(configPath)
			if err != nil {
				printDoctorLine(out, "config", "FAIL: "+err.Error())
				return &configErr{err}
			}
			printDoctorLine(out, "config", fmt.Sprintf("OK (%s, mode=%s)", configPath, cfg.Mode))

			engine, err := policy.NewEngine(
				cfg.Mode,
				cfg.ResolveIncludePaths(configPath),
				policy.Phase1KnownModifiers(),
			)
			if err != nil {
				printDoctorLine(out, "rules", "FAIL: "+err.Error())
				return &configErr{err}
			}
			printDoctorLine(out, "rules",
				fmt.Sprintf("OK (%d rules, version %s)", len(engine.Rules()), engine.RuleSetVersion()))

			allow, err := hostlist.LoadInline("allow", "trollbridge.yaml:lists.allow", cfg.Lists.Allow)
			if err != nil {
				printDoctorLine(out, "lists", "FAIL: "+err.Error())
				return &configErr{err}
			}
			deny, err := hostlist.LoadInline("deny", "trollbridge.yaml:lists.deny", cfg.Lists.Deny)
			if err != nil {
				printDoctorLine(out, "lists", "FAIL: "+err.Error())
				return &configErr{err}
			}
			printDoctorLine(out, "lists",
				fmt.Sprintf("OK (%d allow / %d deny)", len(allow.Patterns), len(deny.Patterns)))

			if !cfg.LLM.Enabled {
				printDoctorLine(out, "llm", "skipped (llm.enabled: false)")
				return nil
			}

			endpoint := cfg.LLM.Endpoint
			if strings.EqualFold(strings.TrimSpace(cfg.LLM.Provider), "aoai") {
				canonical, hint, _ := advisor.NormalizeAOAIEndpoint(endpoint)
				if hint != "" {
					fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", hint)
				}
				endpoint = canonical
			}
			translator, known := advisor.TranslatorFor(cfg.LLM.Provider, endpoint)
			if !known {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: unrecognized llm.provider %q; falling back to anthropic translator\n", cfg.LLM.Provider)
			}
			authName := authNameFor(translator)
			prov := doctorAdvisor
			if prov == nil {
				prov = buildDoctorProvider(cfg.LLM, translator, endpoint)
			}

			printDoctorLine(out, "llm",
				fmt.Sprintf("contacting provider=%s endpoint=%s auth=%s (timeout %ds)",
					providerName(cfg.LLM.Provider), endpoint, authName, cfg.LLM.TimeoutSeconds))

			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.LLM.TimeoutSeconds)*time.Second+2*time.Second)
			defer cancel()
			if verbose {
				// Attach an httptrace so the operator sees connection
				// events around the Classify call. Issue #33 audit.
				stub, _ := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
				traced := attachVerboseTrace(out, stub, time.Now())
				ctx = traced.Context()
			}

			input := advisor.Input{
				Method:         "GET",
				Scheme:         "https",
				Host:           "example.com",
				Port:           443,
				Path:           "/",
				Identity:       "doctor",
				RuleSetVersion: engine.RuleSetVersion(),
				Directives:     cfg.LLM.Directives,
			}
			output, err := prov.Classify(ctx, input)
			if err != nil {
				layer := classifyAdvisorErr(err)
				printDoctorLine(out, "llm",
					fmt.Sprintf("FAIL: provider=%s endpoint=%s auth=%s layer=%s err=%s",
						providerName(cfg.LLM.Provider), endpoint, authName, layer, err.Error()))
				return &runtimeErr{err}
			}
			effect := strings.ToLower(strings.TrimSpace(output.Effect))
			confidence := strings.ToLower(strings.TrimSpace(output.Confidence))
			if !validDoctorEffect(effect) || !validDoctorConfidence(confidence) {
				err := fmt.Errorf("provider returned unrecognized shape: effect=%q confidence=%q", output.Effect, output.Confidence)
				printDoctorLine(out, "llm",
					fmt.Sprintf("FAIL: provider=%s endpoint=%s auth=%s layer=schema err=%s",
						providerName(cfg.LLM.Provider), endpoint, authName, err.Error()))
				return &runtimeErr{err}
			}
			printDoctorLine(out, "llm",
				fmt.Sprintf("OK (provider=%s, endpoint=%s, auth=%s, effect=%s, confidence=%s)",
					providerName(cfg.LLM.Provider), endpoint, authName, effect, confidence))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print connection-level events around the LLM Classify call")
	return cmd
}

func printDoctorLine(out io.Writer, name, status string) {
	fmt.Fprintf(out, "  %-9s %s\n", name+":", status)
}

func providerName(p string) string {
	v := strings.ToLower(strings.TrimSpace(p))
	if v == "" {
		return "anthropic"
	}
	return v
}

// authNameFor returns the operator-facing label for the auth header
// the configured translator emits. Used in doctor's status line so
// operators can see which header trollbridge actually sent.
func authNameFor(t advisor.Translator) string {
	switch t.Name() {
	case "aoai":
		return "api-key"
	case "anthropic":
		return "x-api-key"
	}
	return t.Name()
}

// classifyAdvisorErr returns "wire" for transport-layer failures
// (4xx/5xx, network), "schema" for 200-with-bad-content, and
// "unknown" for anything that didn't carry one of the sentinels.
func classifyAdvisorErr(err error) string {
	switch {
	case errors.Is(err, advisor.ErrAdvisorWire):
		return "wire"
	case errors.Is(err, advisor.ErrAdvisorSchema):
		return "schema"
	}
	return "unknown"
}

func buildDoctorProvider(llm config.LLM, t advisor.Translator, endpoint string) advisor.Provider {
	apiKey := ""
	if llm.APIKeyPath != "" {
		if data, err := os.ReadFile(llm.APIKeyPath); err == nil {
			apiKey = strings.TrimSpace(string(data))
		}
	}
	return &advisor.HTTPClassifier{
		Endpoint:   endpoint,
		APIKey:     apiKey,
		Model:      llm.Model,
		Translator: t,
		Client:     &http.Client{Timeout: time.Duration(llm.TimeoutSeconds) * time.Second},
	}
}

func validDoctorEffect(e string) bool {
	switch e {
	case "allow", "deny", "ask_user", "narrow_scope", "redact_and_retry", "prefer_structured_tool":
		return true
	}
	return false
}

func validDoctorConfidence(c string) bool {
	switch c {
	case "low", "medium", "high":
		return true
	}
	return false
}

// silence unused-import warnings when build tags trim things.
var _ = types.Decision{}
