package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dandriscoll/drawbridge/internal/advisor"
	"github.com/dandriscoll/drawbridge/internal/config"
	"github.com/dandriscoll/drawbridge/internal/hostlist"
	"github.com/dandriscoll/drawbridge/internal/policy"
	"github.com/dandriscoll/drawbridge/internal/types"
	"github.com/spf13/cobra"
)

// doctorAdvisor lets tests inject a fake advisor.Provider.
var doctorAdvisor advisor.Provider

func newDoctorCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the YAML and test the LLM connection.",
		Long: `Doctor is a pre-flight check: it loads drawbridge.yaml, parses the
rule files and lists, and — when llm.enabled — performs a real
classification call against the configured provider with a synthetic
input. Each check prints a status line; non-zero exit on any FAIL.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "drawbridge doctor:")

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

			allow, err := hostlist.LoadInline("allow", "drawbridge.yaml:lists.allow", cfg.Lists.Allow)
			if err != nil {
				printDoctorLine(out, "lists", "FAIL: "+err.Error())
				return &configErr{err}
			}
			deny, err := hostlist.LoadInline("deny", "drawbridge.yaml:lists.deny", cfg.Lists.Deny)
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

			scheme, schemeName := authSchemeFor(cfg.LLM.Provider)
			prov := doctorAdvisor
			if prov == nil {
				prov = buildDoctorProvider(cfg.LLM, scheme)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(cfg.LLM.TimeoutSeconds)*time.Second+2*time.Second)
			defer cancel()

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
				printDoctorLine(out, "llm",
					fmt.Sprintf("FAIL: provider=%s endpoint=%s auth=%s err=%s",
						providerName(cfg.LLM.Provider), cfg.LLM.Endpoint, schemeName, err.Error()))
				return &runtimeErr{err}
			}
			effect := strings.ToLower(strings.TrimSpace(output.Effect))
			confidence := strings.ToLower(strings.TrimSpace(output.Confidence))
			if !validDoctorEffect(effect) || !validDoctorConfidence(confidence) {
				err := fmt.Errorf("provider returned unrecognized shape: effect=%q confidence=%q", output.Effect, output.Confidence)
				printDoctorLine(out, "llm",
					fmt.Sprintf("FAIL: provider=%s endpoint=%s auth=%s err=%s",
						providerName(cfg.LLM.Provider), cfg.LLM.Endpoint, schemeName, err.Error()))
				return &runtimeErr{err}
			}
			printDoctorLine(out, "llm",
				fmt.Sprintf("OK (provider=%s, endpoint=%s, auth=%s, effect=%s, confidence=%s)",
					providerName(cfg.LLM.Provider), cfg.LLM.Endpoint, schemeName, effect, confidence))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to drawbridge.yaml")
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

func authSchemeFor(provider string) (advisor.AuthScheme, string) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aoai":
		return advisor.AuthAzureAPIKey, "api-key"
	}
	return advisor.AuthBearer, "bearer"
}

func buildDoctorProvider(llm config.LLM, scheme advisor.AuthScheme) advisor.Provider {
	apiKey := ""
	if llm.APIKeyPath != "" {
		if data, err := os.ReadFile(llm.APIKeyPath); err == nil {
			apiKey = strings.TrimSpace(string(data))
		}
	}
	return &advisor.HTTPClassifier{
		Endpoint:   llm.Endpoint,
		APIKey:     apiKey,
		AuthScheme: scheme,
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
