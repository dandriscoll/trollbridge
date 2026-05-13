package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dandriscoll/trollbridge/internal/advisor"
	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/dandriscoll/trollbridge/internal/hostlist"
	"github.com/dandriscoll/trollbridge/internal/oplog"
	"github.com/dandriscoll/trollbridge/internal/policy"
	"github.com/dandriscoll/trollbridge/internal/types"
	"github.com/spf13/cobra"
)

// doctorAdvisor lets tests inject a fake advisor.Provider.
var doctorAdvisor advisor.Provider

// doctorLogFilePath is set by the --log-file flag handler; nil when
// the flag was not used. Read by doctorOpLog to wire a tee writer.
var doctorLogFilePath string

func newDoctorCmd() *cobra.Command {
	var configPath string
	var verbose bool
	var checkLLM bool
	var logFile string
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
provider response time.

With --check-llm, doctor runs the LLM classification step even when
llm.enabled is false in the YAML. Useful when wiring up a new
provider: verify the key, endpoint, and model are correct before
flipping the production switch (closes #82).`,
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

			if !cfg.LLM.Enabled && !checkLLM {
				printDoctorLine(out, "llm", "skipped (llm.enabled: false)")
				return nil
			}

			// Pre-validate that the operator actually populated the
			// llm block. Catches the case where --check-llm is used
			// against a yaml that has no provider/endpoint set yet —
			// without this check, doctor would warn about an unknown
			// provider, attempt a POST to an empty endpoint, and fail
			// at wire level with a misleading "no such host" error.
			// Sibling of the api_key_path silent-empty-key class
			// closed below (#82).
			if cfg.LLM.Provider == "" || cfg.LLM.Endpoint == "" {
				printDoctorLine(out, "llm",
					"FAIL: llm.provider and llm.endpoint must both be set in trollbridge.yaml; see ANTHROPIC-LLM-SETUP-AGENT.md or AZURE-OPENAI-LLM-SETUP-AGENT.md")
				return &configErr{errors.New("llm config incomplete: provider or endpoint not set")}
			}

			// Pre-check the api_key_path before any wire call so a
			// missing or unreadable key file fails the doctor with a
			// specific, actionable message — not a misleading 401
			// from the provider (closes #82). An empty api_key_path is
			// operator intent for unauthenticated endpoints and is
			// passed through unchanged.
			if cfg.LLM.APIKeyPath != "" {
				if _, err := os.ReadFile(cfg.LLM.APIKeyPath); err != nil {
					printDoctorLine(out, "llm",
						fmt.Sprintf("FAIL: api_key_path %q does not exist or is unreadable: %s",
							cfg.LLM.APIKeyPath, err.Error()))
					return &configErr{err}
				}
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
				prov = buildDoctorProvider(cfg.LLM, translator, endpoint, doctorOpLog())
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
	cmd.Flags().BoolVar(&checkLLM, "check-llm", false, "run the LLM classification step even when llm.enabled is false")
	cmd.Flags().StringVar(&logFile, "log-file", "", "path to write the operational log to (in addition to stderr); useful for snippet-verification runs (#106)")
	cmd.PreRun = func(*cobra.Command, []string) { doctorLogFilePath = logFile }
	cmd.PostRun = func(*cobra.Command, []string) { doctorLogFilePath = "" }
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

func buildDoctorProvider(llm config.LLM, t advisor.Translator, endpoint string, opLog *slog.Logger) advisor.Provider {
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
		OpLog:      opLog,
	}
}

// doctorOpLog returns a stderr-bound slog.Logger at the resolved
// log level so that running `trollbridge doctor --log-level=debug`
// surfaces the new HTTPClassifier `event=advisor_wire_response`
// records to the operator. Closes #36 wire-detail closure.
//
// When --log-file is set (doctorLogFilePath non-empty), the logger
// also tees to that file so a snippet-verification run can capture
// the lines without piping. Closes the doctor --log-file bullet of
// #106.
func doctorOpLog() *slog.Logger {
	levelVar := new(slog.LevelVar)
	levelVar.Set(slog.LevelInfo)
	if resolvedLogLevel != nil {
		levelVar.Set(*resolvedLogLevel)
	}
	if doctorLogFilePath != "" {
		f, err := os.OpenFile(doctorLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err == nil {
			// Tee writer: stderr always; file in addition. This
			// matches the spirit of the existing oplog StderrSink
			// while letting `--log-file path.log` capture the same
			// stream for later inspection.
			h := slog.NewTextHandler(io.MultiWriter(os.Stderr, f), &slog.HandlerOptions{Level: levelVar})
			return slog.New(h)
		}
		// Fall through to stderr-only on file-open failure (the
		// operator can re-try with a writable path; doctor's other
		// output still names the failure context).
		fmt.Fprintf(os.Stderr, "doctor: cannot open --log-file %s: %v; continuing with stderr only\n", doctorLogFilePath, err)
	}
	lg, err := oplog.New(oplog.StderrSink, levelVar)
	if err != nil {
		// oplog.New only fails on file-sink misconfiguration; stderr
		// is unconditionally available, so this branch should not
		// trigger. Returning nil keeps the HTTPClassifier nil-safe.
		return nil
	}
	return lg
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
