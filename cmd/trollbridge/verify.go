package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dandriscoll/trollbridge/internal/config"
	"github.com/spf13/cobra"
)

// verifyResult is the structured shape `trollbridge verify --json`
// emits on stdout. Fields are stable; new fields are added at the
// end, never renamed or removed. An onboarding agent consumes this
// shape verbatim to decide done-vs-not-done and to surface
// remaining manual steps.
type verifyResult struct {
	OK              bool             `json:"ok"`
	ConfigPath      string           `json:"config_path"`
	ConfigParses    bool             `json:"config_parses"`
	ConfigError     string           `json:"config_error,omitempty"`
	Mode            string           `json:"mode,omitempty"`
	InstallModeHint string           `json:"install_mode_hint,omitempty"`
	Platform        string           `json:"platform"`
	ProxyAddr       string           `json:"proxy_addr,omitempty"`
	ProxyReachable  bool             `json:"proxy_reachable"`
	ProxyError      string           `json:"proxy_error,omitempty"`
	SelfDescribe    bool             `json:"self_describe_reachable"`
	SelfDescribeMsg string           `json:"self_describe_message,omitempty"`
	Interception    *verifyToggle    `json:"interception,omitempty"`
	Advisor         *verifyToggle    `json:"advisor,omitempty"`
	Gaps            []verifyGap      `json:"gaps"`
	NextActions     []string         `json:"next_actions"`
	Confirmations   []string         `json:"confirmations"`
	GeneratedAt     string           `json:"generated_at"`
	PlanVersion     string           `json:"plan_version"`
	Errors          []string         `json:"errors,omitempty"`
	Raw             *json.RawMessage `json:"-"`
}

type verifyToggle struct {
	Enabled bool   `json:"enabled"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
}

type verifyGap struct {
	ID         string `json:"id"`
	What       string `json:"what"`
	NextAction string `json:"next_action"`
	BlocksOK   bool   `json:"blocks_ok"`
}

// newVerifyCmd implements `trollbridge verify`: a single command
// the onboarding agent runs after setup to confirm trollbridge is
// reachable, the configured policy mode is active, and any
// optional surfaces (interception, advisor) that were enabled are
// actually working. Reports gaps as structured JSON.
//
// Verify is the agentic complement to `doctor`: doctor is the
// pre-flight, verify is the post-flight. Both share the strict
// config-load check; verify additionally probes the live system.
func newVerifyCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	var probeTimeoutMs int
	cmd := &cobra.Command{
		Use:           "verify",
		Short:         "Confirm trollbridge is running and configured as expected.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `verify is a post-setup check. An onboarding agent runs this
after starting the proxy to decide done-vs-not-done.

It performs:

  1. Strict load of trollbridge.yaml (same as ` + "`validate`" + `).
  2. TCP dial against the configured proxy bind address.
  3. HTTP GET through the proxy to http://config.trollbridge.dev/setup
     (the proxy's own self-describe endpoint — succeeds iff the
     proxy is in-path).
  4. If interception is on, check that the CA cert path exists.
  5. If the advisor is on, report it as "enabled, run doctor to
     verify the wire connection" — verify does NOT call the LLM
     (no network side-effects beyond the local proxy probe).

With --json (the agentic surface), prints a single JSON object on
stdout naming what works, what doesn't, and the exact next action
for each gap. Exit code is 0 when ok, non-zero when any required
check failed.

Without --json, prints a human-readable summary.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				configPath = defaultConfigPath()
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(probeTimeoutMs)*time.Millisecond)
			defer cancel()
			res := runVerify(ctx, configPath, time.Duration(probeTimeoutMs)*time.Millisecond)
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(res); err != nil {
					return &runtimeErr{err}
				}
			} else {
				printVerifyText(out, res)
			}
			if !res.OK {
				// Non-zero exit so CI / agents can branch on it.
				// runtimeErr maps to exit code 2 per exitCodeFor.
				return &runtimeErr{fmt.Errorf("verify: setup is not yet complete; see gaps in the output")}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to trollbridge.yaml (default: $TROLLBRIDGE_CONFIG, then ./trollbridge.yaml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit a structured JSON object on stdout")
	cmd.Flags().IntVar(&probeTimeoutMs, "probe-timeout-ms", 3000, "per-probe timeout in milliseconds")
	return cmd
}

// runVerify is the body of `trollbridge verify`. Pure with respect
// to logging — no oplog writes, no audit writes. Returns the
// structured result the caller renders.
func runVerify(ctx context.Context, configPath string, perProbe time.Duration) verifyResult {
	res := verifyResult{
		ConfigPath:   configPath,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		Platform:     detectPlatform().friendly(),
		PlanVersion:  "1",
		Gaps:         []verifyGap{},
		NextActions:  []string{},
		Confirmations: []string{},
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		res.ConfigParses = false
		res.ConfigError = err.Error()
		res.Gaps = append(res.Gaps, verifyGap{
			ID:         "config_parse",
			What:       "trollbridge.yaml did not parse cleanly",
			NextAction: "fix the error above and re-run `trollbridge validate -c " + configPath + "`",
			BlocksOK:   true,
		})
		res.NextActions = append(res.NextActions, "Fix the config-parse error and re-run `trollbridge verify`.")
		return res
	}
	res.ConfigParses = true
	res.Mode = cfg.Mode
	res.Confirmations = append(res.Confirmations, "trollbridge.yaml parses cleanly via the strict decoder.")

	addr := cfg.Proxy.Addr()
	res.ProxyAddr = addr
	if cfg.Proxy.Port == 0 {
		res.ProxyReachable = false
		res.ProxyError = "proxy surface is disabled (port=0); trollbridge is not running as a proxy"
		res.Gaps = append(res.Gaps, verifyGap{
			ID:         "proxy_disabled",
			What:       "proxy surface is disabled in the config",
			NextAction: "set `proxy:` to a non-zero host:port and start the proxy",
			BlocksOK:   true,
		})
		res.NextActions = append(res.NextActions, "Enable the proxy surface in trollbridge.yaml.")
		return res
	}

	// ClientAddr collapses wildcard binds to loopback so the probe
	// can reach the daemon co-located on the same host; it also
	// brackets IPv6 literals correctly for URL use.
	dialAddr := cfg.Proxy.ClientAddr()
	dialer := &net.Dialer{Timeout: perProbe}
	conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		res.ProxyReachable = false
		res.ProxyError = err.Error()
		res.Gaps = append(res.Gaps, verifyGap{
			ID:         "proxy_unreachable",
			What:       fmt.Sprintf("nothing answered on %s — trollbridge is not running or is bound to a different address", dialAddr),
			NextAction: "start the proxy: `trollbridge run -c " + configPath + "` (or `sudo systemctl start trollbridge` in daemon-mode)",
			BlocksOK:   true,
		})
		res.NextActions = append(res.NextActions, "Start the proxy and re-run verify.")
		return res
	}
	_ = conn.Close()
	res.ProxyReachable = true
	res.Confirmations = append(res.Confirmations, "TCP dial against "+dialAddr+" succeeded — trollbridge is listening.")

	// Probe self-describe through the proxy. This both confirms the
	// proxy speaks HTTP and confirms the operator can fetch
	// http://config.trollbridge.dev/setup, which is the same surface
	// a fresh consumer agent uses to bootstrap.
	probeURL := "http://" + dialAddr
	proxyURL, _ := url.Parse(probeURL)
	httpc := &http.Client{
		Timeout: perProbe,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://config.trollbridge.dev/setup", nil)
	if resp, err := httpc.Do(req); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			res.SelfDescribe = true
			res.Confirmations = append(res.Confirmations, "self-describe endpoint http://config.trollbridge.dev/setup returned 200 through the proxy.")
		} else {
			res.SelfDescribe = false
			res.SelfDescribeMsg = fmt.Sprintf("status %d", resp.StatusCode)
			res.Gaps = append(res.Gaps, verifyGap{
				ID:         "self_describe_status",
				What:       fmt.Sprintf("/setup returned %d (expected 200)", resp.StatusCode),
				NextAction: "check the proxy's operational log for the request — the host header `config.trollbridge.dev` must be intercepted, not forwarded",
				BlocksOK:   false,
			})
		}
	} else {
		res.SelfDescribe = false
		res.SelfDescribeMsg = err.Error()
		res.Gaps = append(res.Gaps, verifyGap{
			ID:         "self_describe_unreachable",
			What:       "could not reach /setup through the proxy: " + err.Error(),
			NextAction: "the proxy is up but not serving HTTP; check `trollbridge logs tail --follow`",
			BlocksOK:   false,
		})
	}

	// Interception toggle
	tog := &verifyToggle{Enabled: cfg.Interception.Enabled}
	if cfg.Interception.Enabled {
		certPath := cfg.Interception.CA.CertPath
		if _, statErr := os.Stat(certPath); statErr == nil {
			tog.OK = true
			tog.Detail = "CA cert present at " + certPath
			res.Confirmations = append(res.Confirmations, "interception enabled, CA cert present at "+certPath+".")
		} else {
			tog.OK = false
			tog.Detail = "CA cert missing at " + certPath
			res.Gaps = append(res.Gaps, verifyGap{
				ID:         "interception_ca_missing",
				What:       "interception is enabled but the CA cert is missing at " + certPath,
				NextAction: "run `trollbridge ca init` to generate the CA, then `trollbridge ca install --apply` on each consumer host",
				BlocksOK:   true,
			})
			res.NextActions = append(res.NextActions, "Generate the CA and install it on every consumer host.")
		}
	} else {
		tog.OK = true
		tog.Detail = "interception is off — HTTPS rules match host:port only"
	}
	res.Interception = tog

	// Advisor toggle. We deliberately do NOT call the LLM here —
	// that is `trollbridge doctor`'s job. verify just reports the
	// configured state so the agent can decide whether to chain
	// into doctor.
	adv := &verifyToggle{Enabled: cfg.LLM.Enabled}
	if cfg.LLM.Enabled {
		adv.OK = true
		adv.Detail = "advisor enabled; provider=" + cfg.LLM.Provider + ", model=" + cfg.LLM.Model + " — run `trollbridge doctor -c " + configPath + " --check-llm` to test the wire"
		res.NextActions = append(res.NextActions, "Run `trollbridge doctor -c "+configPath+" --check-llm` to confirm the advisor wire.")
	} else {
		adv.OK = true
		adv.Detail = "advisor is off"
	}
	res.Advisor = adv

	res.OK = true
	for _, g := range res.Gaps {
		if g.BlocksOK {
			res.OK = false
		}
	}
	return res
}

func printVerifyText(out io.Writer, r verifyResult) {
	fmt.Fprintln(out, "trollbridge verify:")
	fmt.Fprintf(out, "  config:        %s\n", r.ConfigPath)
	if r.ConfigParses {
		fmt.Fprintf(out, "    parse:       OK (mode=%s)\n", r.Mode)
	} else {
		fmt.Fprintf(out, "    parse:       FAIL: %s\n", r.ConfigError)
	}
	fmt.Fprintf(out, "  proxy:         %s\n", r.ProxyAddr)
	if r.ProxyReachable {
		fmt.Fprintln(out, "    reachable:   OK")
	} else if r.ProxyError != "" {
		fmt.Fprintf(out, "    reachable:   FAIL: %s\n", r.ProxyError)
	}
	if r.SelfDescribe {
		fmt.Fprintln(out, "    /setup:      OK (200 through proxy)")
	} else if r.SelfDescribeMsg != "" {
		fmt.Fprintf(out, "    /setup:      WARN: %s\n", r.SelfDescribeMsg)
	}
	if r.Interception != nil {
		fmt.Fprintf(out, "  interception:  enabled=%v ok=%v %s\n", r.Interception.Enabled, r.Interception.OK, r.Interception.Detail)
	}
	if r.Advisor != nil {
		fmt.Fprintf(out, "  advisor:       enabled=%v ok=%v %s\n", r.Advisor.Enabled, r.Advisor.OK, r.Advisor.Detail)
	}
	if len(r.Gaps) > 0 {
		fmt.Fprintln(out, "  gaps:")
		for _, g := range r.Gaps {
			tag := "WARN"
			if g.BlocksOK {
				tag = "BLOCK"
			}
			fmt.Fprintf(out, "    [%s] %s — %s — next: %s\n", tag, g.ID, g.What, g.NextAction)
		}
	}
	if r.OK {
		fmt.Fprintln(out, "result: OK")
	} else {
		fmt.Fprintln(out, "result: NOT_READY")
	}
}
