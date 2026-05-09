package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const defaultConfigYAML = `trollbridge_version: 3

# 1. Per-surface bind. Each value is "<host>:<port>". Use:
#      lo   = 127.0.0.1
#      all  = 0.0.0.0
#      a literal IP or hostname (e.g. 10.1.2.3, trollbridge.internal)
#      [fd00::1]:8081  for IPv6 literals.
#    'metrics: 0' disables the (unimplemented) Prometheus endpoint.
proxy:   lo:8080
control: lo:8081
metrics: 0

# 2. Allow / deny lists — trollbridge writes them back from the REPL.
#    Each entry is host[:port][/path] with an optional <scheme>:// prefix
#    and * wildcards (*.example.com, trailing /* for path prefix, bare *
#    for any host). Examples:
#      api.github.com
#      *.github.com
#      https://api.github.com/v3/*
#      127.0.0.1
lists:
  allow:
    - localhost
    - 127.0.0.1
  deny:
    - 169.254.169.254
    - metadata.google.internal

# 3. LLM — the advisor that classifies ambiguous requests.
#    Trollbridge speaks each provider's native API directly.
#    provider: anthropic   -> Anthropic Messages API (x-api-key)
#    provider: aoai        -> Azure OpenAI chat-completions (api-key)
#    Other values fall back to the anthropic translator with a warning.
llm:
  enabled: false
  provider: anthropic
  model:    claude-opus-4-7
  endpoint: https://api.anthropic.com/v1/messages
  api_key_path: /etc/trollbridge/llm.key
  send_body: false
  on_unavailable: ask_user
  confidence_floor: medium

  # 4. Directives — the system prompt the advisor follows.
  directives: |
    You are trollbridge's security advisor. Decide allow / deny / ask_user
    for each HTTP request you receive. Refuse anything that exfiltrates
    credentials or contacts cloud metadata services. When uncertain,
    answer ask_user.

# Controller — operator-facing control plane (approve/deny/tui).
# mTLS is enforced; client certs are issued by the same CA used for
# TLS interception (trollbridge ca client-cert <name>).
controller:
  auth: mtls

mode: default-ask

# Interception — TLS termination for HTTPS visibility. CA paths are
# also used by the controller's mTLS listener. Paths are absolute and
# cross-machine stable: every host that loads this config will look
# in /etc/trollbridge/ for the CA. Override per-machine if needed.
interception:
  enabled: false
  ca:
    cert_path: /etc/trollbridge/trollbridge-ca.crt
    key_path:  /etc/trollbridge/trollbridge-ca.key
  leaf_key_type: rsa-4096

# Logging. Paths are absolute so they remain valid regardless of
# the proxy daemon's cwd at startup. Operators who deploy under
# systemd / containers can override per-environment.
logging:
  audit_path:        /var/log/trollbridge/audit.jsonl
  audit_overflow:    deny
  operational_path:  stderr

# Approvals queue tuning. (Auth posture lives under controller.)
approvals:
  timeout_seconds: 300
  on_timeout: deny
  max_pending: 100

`

func newInitCmd() *cobra.Command {
	var dir string
	var force, nonInteractive bool
	defaultDir := filepath.Dir(defaultConfigPath())
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a trollbridge.yaml. Interactive when stdin is a TTY; static defaults otherwise.",
		Long: `Create a trollbridge.yaml in the target directory.

The default directory matches the location every other subcommand
reads from: the directory portion of $TROLLBRIDGE_CONFIG when set,
otherwise the current working directory. Pass -d <path> to write
somewhere else.

By default, when stdin is a TTY, init runs as a guided setup that
asks about topology, policy mode, TLS interception, and LLM
advisor — and (when interception is chosen) generates the CA in
the same invocation.

When stdin is not a TTY (CI, redirected input) or --non-interactive
is passed, init writes the static default config without prompting.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				dir = defaultDir
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return &runtimeErr{err}
			}
			out := cmd.OutOrStdout()
			interactive := !nonInteractive && stdinIsTTY(cmd.InOrStdin())

			yamlPath := filepath.Join(dir, "trollbridge.yaml")
			if _, err := os.Stat(yamlPath); err == nil && !force {
				return &configErr{fmt.Errorf("init: file %s already exists; use --force to archive and replace", yamlPath)}
			} else if err == nil && force {
				backup := yamlPath + ".bak"
				if err := os.Rename(yamlPath, backup); err != nil {
					return &runtimeErr{err}
				}
				fmt.Fprintf(out, "  archived: %s -> %s\n", yamlPath, backup)
			}

			content := defaultConfigYAML
			var ans initAnswers
			if interactive {
				a, err := runInteractiveInit(cmd.InOrStdin(), out)
				if err != nil {
					return &configErr{err}
				}
				ans = a
				if ans.interception {
					// Per-host stability: pin the CA paths to the
					// canonical absolute path used everywhere else in
					// trollbridge. The same path is valid on every
					// host the config is shared with — issue #14.
					ans.caCertPath = DefaultCACertPath
					ans.caKeyPath = DefaultCAKeyPath
				}
				if ans.llmEnabled {
					// LLM key path is a *proxy-host* path. The yaml
					// records where the daemon will read it from
					// (/etc/trollbridge/llm.key by template default).
					// `init` does NOT write the key file — that step
					// belongs on the proxy host as root, so init runs
					// without privilege regardless of where the proxy
					// will eventually live (issues #19, #21).
					ans.llmKeyPath = "/etc/trollbridge/llm.key"
				}
				content = applyAnswers(defaultConfigYAML, ans)
			}

			if err := os.WriteFile(yamlPath, []byte(content), 0o640); err != nil {
				return &runtimeErr{err}
			}
			fmt.Fprintln(out, "trollbridge init: created files:")
			fmt.Fprintln(out, "  ", yamlPath)

			// When the resolved file matches defaultConfigPath(), the
			// rest of the CLI finds it without -c — print bare commands.
			// Otherwise the operator chose a non-default location;
			// thread the absolute path through every follow-on so the
			// printed advice works from any cwd. Compare absolutes on
			// both sides because defaultConfigPath() may return either
			// the cwd-relative "trollbridge.yaml" or the operator's
			// $TROLLBRIDGE_CONFIG override.
			cFlag := ""
			absYaml, errA := filepath.Abs(yamlPath)
			absDefault, errB := filepath.Abs(defaultConfigPath())
			if errA == nil && errB == nil && absYaml != absDefault {
				cFlag = " -c " + absYaml
			}

			printNextSteps(out, ans, interactive, cFlag)
			return nil
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "d", defaultDir, "directory to write the config to (default: matches `trollbridge run -c` discovery)")
	cmd.Flags().BoolVar(&force, "force", false, "archive existing files (.bak) and replace")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "skip the guided setup; write the static default config")
	return cmd
}

// printNextSteps emits an operator-facing block describing the
// commands they should run after `trollbridge init`. The output is
// topology-aware: when the operator chose `remote`, the steps name
// "the proxy host (a different machine than this one)" so the
// operator does not assume the next commands run locally. CA
// generation is always a separate `trollbridge ca init` step,
// **never** inlined into `init` — `init` produces a yaml at no
// privilege; CA generation needs root on the proxy host. (Issue
// #19; v0.4.6/v0.4.7 attempts conflated the two.)
func printNextSteps(out io.Writer, ans initAnswers, interactive bool, cFlag string) {
	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	w("\nnext steps:\n")

	// In non-interactive mode we don't know the topology or whether
	// interception is on, so fall back to a generic flow.
	if !interactive {
		w("  trollbridge ca init%s            # on the proxy host: generates the CA at /etc/trollbridge/\n", cFlag)
		w("  trollbridge ca client-cert <op>%s # on the proxy host: issue an operator client cert\n", cFlag)
		w("  trollbridge run%s                # on the proxy host: start the daemon\n", cFlag)
		w("  trollbridge test https://example.com%s   # from a consumer host: probe one request\n", cFlag)
		return
	}

	remote := ans.topology == "remote"
	proxyHost := "the proxy host"
	if !remote {
		proxyHost = "this host (the proxy host)"
	}

	if ans.interception {
		w("  # CA generation and API key writes are separate, root-only steps.\n")
		w("  # `trollbridge init` writes only the yaml — the operator running it\n")
		w("  # may not be on the proxy host or may not own /etc/trollbridge.\n")
		w("\n")
		w("  On %s, as root:\n", proxyHost)
		w("    sudo trollbridge ca init%s              # generates /etc/trollbridge/trollbridge-ca.{crt,key}\n", cFlag)
		w("    sudo trollbridge ca client-cert <op>%s   # issue an operator client cert\n", cFlag)
		if ans.llmEnabled {
			w("    # write your LLM API key (paste, then Ctrl-D):\n")
			w("    sudo install -m 600 /dev/stdin /etc/trollbridge/llm.key\n")
		}
		w("\n")
		if remote {
			w("  Then transfer trollbridge-ca.crt to every consumer host:\n")
			w("    scp <proxy-host>:/etc/trollbridge/trollbridge-ca.crt \\\n")
			w("        <consumer-host>:/etc/trollbridge/trollbridge-ca.crt\n")
			w("\n")
			w("  On each consumer host:\n")
			w("    sudo trollbridge ca install --apply        # installs the cert into the system trust store\n")
		} else {
			w("  On the same host (the consumer also runs here):\n")
			w("    sudo trollbridge ca install --apply        # installs the cert into the system trust store\n")
		}
		w("\n")
		w("  On %s, run the daemon:\n", proxyHost)
		w("    trollbridge run%s\n", cFlag)
		w("\n")
		w("  From a consumer (set HTTP(S)_PROXY first):\n")
		w("    eval \"$(trollbridge env%s)\"\n", cFlag)
		w("    trollbridge test https://example.com%s\n", cFlag)
		return
	}

	// Interception off → no CA distribution flow, but we still need
	// to name where the daemon will run, and the controller still
	// uses an mTLS CA so ca init is still required.
	w("  On %s, as root (the controller still uses an mTLS CA):\n", proxyHost)
	w("    sudo trollbridge ca init%s              # generates /etc/trollbridge/trollbridge-ca.{crt,key}\n", cFlag)
	w("    sudo trollbridge ca client-cert <op>%s   # issue an operator client cert\n", cFlag)
	if ans.llmEnabled {
		w("    # write your LLM API key (paste, then Ctrl-D):\n")
		w("    sudo install -m 600 /dev/stdin /etc/trollbridge/llm.key\n")
	}
	w("\n")
	w("  On %s, run the daemon:\n", proxyHost)
	w("    trollbridge run%s\n", cFlag)
	w("\n")
	w("  From a consumer:\n")
	w("    eval \"$(trollbridge env%s)\"\n", cFlag)
	w("    trollbridge test https://example.com%s\n", cFlag)
}

// writeLLMKey writes the API key to path with mode 0600. Creates
// the parent directory if it does not already exist (we already
// asked the operator for the path; we trust their choice).
func writeLLMKey(path, key string) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(key), 0o600)
}

