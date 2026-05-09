package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dandriscoll/trollbridge/internal/ca"
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
# also used by the controller's mTLS listener.
interception:
  enabled: false
  ca:
    cert_path: ./trollbridge-ca.crt
    key_path:  ./trollbridge-ca.key
  leaf_key_type: rsa-4096

# Logging.
logging:
  audit_path:        ./trollbridge.audit.jsonl
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
					// Resolve the CA paths to absolutes so the running
					// daemon finds them regardless of cwd. The relative
					// `./trollbridge-ca.{crt,key}` defaults in the
					// template only worked when the operator stayed in
					// the dir they ran init from.
					if abs, err := filepath.Abs(filepath.Join(dir, "trollbridge-ca.crt")); err == nil {
						ans.caCertPath = abs
					}
					if abs, err := filepath.Abs(filepath.Join(dir, "trollbridge-ca.key")); err == nil {
						ans.caKeyPath = abs
					}
				}
				if ans.llmEnabled {
					// LLM key lives next to the yaml. The interactive
					// flow does not ask the operator for a path — every
					// other init artifact lands in <dir>, and the prior
					// default (/etc/trollbridge/llm.key) was a system
					// path most operators could not write to.
					if abs, err := filepath.Abs(filepath.Join(dir, "llm.key")); err == nil {
						ans.llmKeyPath = abs
					} else {
						ans.llmKeyPath = filepath.Join(dir, "llm.key")
					}
				}
				content = applyAnswers(defaultConfigYAML, ans)

				// LLM key first — if this fails, the YAML wouldn't
				// reflect a real installation.
				if ans.llmEnabled {
					if err := writeLLMKey(ans.llmKeyPath, ans.llmKey); err != nil {
						return &runtimeErr{fmt.Errorf("write LLM key: %w", err)}
					}
					fmt.Fprintf(out, "  wrote LLM API key: %s (mode 0600)\n", ans.llmKeyPath)
				}
			}

			if err := os.WriteFile(yamlPath, []byte(content), 0o640); err != nil {
				return &runtimeErr{err}
			}
			fmt.Fprintln(out, "trollbridge init: created files:")
			fmt.Fprintln(out, "  ", yamlPath)

			caGenerated := false
			if interactive && ans.interception {
				certPath := filepath.Join(dir, "trollbridge-ca.crt")
				keyPath := filepath.Join(dir, "trollbridge-ca.key")
				caObj, err := bootstrapCA(certPath, keyPath, force)
				if err != nil {
					return &runtimeErr{fmt.Errorf("bootstrap CA: %w", err)}
				}
				fmt.Fprintln(out, "   generated CA:")
				fmt.Fprintln(out, "     cert:", certPath)
				fmt.Fprintln(out, "     key: ", keyPath, "(mode 0600)")
				fmt.Fprintln(out, "     fingerprint (sha-256):", caObj.SHA256Fingerprint())
				caGenerated = true
			}

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

			fmt.Fprintln(out, "\nnext steps:")
			if !caGenerated {
				fmt.Fprintln(out, "  trollbridge ca init"+cFlag+"                              # generate the CA")
			} else {
				fmt.Fprintln(out, "  trollbridge ca install"+cFlag+"     # show OS-tailored trust-store install commands")
			}
			fmt.Fprintln(out, "  trollbridge ca client-cert <op>                  # issue your operator client cert")
			fmt.Fprintln(out, "  install <op>.{crt,key} at ~/.trollbridge/controller-client.{crt,key}")
			fmt.Fprintln(out, "  trollbridge validate"+cFlag)
			fmt.Fprintln(out, "  trollbridge doctor"+cFlag+"   # check yaml + LLM connection")
			fmt.Fprintln(out, "  trollbridge run"+cFlag)
			fmt.Fprintln(out, "  eval \"$(trollbridge env"+cFlag+")\"   # wire client env")
			return nil
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "d", defaultDir, "directory to write the config to (default: matches `trollbridge run -c` discovery)")
	cmd.Flags().BoolVar(&force, "force", false, "archive existing files (.bak) and replace")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "skip the guided setup; write the static default config")
	return cmd
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

// bootstrapCA wraps ca.Init for the interactive interception path.
// Exposed as a package-level var so tests can stub it without
// running RSA-4096 keygen.
var bootstrapCA = func(certPath, keyPath string, force bool) (*ca.CA, error) {
	return ca.Init(certPath, keyPath, ca.KeyTypeRSA4096, force)
}
