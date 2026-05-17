package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// defaultConfigYAML is the static yaml `trollbridge init` writes. The
// authoring template (defaultConfigYAMLTemplate, below) uses unix
// canonical paths; on Windows we substitute the %ProgramData%
// equivalents at startup so the rendered yaml is cross-machine valid
// on the host the operator is on.
var defaultConfigYAML = strings.NewReplacer(
	"/etc/trollbridge/llm.key", DefaultDaemonLLMKeyPath,
	"/etc/trollbridge/trollbridge-ca.crt", DefaultCACertPath,
	"/etc/trollbridge/trollbridge-ca.key", DefaultCAKeyPath,
	"/var/log/trollbridge/audit.jsonl", DefaultDaemonAuditPath,
	"/etc/trollbridge/", DefaultCADir+string(filepath.Separator),
).Replace(defaultConfigYAMLTemplate)

const defaultConfigYAMLTemplate = `# 1. Per-surface bind. Each value is "<host>:<port>". Use:
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

# Controller — operator-facing control plane (approve/deny/attach).
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
	var answersPath string
	defaultDir := filepath.Dir(defaultConfigPath())
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a trollbridge.yaml. Interactive when stdin is a TTY; --answers <file> for agentic flow; static defaults otherwise.",
		Long: `Create a trollbridge.yaml in the target directory.

The default directory matches the location every other subcommand
reads from: the directory portion of $TROLLBRIDGE_CONFIG when set,
otherwise the current working directory. Pass -d <path> to write
somewhere else.

By default, when stdin is a TTY, init runs as a guided setup that
asks about topology, policy mode, TLS interception, and LLM
advisor — and (when interception is chosen) generates the CA in
the same invocation.

When --answers <file> is passed, init reads structured answers
from the file (or stdin if the value is "-") and renders the
config without prompting. This is the agentic-onboarding path:
an LLM onboarding agent collects user answers, writes the
file matching the schema in config.agentic.yaml, and calls init
with --answers. The same rendering as the interactive path runs;
the answers file is just a non-TTY input channel.

When stdin is not a TTY (CI, redirected input) or --non-interactive
is passed, init writes the static default config without prompting.

See SETUP-AGENT.md for the full agentic-onboarding flow.
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				dir = defaultDir
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return &runtimeErr{err}
			}
			out := cmd.OutOrStdout()
			useAnswersFile := answersPath != ""
			interactive := !useAnswersFile && !nonInteractive && stdinIsTTY(cmd.InOrStdin())

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
			if useAnswersFile {
				a, err := loadAnswersFile(answersPath, cmd.InOrStdin())
				if err != nil {
					return &configErr{err}
				}
				ans = a
				absDir, abserr := filepath.Abs(dir)
				if abserr != nil {
					absDir = dir
				}
				applyPathDefaults(&ans, absDir)
				content = applyAnswers(defaultConfigYAML, ans)

				if ans.llmEnabled && ans.installMode == "user" && ans.llmKey != "" {
					if err := writeLLMKey(ans.llmKeyPath, ans.llmKey); err != nil {
						return &runtimeErr{fmt.Errorf("write LLM key: %w", err)}
					}
					fmt.Fprintf(out, "  wrote LLM API key: %s (mode 0600)\n", ans.llmKeyPath)
				}
			} else if interactive {
				a, err := runInteractiveInit(cmd.InOrStdin(), out)
				if err != nil {
					return &configErr{err}
				}
				ans = a

				absDir, abserr := filepath.Abs(dir)
				if abserr != nil {
					absDir = dir
				}
				applyPathDefaults(&ans, absDir)
				content = applyAnswers(defaultConfigYAML, ans)

				// user-mode + LLM advisor: the operator typed the
				// key into the prompt; init writes the file at
				// <init-dir>/llm.key with mode 0600. daemon-mode
				// suppresses the prompt; the key gets written by
				// the operator post-install (next-steps document
				// the recipe).
				if ans.llmEnabled && ans.installMode == "user" && ans.llmKey != "" {
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

			// Both interactive and --answers paths populate `ans` and
			// expect mode-aware next-steps. Only the bare static
			// default (no flags, no TTY) gets the generic block.
			hasAnswers := interactive || useAnswersFile
			printNextSteps(out, ans, hasAnswers, cFlag)
			return nil
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "d", defaultDir, "directory to write the config to (default: matches `trollbridge run -c` discovery)")
	cmd.Flags().BoolVar(&force, "force", false, "archive existing files (.bak) and replace")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "skip the guided setup; write the static default config")
	cmd.Flags().StringVar(&answersPath, "answers", "", "read structured answers from this YAML file ('-' = stdin); see SETUP-AGENT.md and config.agentic.yaml")
	return cmd
}

// applyPathDefaults branches on install mode to anchor every
// answered path. user-mode anchors at the absolute init-dir path
// (so the daemon, started later from any cwd, still finds them —
// issue #14); daemon-mode uses the canonical /etc/trollbridge/ +
// /var/log/trollbridge/ paths. Shared by the interactive flow and
// the --answers flow so both render the same set of resolved
// paths from the same answers.
//
// Operators who supply an explicit audit_path / cert_path / etc.
// in their answers file can override after this runs — they win
// over the install-mode default. (Today only audit_path has an
// explicit override field; cert/key/llm-key paths are always
// derived from install mode + init dir.)
func applyPathDefaults(ans *initAnswers, absDir string) {
	if ans.installMode == "daemon" {
		ans.caCertPath = DefaultCACertPath
		ans.caKeyPath = DefaultCAKeyPath
		if ans.auditPath == "" {
			ans.auditPath = DefaultDaemonAuditPath
		}
		ans.llmKeyPath = DefaultDaemonLLMKeyPath
		return
	}
	ans.caCertPath = filepath.Join(absDir, "trollbridge-ca.crt")
	ans.caKeyPath = filepath.Join(absDir, "trollbridge-ca.key")
	if ans.auditPath == "" {
		ans.auditPath = filepath.Join(absDir, "trollbridge.audit.jsonl")
	}
	ans.llmKeyPath = filepath.Join(absDir, "llm.key")
}

// printNextSteps emits an operator-facing block describing the
// commands they should run after `trollbridge init`. The output is
// install-mode-aware (user vs daemon) AND topology-aware (does the
// cert need to be transferred to consumer hosts?). CA generation
// is always a separate `trollbridge ca init` step, never inlined
// into `init` — see issue #19. The daemon never runs as root —
// see packaging/systemd/trollbridge.service (User=trollbridge).
func printNextSteps(out io.Writer, ans initAnswers, interactive bool, cFlag string) {
	w := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	w("\nnext steps:\n")

	// Non-interactive defaults to user-mode + local topology.
	if !interactive {
		w("  trollbridge ca init%s                       # generates the CA next to your config\n", cFlag)
		w("  trollbridge ca client-cert <op>%s            # issue an operator client cert\n", cFlag)
		w("  trollbridge run%s                            # start the daemon\n", cFlag)
		w("  trollbridge test https://example.com%s       # probe one request through the proxy\n", cFlag)
		return
	}

	if ans.installMode == "daemon" {
		printDaemonNextSteps(w, ans, cFlag)
		return
	}
	printUserNextSteps(w, ans, cFlag)
}

// printUserNextSteps renders the user-mode flow. No sudo anywhere;
// every command runs as the operator. CA files end up next to the
// yaml; the LLM key is already written if applicable.
func printUserNextSteps(w func(string, ...any), ans initAnswers, cFlag string) {
	w("  # user-mode: every step runs as you; no sudo anywhere.\n")
	w("\n")
	w("  trollbridge ca init%s                       # generates the CA next to your config\n", cFlag)
	w("  trollbridge ca client-cert <op>%s            # issue an operator client cert\n", cFlag)
	w("\n")
	if ans.interception && ans.topology == "remote" {
		w("  # consumers run on a different machine. Transfer the CA cert:\n")
		w("  scp <init-dir>/trollbridge-ca.crt <consumer>:/tmp/trollbridge-ca.crt\n")
		w("  # then on each consumer:\n")
		w("  trollbridge ca install --apply --cert /tmp/trollbridge-ca.crt\n")
		w("\n")
	} else if ans.interception {
		w("  trollbridge ca install --apply               # install the CA into your system trust store\n")
		w("\n")
	}
	w("  trollbridge run%s\n", cFlag)
	w("\n")
	w("  # in another shell:\n")
	w("  eval \"$(trollbridge env%s)\"\n", cFlag)
	w("  trollbridge test https://example.com%s\n", cFlag)
}

// initGOOS is read in place of runtime.GOOS so tests can pick the
// Windows branch without cross-compiling. Production callers leave it
// at runtime.GOOS. Mirrors `updateGOOS` in update.go.
var initGOOS = runtime.GOOS

// printDaemonNextSteps renders the daemon-mode flow. Setup steps
// run via `sudo -u trollbridge` (after package install creates the
// user/group/dirs); the daemon process itself runs as the
// `trollbridge` user, never as root.
//
// On Windows, daemon-mode is not yet supported (no Windows-service
// integration, no NTFS ACL enforcement on CA keys — see issue #101
// and its tracked Windows-daemon follow-up). Refuse with a clear
// next-action instead of emitting POSIX commands the operator
// cannot execute. Closes #101 part 2.
func printDaemonNextSteps(w func(string, ...any), ans initAnswers, cFlag string) {
	if initGOOS == "windows" {
		w("  # daemon-mode is not yet supported on Windows.\n")
		w("  # Trollbridge user-mode runs under your account and uses\n")
		w("  # per-user filesystem ACLs to protect the CA key. Re-run\n")
		w("  # `trollbridge init` and choose user-mode at the install-mode\n")
		w("  # prompt, or watch\n")
		w("  #   https://github.com/dandriscoll/trollbridge/issues\n")
		w("  # for daemon-mode-on-Windows support (Windows-service\n")
		w("  # integration + NTFS ACL enforcement on CA keys).\n")
		return
	}
	w("  # daemon-mode: trollbridge runs as the `trollbridge` system user (not root).\n")
	w("  # The package install creates the user/group and pre-creates /etc/trollbridge\n")
	w("  # and /var/log/trollbridge owned by it. Setup steps run via `sudo -u trollbridge`.\n")
	w("\n")
	w("  sudo -u trollbridge trollbridge ca init%s          # generates /etc/trollbridge/trollbridge-ca.{crt,key}\n", cFlag)
	w("  sudo -u trollbridge trollbridge ca client-cert <op>%s\n", cFlag)
	if ans.llmEnabled {
		w("  # write your LLM API key (paste, then Ctrl-D) as the trollbridge user:\n")
		w("  sudo -u trollbridge install -m 600 /dev/stdin /etc/trollbridge/llm.key\n")
	}
	w("\n")
	if ans.interception && ans.topology == "remote" {
		w("  # consumers run on a different machine. Transfer the CA cert:\n")
		w("  scp <proxy-host>:/etc/trollbridge/trollbridge-ca.crt \\\n")
		w("      <consumer>:/etc/trollbridge/trollbridge-ca.crt\n")
		w("  # then on each consumer:\n")
		w("  sudo trollbridge ca install --apply\n")
		w("\n")
	} else if ans.interception {
		w("  sudo trollbridge ca install --apply               # install the CA into the system trust store\n")
		w("\n")
	}
	w("  # start the daemon under systemd (the unit ships in packaging/systemd/):\n")
	w("  sudo systemctl start trollbridge\n")
	w("\n")
	w("  # in another shell, on a consumer:\n")
	w("  eval \"$(trollbridge env%s)\"\n", cFlag)
	w("  trollbridge test https://example.com%s\n", cFlag)
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

