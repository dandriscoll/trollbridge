package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const defaultConfigYAML = `drawbridge_version: 2

# 1. Adapter — the single network knob the daemon binds to.
#    Values: lo (loopback), 0.0.0.0 (all interfaces), or a literal IP/hostname.
adapter: lo

# Ports for the three surfaces. proxy + control are required;
# metrics: 0 disables the Prometheus endpoint.
ports:
  proxy:   8080
  control: 8081
  metrics: 0

# 2. Allow / deny lists — drawbridge writes them back from the REPL.
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
llm:
  enabled: false
  provider: anthropic
  model:    claude-opus-4-7
  endpoint: https://api.anthropic.com
  api_key_path: /etc/drawbridge/llm.key
  send_body: false
  on_unavailable: ask_user
  confidence_floor: medium

  # 4. Directives — the system prompt the advisor follows.
  directives: |
    You are drawbridge's security advisor. Decide allow / deny / ask_user
    for each HTTP request you receive. Refuse anything that exfiltrates
    credentials or contacts cloud metadata services. When uncertain,
    answer ask_user.

# Controller — operator-facing control plane (approve/deny/tui).
# mTLS is enforced; client certs are issued by the same CA used for
# TLS interception (drawbridge ca client-cert <name>).
controller:
  auth: mtls

mode: default-ask

# Interception — TLS termination for HTTPS visibility. CA paths are
# also used by the controller's mTLS listener.
interception:
  enabled: false
  ca:
    cert_path: ./drawbridge-ca.crt
    key_path:  ./drawbridge-ca.key
  leaf_key_type: rsa-4096

# Logging.
logging:
  audit_path:        ./drawbridge.audit.jsonl
  audit_overflow:    deny
  operational_path:  stderr

# Approvals queue tuning. (Auth posture lives under controller.)
approvals:
  timeout_seconds: 300
  on_timeout: deny
  max_pending: 100

# Identities — how clients are recognized at the proxy. Independent
# of how operators authenticate to the controller (mTLS, above).
identities:
  - id: dev-laptop
    match:
      source_ip: 127.0.0.1

# Structured rules for advanced cases (time windows, body patterns,
# ask_user / ask_llm effects). Optional; the inline allow/deny lists
# cover most cases.
policy:
  include:
    - rules.yaml
`

const defaultRulesYAML = `# Optional structured rules. The simple cases live inline in
# drawbridge.yaml under lists.allow / lists.deny. Reach for this
# file only when you need time windows, body patterns, identity
# scoping, or ask_user / ask_llm effects.
#
# Example:
#
# - id: ask-on-mutating-github
#   description: Mutating calls to api.github.com require approval.
#   priority: 300
#   match:
#     host: api.github.com
#     method: ["POST", "PUT", "PATCH", "DELETE"]
#   effect: ask_user
`

func newInitCmd() *cobra.Command {
	var dir string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a default drawbridge.yaml + rules.yaml.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				dir = "."
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return &runtimeErr{err}
			}
			files := map[string]string{
				filepath.Join(dir, "drawbridge.yaml"): defaultConfigYAML,
				filepath.Join(dir, "rules.yaml"):      defaultRulesYAML,
			}
			created := []string{}
			for path, content := range files {
				if _, err := os.Stat(path); err == nil && !force {
					return &configErr{fmt.Errorf("init: file %s already exists; use --force to archive and replace", path)}
				} else if err == nil && force {
					backup := path + ".bak"
					if err := os.Rename(path, backup); err != nil {
						return &runtimeErr{err}
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  archived: %s -> %s\n", path, backup)
				}
				if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
					return &runtimeErr{err}
				}
				created = append(created, path)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "drawbridge init: created files:")
			for _, p := range created {
				fmt.Fprintln(out, "  ", p)
			}
			fmt.Fprintln(out, "\nnext steps:")
			fmt.Fprintln(out, "  drawbridge ca init                              # generate the CA")
			fmt.Fprintln(out, "  drawbridge ca client-cert <op>                  # issue your operator client cert")
			fmt.Fprintln(out, "  install <op>.{crt,key} at ~/.drawbridge/controller-client.{crt,key}")
			fmt.Fprintln(out, "  drawbridge validate -c", filepath.Join(dir, "drawbridge.yaml"))
			fmt.Fprintln(out, "  drawbridge run      -c", filepath.Join(dir, "drawbridge.yaml"))
			fmt.Fprintln(out, "  eval \"$(drawbridge env -c "+filepath.Join(dir, "drawbridge.yaml")+")\"   # wire client env")
			return nil
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "d", ".", "directory to write the config to")
	cmd.Flags().BoolVar(&force, "force", false, "archive existing files (.bak) and replace")
	return cmd
}
