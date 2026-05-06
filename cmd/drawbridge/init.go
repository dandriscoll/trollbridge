package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const defaultConfigYAML = `drawbridge_version: 1

listen:
  address: 127.0.0.1
  port: 8080

mode: default-deny

interception:
  enabled: false

logging:
  audit_path: ./drawbridge.audit.jsonl
  audit_overflow: deny

approvals:
  control_listen: 127.0.0.1:8081
  timeout_seconds: 300
  on_timeout: deny

identities:
  - id: dev-laptop
    match:
      source_ip: 127.0.0.1

policy:
  # Fast-path lists. Evaluated BEFORE YAML rules and BEFORE the LLM
  # advisor. A match is the final decision. Format per host[:port][/path].
  allow_files:
    - allow.txt
  deny_files:
    - deny.txt
  # Structured rules for advanced cases (time windows, body patterns,
  # ask_user, ask_llm). Optional.
  include:
    - rules.yaml
`

const defaultRulesYAML = `# Optional structured rules. The simple cases live in allow.txt
# and deny.txt; reach for this file only when you need time
# windows, body patterns, identity scoping, or ask_user / ask_llm
# effects.
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

const defaultAllowTxt = `# allow.txt — flat allow list. One pattern per line. Comments
# start with '#'. A match here = final allow (no rule engine, no
# advisor consulted). Format:  host[:port][/path]
#
# Wildcards:
#   *               any host (use sparingly)
#   *.example.com   any subdomain of example.com (a.example.com,
#                   a.b.example.com); does NOT match bare example.com
#   host:443        exact port
#   host            any port
#   host/api/*      path prefix /api/
#   host/exact      exact path
#
# Edit and grow this file to fit your agent's needs.

# localhost (dev convenience)
localhost
127.0.0.1
`

const defaultDenyTxt = `# deny.txt — flat deny list. A match here = final deny (no rule
# engine, no advisor consulted). Deny wins over allow.
#
# The defaults below cover credential-bearing endpoints that an
# agent should never reach. Add to this file before broadening
# your allow.txt.

# Cloud instance metadata services (credential-bearing).
169.254.169.254
metadata.google.internal
metadata.azure.com
`

func newInitCmd() *cobra.Command {
	var dir string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a default drawbridge.yaml and rule set.",
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
				filepath.Join(dir, "allow.txt"):       defaultAllowTxt,
				filepath.Join(dir, "deny.txt"):        defaultDenyTxt,
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
			fmt.Fprintln(out, "  drawbridge validate -c", filepath.Join(dir, "drawbridge.yaml"))
			fmt.Fprintln(out, "  drawbridge run      -c", filepath.Join(dir, "drawbridge.yaml"))
			fmt.Fprintln(out, "  set HTTP_PROXY=http://127.0.0.1:8080 in your client environment")
			return nil
		},
	}
	cmd.Flags().StringVarP(&dir, "dir", "d", ".", "directory to write the config to")
	cmd.Flags().BoolVar(&force, "force", false, "archive existing files (.bak) and replace")
	return cmd
}
