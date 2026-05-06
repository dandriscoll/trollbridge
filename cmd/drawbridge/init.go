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
  include:
    - rules.yaml
`

const defaultRulesYAML = `# Default rules.
- id: deny-cloud-metadata
  description: |
    Cloud metadata services are credential-bearing and should never
    be reachable by an agent.
  priority: 1000
  match:
    host:
      - 169.254.169.254
      - metadata.google.internal
      - metadata.azure.com
  effect: deny

- id: allow-localhost
  description: Localhost traffic is permitted (dev convenience).
  priority: 100
  match:
    host:
      - localhost
      - 127.0.0.1
  effect: allow
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
