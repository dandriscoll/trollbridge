package main

import (
	"fmt"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/setupplan"
	"github.com/spf13/cobra"
)

// newSetupPlanCmd implements `trollbridge setup-plan`: emit the
// canonical agentic-onboarding plan as JSON (default), YAML, or
// markdown. The plan content lives in internal/setupplan; this
// command is a thin renderer.
//
// Format selection mirrors `validate`'s convention: JSON is the
// machine surface, --doc and --yaml are alternative views over
// the same data. Exactly one format is emitted; on `--json --yaml`
// the latter wins (cobra's flag parsing reads each flag once and
// the renderer just switches on the resolved value).
func newSetupPlanCmd() *cobra.Command {
	var format string
	var asJSON, asYAML, asDoc bool
	cmd := &cobra.Command{
		Use:   "setup-plan",
		Short: "Emit the agentic-onboarding plan (JSON / YAML / markdown).",
		Long: `setup-plan prints the structured plan an onboarding LLM agent
walks to set up trollbridge. The plan names the questions to ask
the user, the order to ask them, what each answer means, the
commands to run, the platform-specific notes, and the
verification contract.

The plan is the same on every host the binary runs on; it has no
I/O, no env inspection, no config reads. It is the *static
agent-readable plan*. Per-environment dynamic checks live in
` + "`trollbridge verify`" + `.

Three formats:

  --json   (default) machine-readable JSON; one object on stdout
  --yaml   same shape, YAML serialization
  --doc    markdown view (the same content SETUP-AGENT.md presents)

See ` + "`SETUP-AGENT.md`" + ` for the full agentic-onboarding entry document.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve format: explicit -- flag wins; otherwise the
			// shorthand bool flags; otherwise JSON. Exactly one format
			// is emitted to keep the output unambiguous.
			f := strings.ToLower(format)
			switch {
			case f != "":
				// explicit --format wins
			case asYAML:
				f = "yaml"
			case asDoc:
				f = "doc"
			case asJSON:
				f = "json"
			default:
				f = "json"
			}

			out := cmd.OutOrStdout()
			plan := setupplan.Build()
			switch f {
			case "json":
				return setupplan.RenderJSON(out, plan)
			case "yaml":
				return setupplan.RenderYAML(out, plan)
			case "doc", "md", "markdown":
				return setupplan.RenderDoc(out, plan)
			default:
				return &configErr{fmt.Errorf("setup-plan: unknown --format %q (want one of: json, yaml, doc)", format)}
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "output format: json | yaml | doc (default json)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "alias for --format=json")
	cmd.Flags().BoolVar(&asYAML, "yaml", false, "alias for --format=yaml")
	cmd.Flags().BoolVar(&asDoc, "doc", false, "alias for --format=doc (markdown view)")
	return cmd
}
