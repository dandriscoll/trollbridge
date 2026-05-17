package setupplan

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// RenderJSON encodes the plan as a single JSON object on stdout.
// Pretty-printed with two-space indent so an operator who reads
// the output gets readable structure; agents that consume the
// bytes don't care about whitespace.
func RenderJSON(out io.Writer, p Plan) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// RenderYAML encodes the plan as YAML. Same shape as the JSON
// view; differs only in marshalling.
func RenderYAML(out io.Writer, p Plan) error {
	enc := yaml.NewEncoder(out)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(p)
}

// RenderDoc writes the markdown view — the same content
// SETUP-AGENT.md presents to a human-reading agent. Keeping the
// markdown derived from the same data structure means
// `setup-plan --doc` and the committed SETUP-AGENT.md cannot
// drift: the test suite asserts they match.
func RenderDoc(out io.Writer, p Plan) error {
	var b strings.Builder
	b.WriteString("# trollbridge — Agentic setup plan\n\n")
	fmt.Fprintf(&b, "Plan version: %s. Project: %s. Entry doc: `%s`. Authoring YAML template: `%s`.\n\n", p.Version, p.Project, p.EntryDoc, p.AgenticYAMLTemplate)
	b.WriteString(p.Summary + "\n\n")

	b.WriteString("## Goals — start here\n\n")
	b.WriteString("Ask the user which of these best describes the outcome they want. " +
		"You can map multiple goals, but pick the dominant one first; the others are " +
		"add-ons.\n\n")
	for _, g := range p.Goals {
		fmt.Fprintf(&b, "- **%s** — %s\n  - Knobs: `%s`\n", g.Label, g.Description, strings.Join(g.Knobs, "`, `"))
	}
	b.WriteString("\n")

	b.WriteString("## Questions to ask the user\n\n")
	b.WriteString("Walk these in order. Skip any question whose `depends_on` does not match. " +
		"For optional questions (`required: false`), only ask if the user's goal makes them " +
		"relevant or the user volunteers interest. Bold values are defaults.\n\n")
	for _, q := range p.Questions {
		marker := "optional"
		if q.Required {
			marker = "REQUIRED"
		}
		fmt.Fprintf(&b, "### %s — `%s` (%s)\n\n", q.ID, q.YAMLPath, marker)
		fmt.Fprintf(&b, "**Prompt:** %s\n\n", q.Prompt)
		fmt.Fprintf(&b, "**Why this matters:** %s\n\n", q.Rationale)
		if len(q.DependsOn) > 0 {
			fmt.Fprintf(&b, "**Depends on:** %s\n\n", strings.Join(q.DependsOn, ", "))
		}
		if q.Default != "" {
			fmt.Fprintf(&b, "**Default:** `%s`\n\n", q.Default)
		}
		if len(q.Answers) > 0 {
			for _, a := range q.Answers {
				if a.Value == q.Default {
					fmt.Fprintf(&b, "- **`%s`** (default) — %s  \n  *Consequence:* %s\n", a.Value, a.Label, a.Consequence)
				} else {
					fmt.Fprintf(&b, "- `%s` — %s  \n  *Consequence:* %s\n", a.Value, a.Label, a.Consequence)
				}
			}
			b.WriteString("\n")
		} else if q.Free {
			b.WriteString("*Free-form answer.*\n\n")
		}
		if q.Warning != "" {
			fmt.Fprintf(&b, "> ⚠ %s\n\n", q.Warning)
		}
		if q.SafeIfSkip != "" {
			fmt.Fprintf(&b, "*Safe default if skipped:* %s\n\n", q.SafeIfSkip)
		}
	}

	b.WriteString("## Steps the agent runs (or asks the user to run)\n\n")
	b.WriteString("Run these in order after answers are collected. `when:` clauses are conditionals — " +
		"only run when the named answer holds. `run_by` names who must execute: `agent` is the " +
		"onboarding agent; `user` is the operator with normal privileges; `user-elevated` needs sudo/Administrator.\n\n")
	for _, s := range p.Steps {
		fmt.Fprintf(&b, "### %s — %s\n\n", s.ID, s.Title)
		fmt.Fprintf(&b, "%s\n\n", s.Description)
		fmt.Fprintf(&b, "`run_by: %s`", s.RunBy)
		if s.When != "" {
			fmt.Fprintf(&b, " · `when: %s`", s.When)
		}
		if len(s.Platforms) > 0 {
			fmt.Fprintf(&b, " · `platforms: %s`", strings.Join(s.Platforms, ", "))
		}
		b.WriteString("\n\n")
		if len(s.Commands) > 0 {
			b.WriteString("```sh\n")
			for _, c := range s.Commands {
				b.WriteString(c + "\n")
			}
			b.WriteString("```\n\n")
		}
	}

	b.WriteString("## Platform notes\n\n")
	for _, pn := range p.PlatformNotes {
		fmt.Fprintf(&b, "### %s\n\n", pn.Platform)
		for _, n := range pn.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Verification\n\n")
	fmt.Fprintf(&b, "Run `%s`. JSON-on-stdout: `%v`.\n\n", p.Verification.Command, p.Verification.JSON)
	b.WriteString("Confirms:\n\n")
	for _, c := range p.Verification.Confirms {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	if len(p.Verification.ManualFollowups) > 0 {
		b.WriteString("\nManual followups the agent must surface to the user:\n\n")
		for _, c := range p.Verification.ManualFollowups {
			fmt.Fprintf(&b, "- %s\n", c)
		}
	}
	b.WriteString("\n")

	b.WriteString("## Backward compatibility\n\n")
	for _, n := range p.BackwardCompat {
		fmt.Fprintf(&b, "- %s\n", n)
	}

	_, err := io.WriteString(out, b.String())
	return err
}
