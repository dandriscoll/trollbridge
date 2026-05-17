package setupplan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestBuild_VersionAndKeyFields ensures Build() returns a non-empty
// plan with the schema fields agents depend on. Catches accidental
// drift if a future change drops a top-level field without bumping
// the version.
func TestBuild_VersionAndKeyFields(t *testing.T) {
	p := Build()
	if p.Version != PlanVersion {
		t.Errorf("Build().Version = %q, want %q", p.Version, PlanVersion)
	}
	if p.Project != "trollbridge" {
		t.Errorf("Build().Project = %q, want trollbridge", p.Project)
	}
	if p.EntryDoc != "SETUP-AGENT.md" {
		t.Errorf("Build().EntryDoc = %q, want SETUP-AGENT.md", p.EntryDoc)
	}
	if len(p.Questions) == 0 {
		t.Fatal("Build().Questions is empty")
	}
	if len(p.Steps) == 0 {
		t.Fatal("Build().Steps is empty")
	}
	if len(p.PlatformNotes) < 3 {
		t.Errorf("Build().PlatformNotes count = %d, want at least 3 (linux/darwin/windows)", len(p.PlatformNotes))
	}
}

// TestBuild_DependsOnReferencesValidQuestions ensures every
// depends_on names a real question id. Dangling references would
// silently lead an agent to skip questions it should ask.
func TestBuild_DependsOnReferencesValidQuestions(t *testing.T) {
	p := Build()
	ids := map[string]bool{}
	for _, q := range p.Questions {
		ids[q.ID] = true
	}
	for _, q := range p.Questions {
		for _, dep := range q.DependsOn {
			// dep is "qid=value"; extract the qid.
			parts := strings.SplitN(dep, "=", 2)
			if !ids[parts[0]] {
				t.Errorf("question %q depends_on %q but no such question id exists", q.ID, parts[0])
			}
		}
	}
}

// TestBuild_RequiredQuestionsCoverLoadBearingAxes asserts the
// load-bearing decisions an agent MUST ask are all flagged
// required: install_mode, topology, policy mode, interception,
// advisor enabled. Missing any of these silently downgrades the
// agentic flow.
func TestBuild_RequiredQuestionsCoverLoadBearingAxes(t *testing.T) {
	p := Build()
	req := map[string]bool{}
	for _, q := range p.Questions {
		if q.Required && q.DependsOn == nil {
			req[q.ID] = true
		}
	}
	for _, id := range []string{"q.install_mode", "q.topology", "q.policy_mode", "q.interception", "q.advisor.enabled"} {
		if !req[id] {
			t.Errorf("required (no depends_on) question missing: %q", id)
		}
	}
}

// TestRenderJSON_Decodes asserts the JSON view round-trips through
// the standard decoder.
func TestRenderJSON_Decodes(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, Build()); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var back Plan
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("json round-trip: %v", err)
	}
	if back.Version != PlanVersion {
		t.Errorf("round-trip Version = %q, want %q", back.Version, PlanVersion)
	}
	if len(back.Questions) != len(Build().Questions) {
		t.Errorf("round-trip lost questions: %d vs %d", len(back.Questions), len(Build().Questions))
	}
}

// TestRenderYAML_Decodes asserts the YAML view round-trips through
// yaml.v3.
func TestRenderYAML_Decodes(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderYAML(&buf, Build()); err != nil {
		t.Fatalf("RenderYAML: %v", err)
	}
	var back Plan
	if err := yaml.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("yaml round-trip: %v", err)
	}
	if back.Version != PlanVersion {
		t.Errorf("yaml round-trip Version = %q, want %q", back.Version, PlanVersion)
	}
}

// TestRenderDoc_ContainsExpectedHeadings ensures the markdown
// view exposes the section headings agents grep for.
func TestRenderDoc_ContainsExpectedHeadings(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderDoc(&buf, Build()); err != nil {
		t.Fatalf("RenderDoc: %v", err)
	}
	s := buf.String()
	for _, h := range []string{
		"# trollbridge — Agentic setup plan",
		"## Goals — start here",
		"## Questions to ask the user",
		"## Steps the agent runs",
		"## Platform notes",
		"## Verification",
		"## Backward compatibility",
	} {
		if !strings.Contains(s, h) {
			t.Errorf("RenderDoc missing heading %q", h)
		}
	}
}
