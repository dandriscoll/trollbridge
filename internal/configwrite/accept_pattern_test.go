package configwrite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeYAMLFiles(t *testing.T, listsContent, rulesContent string) (listsPath, rulesPath string) {
	t.Helper()
	dir := t.TempDir()
	listsPath = filepath.Join(dir, "trollbridge.yaml")
	rulesPath = filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(listsPath, []byte(listsContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0o644); err != nil {
		t.Fatal(err)
	}
	return
}

func TestAcceptPatternSuggestion_AppendsRuleAndRemovesSources(t *testing.T) {
	lists := `lists:
  allow:
    - GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1
    - GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2
    - GET https://api.github.com/repos/foo/bar
`
	rules := `- id: ignore-cloud-metadata
  match:
    host: 169.254.169.254
  effect: deny
`
	listsPath, rulesPath := writeYAMLFiles(t, lists, rules)

	rule := PatternRule{
		ID:      "suggested-azure_arm-abc12345",
		Pattern: "azure_arm",
		Components: map[string]string{
			"subscription": "SUB-A",
			"resource_group": "rg1",
		},
		Method: "GET",
		Effect: "allow",
	}
	sources := []string{
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
		"GET https://management.azure.com/subscriptions/SUB-A/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2",
	}

	ruleChanged, srcChanged, err := AcceptPatternSuggestion(rulesPath, listsPath, "allow", rule, sources)
	if err != nil {
		t.Fatalf("AcceptPatternSuggestion: %v", err)
	}
	if !ruleChanged {
		t.Fatal("rule should have been appended")
	}
	if !srcChanged {
		t.Fatal("sources should have been removed")
	}

	rulesOut, _ := os.ReadFile(rulesPath)
	rulesStr := string(rulesOut)
	if !strings.Contains(rulesStr, "suggested-azure_arm-abc12345") {
		t.Fatalf("rule id missing from rules file:\n%s", rulesStr)
	}
	if !strings.Contains(rulesStr, "azure_arm") || !strings.Contains(rulesStr, "SUB-A") {
		t.Fatalf("rule body missing pattern/components:\n%s", rulesStr)
	}
	// rule list still parses as YAML.
	var parsed []map[string]any
	if err := yaml.Unmarshal(rulesOut, &parsed); err != nil {
		t.Fatalf("rules YAML doesn't parse: %v\n%s", err, rulesStr)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 rules in file (original + new); got %d", len(parsed))
	}

	listsOut, _ := os.ReadFile(listsPath)
	listsStr := string(listsOut)
	if strings.Contains(listsStr, "vm-1") || strings.Contains(listsStr, "vm-2") {
		t.Fatalf("source entries should have been removed:\n%s", listsStr)
	}
	if !strings.Contains(listsStr, "api.github.com") {
		t.Fatalf("non-source entry was unexpectedly removed:\n%s", listsStr)
	}
}

func TestAcceptPatternSuggestion_IdempotentByID(t *testing.T) {
	lists := `lists:
  allow: []
`
	rules := `- id: existing-rule
  match:
    pattern: azure_arm
  effect: allow
`
	listsPath, rulesPath := writeYAMLFiles(t, lists, rules)

	rule := PatternRule{
		ID:      "existing-rule",
		Pattern: "azure_arm",
		Effect:  "allow",
	}
	ruleChanged, _, err := AcceptPatternSuggestion(rulesPath, listsPath, "allow", rule, nil)
	if err != nil {
		t.Fatalf("AcceptPatternSuggestion: %v", err)
	}
	if ruleChanged {
		t.Fatal("duplicate ID should be no-op (ruleChanged=false)")
	}
}

func TestAcceptPatternSuggestion_EmptyRulesPath_Errors(t *testing.T) {
	_, _, err := AcceptPatternSuggestion("", "lists.yaml", "allow", PatternRule{ID: "x", Pattern: "azure_arm", Effect: "allow"}, nil)
	if err == nil || !strings.Contains(err.Error(), "policy.include") {
		t.Fatalf("expected actionable error about policy.include; got %v", err)
	}
}

func TestAcceptPatternSuggestion_MissingRulesFile_Errors(t *testing.T) {
	listsPath, _ := writeYAMLFiles(t, "lists:\n  allow: []\n", "")
	missing := filepath.Join(filepath.Dir(listsPath), "doesnotexist.yaml")
	_, _, err := AcceptPatternSuggestion(missing, listsPath, "allow", PatternRule{ID: "x", Pattern: "azure_arm", Effect: "allow"}, nil)
	if err == nil {
		t.Fatal("expected error on missing rules file")
	}
}

func TestAcceptPatternSuggestion_InvalidArgs(t *testing.T) {
	listsPath, rulesPath := writeYAMLFiles(t, "lists:\n  allow: []\n", "")
	cases := []struct {
		name string
		rule PatternRule
		list string
	}{
		{"empty id", PatternRule{Pattern: "azure_arm", Effect: "allow"}, "allow"},
		{"empty pattern", PatternRule{ID: "x", Effect: "allow"}, "allow"},
		{"bad effect", PatternRule{ID: "x", Pattern: "azure_arm", Effect: "nope"}, "allow"},
		{"bad list", PatternRule{ID: "x", Pattern: "azure_arm", Effect: "allow"}, "neither"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := AcceptPatternSuggestion(rulesPath, listsPath, tc.list, tc.rule, nil); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestAcceptPatternSuggestion_RuleBodyShape(t *testing.T) {
	listsPath, rulesPath := writeYAMLFiles(t, "lists:\n  allow: []\n", "")
	rule := PatternRule{
		ID:          "test-rule",
		Description: "test description",
		Priority:    250,
		Pattern:     "azure_arm",
		Components:  map[string]string{"subscription": "SUB-A", "resource_type": "virtualMachines"},
		Method:      "DELETE",
		Effect:      "deny",
	}
	if _, _, err := AcceptPatternSuggestion(rulesPath, listsPath, "deny", rule, nil); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(rulesPath)
	var parsed []map[string]any
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("rules count: %d", len(parsed))
	}
	r := parsed[0]
	if r["id"] != "test-rule" || r["description"] != "test description" {
		t.Fatalf("id/description: %+v", r)
	}
	if r["priority"] != 250 {
		t.Fatalf("priority: %v (%T)", r["priority"], r["priority"])
	}
	m, ok := r["match"].(map[string]any)
	if !ok {
		t.Fatalf("match not a map: %T", r["match"])
	}
	if m["pattern"] != "azure_arm" || m["method"] != "DELETE" {
		t.Fatalf("match pattern/method: %+v", m)
	}
	comps, ok := m["components"].(map[string]any)
	if !ok {
		t.Fatalf("components not a map: %T", m["components"])
	}
	if comps["subscription"] != "SUB-A" || comps["resource_type"] != "virtualMachines" {
		t.Fatalf("components: %+v", comps)
	}
	if r["effect"] != "deny" {
		t.Fatalf("effect: %v", r["effect"])
	}
}
