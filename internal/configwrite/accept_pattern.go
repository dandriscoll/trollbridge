package configwrite

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PatternRule is the structured shape an accepted pattern suggestion
// writes into a rule file. Mirrors policy.Rule's pattern-aware
// fields without importing the policy package (avoids a cycle).
type PatternRule struct {
	ID          string
	Description string
	Priority    int               // 0 → use Engine's default (100)
	Pattern     string            // pattern name, e.g. "azure_arm"
	Components  map[string]string // constant components; absent keys = wildcard
	Method      string            // uppercase verb, or "" for any
	Effect      string            // "allow" or "deny"
}

// AcceptPatternSuggestion appends a pattern-shaped rule to rulesPath
// and removes the source entries from listsPath (under
// `lists.allow` or `lists.deny`, depending on `list`). Both writes
// are independent and atomic per file; if the rule write succeeds
// but the list write fails, the rule lands and the sources remain
// in the list (redundant but correct — the rule subsumes them).
// Re-invoking with the same rule (same generated ID) is idempotent:
// the rule append is skipped if an entry with the same ID exists;
// source removal still proceeds.
//
// Returns (ruleChanged, sourcesChanged, err). ruleChanged is true
// when the rule was appended; sourcesChanged when at least one
// source entry was removed from the list. err is the first error
// (rule write before source removal).
func AcceptPatternSuggestion(rulesPath, listsPath string, list string, rule PatternRule, sources []string) (ruleChanged, sourcesChanged bool, err error) {
	if rulesPath == "" {
		return false, false, fmt.Errorf("accept pattern suggestion: empty rulesPath — add a rule file path under policy.include in trollbridge.yaml")
	}
	if rule.ID == "" {
		return false, false, fmt.Errorf("accept pattern suggestion: rule.ID is empty")
	}
	if rule.Pattern == "" {
		return false, false, fmt.Errorf("accept pattern suggestion: rule.Pattern is empty")
	}
	if rule.Effect != "allow" && rule.Effect != "deny" && rule.Effect != "ask_user" && rule.Effect != "ask_llm" {
		return false, false, fmt.Errorf("accept pattern suggestion: rule.Effect %q invalid", rule.Effect)
	}
	if list != "allow" && list != "deny" {
		return false, false, fmt.Errorf("accept pattern suggestion: list %q invalid", list)
	}

	ruleChanged, err = appendPatternRule(rulesPath, rule)
	if err != nil {
		return false, false, fmt.Errorf("append pattern rule to %s: %w", rulesPath, err)
	}

	if len(sources) > 0 {
		// Reuse the existing mutate primitive to remove sources
		// from the list. (The rule we just wrote subsumes them.)
		srcSet := map[string]struct{}{}
		for _, s := range sources {
			srcSet[strings.TrimSpace(s)] = struct{}{}
		}
		sourcesChanged, err = mutate(listsPath, list, func(entries []string) []string {
			kept := make([]string, 0, len(entries))
			for _, e := range entries {
				if _, isSrc := srcSet[strings.TrimSpace(e)]; isSrc {
					continue
				}
				kept = append(kept, e)
			}
			return kept
		})
		if err != nil {
			return ruleChanged, false, fmt.Errorf("remove sources from %s: %w", listsPath, err)
		}
	}
	return ruleChanged, sourcesChanged, nil
}

// appendPatternRule appends one rule to a rules YAML file. The file
// MUST exist and parse as a YAML sequence of rule mappings (matches
// engine.Reload's expectations). A rule whose `id` matches an
// existing entry is treated as already-present (returns false, nil).
func appendPatternRule(path string, rule PatternRule) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return false, fmt.Errorf("parse: %w", err)
	}
	// Rule files are a top-level sequence (per Engine.Reload). A
	// completely empty file unmarshals as a nil document; we
	// initialize a sequence node in that case.
	var seq *yaml.Node
	if len(root.Content) == 0 {
		seq = &yaml.Node{Kind: yaml.SequenceNode}
		root.Kind = yaml.DocumentNode
		root.Content = []*yaml.Node{seq}
	} else if root.Content[0].Kind == yaml.SequenceNode {
		seq = root.Content[0]
	} else {
		return false, fmt.Errorf("top-level is not a YAML sequence (Engine.Reload expects `- id: ...` rules)")
	}
	// Idempotency check: scan existing rules for matching id.
	for _, item := range seq.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(item.Content); i += 2 {
			if item.Content[i].Value == "id" && item.Content[i+1].Value == rule.ID {
				return false, nil
			}
		}
	}
	seq.Content = append(seq.Content, ruleToNode(rule))

	out, err := yaml.Marshal(&root)
	if err != nil {
		return false, fmt.Errorf("marshal: %w", err)
	}
	if err := atomicWrite(path, out, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func ruleToNode(rule PatternRule) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode}
	addStr := func(k, v string) {
		if v == "" {
			return
		}
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: v},
		)
	}
	addInt := func(k string, v int) {
		if v == 0 {
			return
		}
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("%d", v)},
		)
	}

	addStr("id", rule.ID)
	addStr("description", rule.Description)
	addInt("priority", rule.Priority)

	// match: { pattern: ..., components: {...}, method: ... }
	matchVal := &yaml.Node{Kind: yaml.MappingNode}
	matchVal.Content = append(matchVal.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "pattern"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: rule.Pattern},
	)
	if len(rule.Components) > 0 {
		// Sorted for stable output.
		keys := make([]string, 0, len(rule.Components))
		for k := range rule.Components {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		comps := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range keys {
			comps.Content = append(comps.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: k},
				&yaml.Node{Kind: yaml.ScalarNode, Value: rule.Components[k]},
			)
		}
		matchVal.Content = append(matchVal.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "components"},
			comps,
		)
	}
	if rule.Method != "" {
		matchVal.Content = append(matchVal.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "method"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: rule.Method},
		)
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "match"},
		matchVal,
	)

	addStr("effect", rule.Effect)
	return m
}
