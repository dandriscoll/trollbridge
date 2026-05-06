package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/dandriscoll/drawbridge/internal/types"
	"gopkg.in/yaml.v3"
)

// Engine is the deterministic rule engine. Authoritative; never
// elevated by the LLM advisor (DESIGN.md §10.1).
type Engine struct {
	mode    string
	include []string

	mu      sync.RWMutex
	rules   []Rule
	version string
	knownModifiers map[string]bool
}

// NewEngine constructs an Engine from a top-level mode and a list
// of rule-file paths. Rules are loaded once at construction; reload
// via Reload.
func NewEngine(mode string, includePaths []string, knownModifiers []string) (*Engine, error) {
	known := make(map[string]bool, len(knownModifiers))
	for _, m := range knownModifiers {
		known[m] = true
	}
	e := &Engine{
		mode:           mode,
		include:        includePaths,
		knownModifiers: known,
	}
	if err := e.Reload(); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload re-reads rule files and atomically swaps the active set on
// success. On error, prior rules are kept.
func (e *Engine) Reload() error {
	rules := make([]Rule, 0)
	hasher := sha256.New()
	for _, path := range e.include {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read rules %s: %w", path, err)
		}
		hasher.Write(data)
		var fileRules []Rule
		if err := yaml.Unmarshal(data, &fileRules); err != nil {
			return fmt.Errorf("parse rules %s: %w", path, err)
		}
		for i, r := range fileRules {
			if r.ID == "" {
				return fmt.Errorf("rule load error in %s at index %d: missing required field `id`. Fix: add an `id:` line to the rule.", path, i)
			}
			if r.Effect == "" {
				return fmt.Errorf("rule load error in %s at rule index %d (id: %s): missing required field `effect`. Valid values: `allow | deny | ask_user | ask_llm`. Fix: add an `effect:` line under the rule's match clause.", path, i, r.ID)
			}
			switch r.Effect {
			case "allow", "deny", "ask_user", "ask_llm":
			default:
				return fmt.Errorf("rule load error in %s at rule index %d (id: %s): invalid `effect` %q. Valid values: `allow | deny | ask_user | ask_llm`.", path, i, r.ID, r.Effect)
			}
			for _, mod := range r.Modifiers {
				if e.knownModifiers != nil && !e.knownModifiers[mod] {
					return fmt.Errorf("rule load error in %s (id: %s): unknown modifier %q. Run `drawbridge validate` to list known modifiers.", path, r.ID, mod)
				}
			}
			if r.Priority == 0 {
				r.Priority = 100
			}
			rules = append(rules, r)
		}
	}

	// Sort by priority desc, then declaration order (stable sort
	// preserves relative declaration order for equal priorities).
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority > rules[j].Priority
	})

	version := hex.EncodeToString(hasher.Sum(nil))[:16]

	e.mu.Lock()
	e.rules = rules
	e.version = version
	e.mu.Unlock()
	return nil
}

// RuleSetVersion returns the current rule set's version hash.
func (e *Engine) RuleSetVersion() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.version
}

// Rules returns a copy of the active rules (for `drawbridge rules
// list`).
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Decide evaluates rules against the request and returns a
// Decision. Phase 1: no LLM advisor; ask_llm collapses to
// default-mode resolution.
func (e *Engine) Decide(req *types.RequestEvent) types.Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, r := range e.rules {
		if r.matches(req) {
			reason := r.Description
			if reason == "" {
				reason = fmt.Sprintf("rule %s matched", r.ID)
			}
			return types.Decision{
				Effect:    types.Effect(r.Effect),
				Source:    types.SourceRule,
				RuleID:    r.ID,
				Reason:    reason,
				Modifiers: append([]string(nil), r.Modifiers...),
			}
		}
	}

	// No rule matched: fall through to default mode.
	switch e.mode {
	case "default-allow":
		return types.Decision{
			Effect: types.EffectAllow,
			Source: types.SourceDefault,
			Reason: "no rule matched; default-allow mode",
		}
	case "default-ask":
		// Phase 1: collapse to ask_user (no advisor available).
		return types.Decision{
			Effect: types.EffectAskUser,
			Source: types.SourceDefault,
			Reason: "no rule matched; default-ask mode",
		}
	default: // default-deny
		return types.Decision{
			Effect: types.EffectDeny,
			Source: types.SourceDefault,
			Reason: "no rule matched; default-deny mode",
		}
	}
}

// Phase1KnownModifiers returns the set of modifier names the Phase 1
// engine recognizes. Unknown names cause `validate`/load to fail.
func Phase1KnownModifiers() []string {
	return []string{
		"redact_authorization_header",
		"redact_cookie",
	}
}
