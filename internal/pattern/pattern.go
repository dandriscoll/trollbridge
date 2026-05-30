// Package pattern implements recognition of URL families that have
// predictable structure — most notably Azure Resource Manager URLs
// (/subscriptions/.../resourceGroups/.../providers/...) and Azure
// Key Vault URLs (https://<vault>.vault.azure.net/...).
//
// A Pattern recognizes one URL family and extracts named components
// from it. A Registry holds the active set of patterns; each
// incoming request is fed to Registry.Recognize once, before rule
// evaluation, and the resulting MatchedPattern (if any) is
// decorated onto the RequestEvent.
//
// Patterns are recognition only; they never decide. The rule engine
// references a recognized pattern via the new Match.Pattern /
// Match.Components clauses to write semantic policy ("allow GETs
// in this subscription"). The audit log records the recognized
// pattern and components on every request that fits a known shape,
// even when no pattern-rule matched — so an operator can grep all
// ARM traffic regardless of decision.
//
// Built-in patterns are non-overlapping: a request matches at most
// one. Future overlapping patterns (e.g. AWS sub-services under the
// same host) would need a tie-breaker; the current Recognize
// returns the first match in registration order.
package pattern

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Pattern recognizes one URL family and extracts named components.
// Implementations MUST be pure (no I/O, no side effects); Match
// may be called concurrently from multiple goroutines.
type Pattern interface {
	// Name returns the registry key, e.g. "azure_arm". The name
	// is what operators write in rules and what appears in audit
	// logs. Must be stable for the lifetime of the binary.
	Name() string

	// Components returns the declared component names this pattern
	// extracts. The order is documentation-only; the runtime
	// references components by name. Used at rule-load time to
	// validate Match.Components keys.
	Components() []string

	// Match attempts to recognize the request. Returns
	// (MatchResult, true) if the request is in this pattern's
	// domain; (zero, false) otherwise. When true, every name in
	// Components() MUST be present in the result's map (empty
	// string for "this URL does not carry that component",
	// non-empty otherwise) — callers rely on this to distinguish
	// "absent" from "missing key".
	Match(host string, port int, scheme, path string) (MatchResult, bool)
}

// MatchResult is the per-pattern output of a successful recognition.
type MatchResult struct {
	// Components holds the extracted values, keyed by the names
	// declared in Pattern.Components(). Values are case-preserving
	// (the literal string from the URL).
	Components map[string]string
}

// MatchedPattern is the recognition record decorated onto a
// RequestEvent. The Name is the matched pattern's Name(); the
// Components are a copy of the MatchResult.Components map (so
// downstream code may freely read it without holding the Pattern).
type MatchedPattern struct {
	Name       string
	Components map[string]string
}

// Registry is the active set of patterns. Recognize is safe for
// concurrent use; Register is not (call only during startup).
type Registry struct {
	mu      sync.RWMutex
	byName  map[string]Pattern
	ordered []Pattern // registration order; Recognize returns the first match
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Pattern)}
}

// Register adds a Pattern to the Registry. Returns an error if a
// pattern with the same Name is already registered.
func (r *Registry) Register(p Pattern) error {
	if p == nil {
		return fmt.Errorf("pattern: cannot register nil")
	}
	name := p.Name()
	if name == "" {
		return fmt.Errorf("pattern: cannot register pattern with empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byName[name]; ok {
		return fmt.Errorf("pattern: duplicate registration for %q", name)
	}
	r.byName[name] = p
	r.ordered = append(r.ordered, p)
	return nil
}

// ByName returns the Pattern registered with the given Name, if any.
func (r *Registry) ByName(name string) (Pattern, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byName[name]
	return p, ok
}

// All returns the registered patterns in registration order.
func (r *Registry) All() []Pattern {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Pattern, len(r.ordered))
	copy(out, r.ordered)
	return out
}

// Names returns the registered pattern names, sorted alphabetically
// for stable error messages.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Recognize runs each registered pattern's Match against the
// request and returns the first that succeeds. Returns nil if no
// pattern matches. The returned MatchedPattern's Components map is
// a fresh copy; callers may mutate it without affecting the
// pattern's internal state.
//
// A pattern that panics in Match is logged-and-skipped (defense
// in depth for future custom patterns); the panic does not
// propagate to the caller. Built-in patterns are panic-free by
// audit, but the defense exists so a future pluggable pattern
// cannot crash the daemon.
func (r *Registry) Recognize(host string, port int, scheme, path string) *MatchedPattern {
	r.mu.RLock()
	patterns := r.ordered
	r.mu.RUnlock()
	for _, p := range patterns {
		res, ok := safeMatch(p, host, port, scheme, path)
		if !ok {
			continue
		}
		// Copy the components map so callers can't mutate the
		// pattern's internal state if a future pattern were to
		// return a non-fresh map by accident.
		comps := make(map[string]string, len(res.Components))
		for k, v := range res.Components {
			comps[k] = v
		}
		return &MatchedPattern{Name: p.Name(), Components: comps}
	}
	return nil
}

// safeMatch wraps Pattern.Match in defer/recover. A panic is
// reported via OnPatternPanic (if set) and treated as a non-match.
// Set OnPatternPanic from the server-layer wiring so the panic
// surfaces in the operational log.
func safeMatch(p Pattern, host string, port int, scheme, path string) (res MatchResult, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			if cb := OnPatternPanic; cb != nil {
				cb(p.Name(), r)
			}
			res = MatchResult{}
			ok = false
		}
	}()
	return p.Match(host, port, scheme, path)
}

// OnPatternPanic, if set, is invoked when a Pattern.Match call
// panics. The panic is then swallowed so the request can proceed.
// Set this from the server-layer wiring to route the panic into
// the operational log.
var OnPatternPanic func(patternName string, recovered any)

// ValidateRuleMatch checks that a rule's Match.Pattern names a
// registered pattern and that every component key listed in
// Match.Components is declared by that pattern. The Engine calls
// this at rule load. Returns a descriptive error suitable for
// surfacing to the operator.
//
// Satisfies the policy.PatternValidator interface (declared there
// to avoid a policy → pattern import cycle).
func (r *Registry) ValidateRuleMatch(patternName string, componentKeys []string) error {
	p, ok := r.ByName(patternName)
	if !ok {
		valid := strings.Join(r.Names(), ", ")
		if valid == "" {
			valid = "(none registered)"
		}
		return fmt.Errorf("unknown pattern %q. Valid patterns: %s. Fix: correct the spelling under match.pattern.", patternName, valid)
	}
	declared := make(map[string]bool, len(p.Components()))
	for _, c := range p.Components() {
		declared[c] = true
	}
	for _, k := range componentKeys {
		if !declared[k] {
			valid := strings.Join(p.Components(), ", ")
			return fmt.Errorf("unknown component %q for pattern %s. Valid components: %s. Fix: correct the spelling under match.components.", k, patternName, valid)
		}
	}
	return nil
}

// RecognizeForRequest is a convenience that wraps Recognize and
// returns the result as a types.MatchedPattern (the shape carried
// on RequestEvent). Returns nil if no pattern matched. Keeps the
// pattern→types conversion in one place so server-side callers
// stay terse.
//
// We avoid importing internal/types from pattern (cycle hazard);
// the server-side wiring calls Recognize and constructs the
// types.MatchedPattern itself. See server.go decoration site.

// BuiltIns returns the set of built-in patterns that ship with the
// binary. The daemon registers these at startup. The function
// returns a fresh slice each call so callers can register the
// patterns into a Registry without worrying about shared state.
func BuiltIns() []Pattern {
	return []Pattern{
		AzureARM(),
		AzureKeyVault(),
	}
}
