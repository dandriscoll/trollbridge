package advisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SuggestionInput carries a multi-candidate proposal for the LLM to
// rank and narrate. SIBLING shape of Input — NOT an extension. Per
// docs/alignment-principles.md §1, neither shape includes a list-
// mutation field: the LLM only ranks and narrates among candidates
// the deterministic detector has already produced.
type SuggestionInput struct {
	Candidates []SuggestionCandidate `json:"candidates"`
	AllowList  []string              `json:"allow_list,omitempty"`
	DenyList   []string              `json:"deny_list,omitempty"`
	Directives string                `json:"directives,omitempty"`
	Mode       string                `json:"mode,omitempty"`
}

// SuggestionCandidate names one detector finding the LLM may rank.
type SuggestionCandidate struct {
	Axis             string   `json:"axis"`
	List             string   `json:"list"`
	SourceEntries    []string `json:"source_entries"`
	SuggestedPattern string   `json:"suggested_pattern"`
}

// SuggestionOutput is the validated LLM response. Ranking lists the
// candidates' AXIS names in best-fit order; the server rejects any
// ranking element that names an axis not present in the input.
// Reason is operator-facing (≤200 chars).
type SuggestionOutput struct {
	Ranking    []string `json:"ranking"`
	Reason     string   `json:"reason"`
	Confidence string   `json:"confidence"`
	AdvisorID  string   `json:"advisor_id,omitempty"`
}

// SuggestProvider is the optional interface a Provider may
// implement to participate in the suggestion flow. Providers that
// do NOT implement SuggestProvider trigger the deterministic
// fallback in Service.Suggest — both paths preserve alignment
// principle §1 (the LLM never invents a pattern outside the
// candidate set) and emit the same telemetry envelope.
type SuggestProvider interface {
	Suggest(ctx context.Context, in SuggestionInput) (SuggestionOutput, error)
}

// SuggestInputHash returns the canonical sha256 of the suggestion
// input (sorted candidate axes within each list, sorted source
// entries within each candidate). The hash correlates the
// `suggestion_ask_started` log line with the resulting digest
// entry, mirroring the per-request llm_input_hash from #137.
func SuggestInputHash(in SuggestionInput) string {
	canonical := SuggestionInput{
		AllowList:  append([]string(nil), in.AllowList...),
		DenyList:   append([]string(nil), in.DenyList...),
		Directives: in.Directives,
		Mode:       in.Mode,
	}
	sort.Strings(canonical.AllowList)
	sort.Strings(canonical.DenyList)
	for _, c := range in.Candidates {
		sorted := append([]string(nil), c.SourceEntries...)
		sort.Strings(sorted)
		canonical.Candidates = append(canonical.Candidates, SuggestionCandidate{
			Axis: c.Axis, List: c.List, SourceEntries: sorted,
			SuggestedPattern: c.SuggestedPattern,
		})
	}
	sort.Slice(canonical.Candidates, func(i, j int) bool {
		a, b := canonical.Candidates[i], canonical.Candidates[j]
		if a.List != b.List {
			return a.List < b.List
		}
		if a.Axis != b.Axis {
			return a.Axis < b.Axis
		}
		return strings.Join(a.SourceEntries, "\x00") < strings.Join(b.SourceEntries, "\x00")
	})
	bytes, _ := json.Marshal(canonical)
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

// Suggest ranks and narrates the candidates. When the provider
// implements SuggestProvider, the LLM is consulted; otherwise the
// service falls back to a deterministic priority-order ranking
// with a templated reason. Both paths produce the same
// SuggestionOutput shape so the caller (internal/suggestion) and
// the telemetry envelope are unchanged.
//
// In v1 the trollbridge Anthropic/AOAI translators do NOT
// implement SuggestProvider; deterministic ranking is the
// mainline. Real LLM integration is a follow-up.
//
// Validation guarantees: the returned Ranking lists only axis
// names present in the input candidate set; any LLM response that
// names an unknown axis is rejected (returns ErrAdvisorSchema).
// This is the load-bearing alignment-principle §1 guard: the LLM
// cannot smuggle in a pattern not in the input.
func (s *Service) Suggest(ctx context.Context, in SuggestionInput) (SuggestionOutput, time.Duration, error) {
	start := time.Now()
	if len(in.Candidates) == 0 {
		return SuggestionOutput{}, 0, errors.New("suggest: no candidates")
	}
	in.Mode = s.cfg.Mode
	in.Directives = s.cfg.Directives

	allowedAxes := map[string]bool{}
	for _, c := range in.Candidates {
		allowedAxes[c.Axis] = true
	}

	if sp, ok := s.prov.(SuggestProvider); ok && s.cfg.Enabled {
		ctx2, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
		out, err := sp.Suggest(ctx2, in)
		latency := time.Since(start)
		if err != nil {
			return SuggestionOutput{}, latency, err
		}
		if err := validateSuggestion(out, allowedAxes); err != nil {
			return SuggestionOutput{}, latency, fmt.Errorf("%w: %v", ErrAdvisorSchema, err)
		}
		if out.AdvisorID == "" {
			out.AdvisorID = s.cfg.ModelIdentifier
		}
		return out, latency, nil
	}

	return deterministicSuggest(in), time.Since(start), nil
}

// validateSuggestion enforces alignment-principle §1 at response
// time. The LLM may only rank axes present in the input; novel
// patterns or fabricated axis names are rejected.
func validateSuggestion(out SuggestionOutput, allowedAxes map[string]bool) error {
	if len(out.Ranking) == 0 {
		return errors.New("empty ranking")
	}
	for _, a := range out.Ranking {
		if !allowedAxes[a] {
			return fmt.Errorf("ranking names unknown axis %q (LLM may not invent axes)", a)
		}
	}
	if len(out.Reason) > 400 {
		out.Reason = out.Reason[:400]
	}
	return nil
}

// axisPriority orders axes for deterministic ranking. The chosen
// priority reflects "semantic first, then narrower-wildcard first":
// pattern:* axes (azure_arm, azure_keyvault — #203 follow-up) rank
// ahead of flat axes because the operator wants the semantic
// suggestion offered first. Among flat axes: method (1 position
// widens) → url_segment (one path level) → hostname (whole
// subdomain). The pattern-axis priority is applied via
// axisPriorityFor (handles the dynamic `pattern:<name>` suffix).
var axisPriority = map[string]int{
	"method":             10,
	"url_segment":        20,
	"hostname_below_tld": 30,
}

// axisPriorityFor returns the rank for an axis name, including
// dynamic `pattern:*` axes. Lower ranks sort first. Pattern axes
// rank 1 (highest priority — surfaced first); unknown axes fall
// back to a large value so they sort last deterministically.
func axisPriorityFor(axis string) int {
	if strings.HasPrefix(axis, "pattern:") {
		return 1
	}
	if p, ok := axisPriority[axis]; ok {
		return p
	}
	return 9999
}

func deterministicSuggest(in SuggestionInput) SuggestionOutput {
	ranking := make([]string, 0, len(in.Candidates))
	seen := map[string]bool{}
	for _, c := range in.Candidates {
		if !seen[c.Axis] {
			ranking = append(ranking, c.Axis)
			seen[c.Axis] = true
		}
	}
	sort.SliceStable(ranking, func(i, j int) bool {
		return axisPriorityFor(ranking[i]) < axisPriorityFor(ranking[j])
	})

	// Templated reason — pick the top-ranked candidate and describe
	// its shape. The detector already names what's being unified.
	top := in.Candidates[0]
	for _, c := range in.Candidates {
		if c.Axis == ranking[0] {
			top = c
			break
		}
	}
	reason := buildTemplateReason(top)
	return SuggestionOutput{
		Ranking:    ranking,
		Reason:     reason,
		Confidence: "medium",
		AdvisorID:  "deterministic",
	}
}

func buildTemplateReason(c SuggestionCandidate) string {
	n := len(c.SourceEntries)
	switch {
	case c.Axis == "method":
		return fmt.Sprintf("%d entries differ only in HTTP method; %q would match all.", n, c.SuggestedPattern)
	case c.Axis == "url_segment":
		return fmt.Sprintf("%d entries differ only in their final path segment; %q would match all.", n, c.SuggestedPattern)
	case c.Axis == "hostname_below_tld":
		return fmt.Sprintf("%d entries are subdomains of a common parent; %q would match all.", n, c.SuggestedPattern)
	case strings.HasPrefix(c.Axis, "pattern:"):
		return fmt.Sprintf("%d entries fit %s; rule %q would match the group.", n, strings.TrimPrefix(c.Axis, "pattern:"), c.SuggestedPattern)
	default:
		return fmt.Sprintf("%d entries can be generalized to %q.", n, c.SuggestedPattern)
	}
}
