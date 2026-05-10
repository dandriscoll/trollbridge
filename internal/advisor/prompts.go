package advisor

import "strings"

// Mode constants name the advisor's operating shape (closes #54).
// review  — classify against the operator's allow/deny lists.
// research — same, plus the LLM may invoke a web search tool for URL
//           context. Anthropic-only; AOAI deployments fall back to
//           review with a startup warning.
const (
	ModeReview   = "review"
	ModeResearch = "research"
)

// baselineReview frames the advisor's role and operating mode for
// review-mode classifications. trollbridge prepends this to the
// operator's directives (cfg.LLM.Directives) before sending the
// system prompt — so operating function is trollbridge-controlled,
// while operator intent remains the operator's.
const baselineReview = `You are a security policy advisor for trollbridge, an HTTP/HTTPS proxy that gates an AI agent's network egress.

Operating mode: review.
- The operator's allow_list and deny_list (in the request JSON) represent their stated intent for the agent.
- Treat those lists as authoritative when the request matches their patterns.
- When the lists do not decisively cover the request, classify based on the operator's directives below.
- Invoke the trollbridge_decision tool exactly once with your verdict.`

// baselineResearch is the system-prompt baseline for research mode.
// Adds the web_search affordance to review mode's framing.
const baselineResearch = `You are a security policy advisor for trollbridge, an HTTP/HTTPS proxy that gates an AI agent's network egress.

Operating mode: research.
- The operator's allow_list and deny_list (in the request JSON) represent their stated intent for the agent.
- You have access to the web_search tool. Use it when the request URL or host is unfamiliar and the lists alone do not give enough context — search for the host, the project name, or specific path patterns to determine whether the request is plausibly benign.
- After researching, classify against the operator's lists and directives.
- Invoke the trollbridge_decision tool exactly once with your final verdict.`

// composeSystemPrompt builds the system-prompt content sent to the
// LLM: the trollbridge mode-baseline first, then the operator's
// directives (if any) separated by a blank line. Empty directives are
// permitted — operators may rely entirely on the baseline.
func composeSystemPrompt(mode, directives string) string {
	base := baselineReview
	if mode == ModeResearch {
		base = baselineResearch
	}
	directives = strings.TrimSpace(directives)
	if directives == "" {
		return base
	}
	return base + "\n\n" + directives
}
