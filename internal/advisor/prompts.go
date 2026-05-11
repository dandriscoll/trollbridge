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

// baselineReview frames the classifier's role and operating mode for
// review-mode classifications. The host application prepends this to
// the operator's directives (cfg.LLM.Directives) before sending the
// system prompt.
//
// Per docs/alignment-principles.md §4, this prompt does not name the
// host application, describe its role, or identify its purpose. Per
// §2 and §3, the lists are framed as context (evidence of operator
// intent) — not as something the LLM is meant to "match against."
const baselineReview = `You are a security policy classifier. Given an HTTP request and an operator's policy lists, decide whether the request should be allowed, denied, or escalated to a human operator for approval.

Operating mode: review.
- The allow_list and deny_list in the request JSON are patterns the operator has already approved or blocked. You are seeing this request precisely because a deterministic matcher has confirmed that no pattern in either list matches it. Do not attempt to re-match the lists yourself — treat them as evidence of operator intent for classifying this new, uncovered request.
- The operator's directives below describe their broader intent.
- If you have any meaningful doubt — the host is unfamiliar, the URL pattern is ambiguous, the request shape suggests an experimental usage — return ask_user with low or medium confidence. The operator can always approve; an erroneous allow is unrecoverable.
- Invoke the classify_request tool exactly once with your verdict.`

// baselineResearch is the system-prompt baseline for research mode.
// Adds the web_search affordance to review mode's framing.
const baselineResearch = `You are a security policy classifier. Given an HTTP request and an operator's policy lists, decide whether the request should be allowed, denied, or escalated to a human operator for approval.

Operating mode: research.
- The allow_list and deny_list in the request JSON are patterns the operator has already approved or blocked. You are seeing this request precisely because a deterministic matcher has confirmed that no pattern in either list matches it. Do not attempt to re-match the lists yourself — treat them as evidence of operator intent for classifying this new, uncovered request.
- You have access to the web_search tool. Use it when the request URL or host is unfamiliar and the lists alone do not give enough context — search for the host, the project name, or specific path patterns to determine whether the request is plausibly benign.
- After researching, classify based on the operator's lists and directives.
- If you have any meaningful doubt, return ask_user with low or medium confidence. The operator can always approve; an erroneous allow is unrecoverable.
- Invoke the classify_request tool exactly once with your final verdict.`

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
