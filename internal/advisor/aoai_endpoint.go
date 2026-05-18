package advisor

import (
	"net/url"
	"strings"
)

// AOAIEndpointKind classifies an Azure OpenAI URL into one of the
// shapes trollbridge supports.
type AOAIEndpointKind int

const (
	// AOAIUnknown — the URL is not recognizably an Azure OpenAI
	// endpoint (e.g. wrong host, unparseable). Translator selection
	// proceeds with the chat-completions default.
	AOAIUnknown AOAIEndpointKind = iota
	// AOAIChatCompletions — URL ends in /openai/deployments/<dep>/chat/completions.
	AOAIChatCompletions
	// AOAIResponses — URL ends in /openai/responses.
	AOAIResponses
)

// defaultAOAIAPIVersion is appended when the operator's pasted URL
// lacks one. We pick a Responses API version that is currently
// stable; operators who want a different version set it explicitly.
const defaultAOAIAPIVersion = "2025-04-01-preview"

// NormalizeAOAIEndpoint accepts the variety of URL shapes an
// operator may paste from the Azure portal and returns:
//
//   - the canonical URL trollbridge will actually POST to,
//   - a non-empty hint string when the URL was rewritten or amended
//     (so the caller can surface a warning to the operator),
//   - the kind of endpoint chosen.
//
// Recognized inputs:
//
//   - https://<resource>.openai.azure.com/openai/responses?api-version=…
//     → returned as-is, kind=AOAIResponses.
//   - https://<resource>.openai.azure.com/openai/deployments/<dep>/chat/completions?api-version=…
//     → returned as-is, kind=AOAIChatCompletions.
//   - https://<resource>.openai.azure.com or .../openai or .../openai/
//     → rewritten to .../openai/responses?api-version=<default>,
//       kind=AOAIResponses, hint set.
//   - URL with /openai/responses but no api-version → api-version
//     appended, hint set.
//   - URL with /openai/deployments/.../chat/completions but no
//     api-version → api-version appended, hint set.
//
// Anything else is left alone with kind=AOAIUnknown.
func NormalizeAOAIEndpoint(raw string) (canonical, hint string, kind AOAIEndpointKind) {
	if raw == "" {
		return raw, "", AOAIUnknown
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw, "", AOAIUnknown
	}
	path := strings.TrimRight(u.Path, "/")

	switch {
	case strings.Contains(path, "/openai/responses"):
		kind = AOAIResponses
	case strings.Contains(path, "/openai/deployments/") && strings.HasSuffix(path, "/chat/completions"):
		kind = AOAIChatCompletions
	case path == "" || path == "/openai" || strings.HasSuffix(path, "/openai"):
		// Bare resource or .../openai — assume Responses (modern).
		u.Path = strings.TrimSuffix(path, "/openai") + "/openai/responses"
		kind = AOAIResponses
	default:
		// Unknown path — leave alone but report unknown.
		return raw, "", AOAIUnknown
	}

	// Ensure api-version is present.
	q := u.Query()
	addedVersion := false
	if q.Get("api-version") == "" {
		q.Set("api-version", defaultAOAIAPIVersion)
		u.RawQuery = q.Encode()
		addedVersion = true
	}

	canonical = u.String()
	if canonical != raw {
		switch {
		case addedVersion && kind == AOAIResponses && !strings.Contains(raw, "/openai/responses"):
			hint = "AOAI endpoint rewritten to canonical Responses API form `" + canonical + "` (modern API). Set llm.endpoint explicitly to this value to silence this hint."
		case addedVersion:
			hint = "AOAI endpoint had no api-version; appended `api-version=" + defaultAOAIAPIVersion + "`. Set llm.endpoint explicitly to silence this hint."
		default:
			hint = "AOAI endpoint normalized to `" + canonical + "`."
		}
	}
	return canonical, hint, kind
}

// AOAIDeploymentFromURL returns the deployment name embedded in an
// AOAI chat-completions URL, e.g. "gpt-4o-mini" for
// `https://<resource>.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions`.
// Returns "" when the URL has no deployment segment (Responses API,
// bare resource, malformed input). Used by the advisor's log lines
// to attribute requests to a deployment when an operator runs
// multiple deployments (#157).
func AOAIDeploymentFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	const marker = "/openai/deployments/"
	i := strings.Index(u.Path, marker)
	if i < 0 {
		return ""
	}
	rest := u.Path[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}
