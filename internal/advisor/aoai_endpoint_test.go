package advisor

import (
	"strings"
	"testing"
)

func TestNormalizeAOAIEndpoint(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantKind  AOAIEndpointKind
		wantHint  bool
		wantPath  string // canonical URL must contain this path
		wantQuery string // canonical URL must contain this query fragment
	}{
		{
			name:     "empty",
			raw:      "",
			wantKind: AOAIUnknown,
			wantHint: false,
		},
		{
			name:      "responses with version pass-through",
			raw:       "https://r.openai.azure.com/openai/responses?api-version=2025-04-01-preview",
			wantKind:  AOAIResponses,
			wantHint:  false,
			wantPath:  "/openai/responses",
			wantQuery: "api-version=2025-04-01-preview",
		},
		{
			name:      "chat-completions with version pass-through",
			raw:       "https://r.openai.azure.com/openai/deployments/d/chat/completions?api-version=2024-10-21",
			wantKind:  AOAIChatCompletions,
			wantHint:  false,
			wantPath:  "/openai/deployments/d/chat/completions",
			wantQuery: "api-version=2024-10-21",
		},
		{
			name:      "bare resource rewritten to responses",
			raw:       "https://r.openai.azure.com",
			wantKind:  AOAIResponses,
			wantHint:  true,
			wantPath:  "/openai/responses",
			wantQuery: "api-version=" + defaultAOAIAPIVersion,
		},
		{
			name:      "bare openai rewritten to responses",
			raw:       "https://r.openai.azure.com/openai",
			wantKind:  AOAIResponses,
			wantHint:  true,
			wantPath:  "/openai/responses",
			wantQuery: "api-version=" + defaultAOAIAPIVersion,
		},
		{
			name:      "openai-with-trailing-slash rewritten",
			raw:       "https://r.openai.azure.com/openai/",
			wantKind:  AOAIResponses,
			wantHint:  true,
			wantPath:  "/openai/responses",
			wantQuery: "api-version=" + defaultAOAIAPIVersion,
		},
		{
			name:      "responses without version → version added",
			raw:       "https://r.openai.azure.com/openai/responses",
			wantKind:  AOAIResponses,
			wantHint:  true,
			wantPath:  "/openai/responses",
			wantQuery: "api-version=" + defaultAOAIAPIVersion,
		},
		{
			name:      "chat-completions without version → version added",
			raw:       "https://r.openai.azure.com/openai/deployments/d/chat/completions",
			wantKind:  AOAIChatCompletions,
			wantHint:  true,
			wantPath:  "/openai/deployments/d/chat/completions",
			wantQuery: "api-version=" + defaultAOAIAPIVersion,
		},
		{
			name:     "unrelated path → unknown",
			raw:      "https://example.com/some/other/api",
			wantKind: AOAIUnknown,
			wantHint: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canonical, hint, kind := NormalizeAOAIEndpoint(tc.raw)
			if kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", kind, tc.wantKind)
			}
			if (hint != "") != tc.wantHint {
				t.Errorf("hint presence = %v (%q), want %v", hint != "", hint, tc.wantHint)
			}
			if tc.wantPath != "" && !strings.Contains(canonical, tc.wantPath) {
				t.Errorf("canonical %q missing path %q", canonical, tc.wantPath)
			}
			if tc.wantQuery != "" && !strings.Contains(canonical, tc.wantQuery) {
				t.Errorf("canonical %q missing query %q", canonical, tc.wantQuery)
			}
		})
	}
}
