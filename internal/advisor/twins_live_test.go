//go:build twinslive

// twinslive runs only when the build tag is set, e.g.
//
//   go test -tags=twinslive ./internal/advisor/... -run Twins
//
// It exercises HTTPClassifier against the live twins.la endpoints
// (anthropic.twins.la and aoai.twins.la), a deployment-contract
// pass that catches breakage in the wire shape between trollbridge
// and the documented native APIs.
//
// The twins are echo bots — they always reply with synthetic text,
// never invoke tools. So success here is "wire layer verified" —
// the request was syntactically valid (HTTP 200) — and the parser
// correctly classifies the missing tool_use block as a schema
// failure (not a wire failure).
//
// Required environment:
//   ANTHROPIC_TWIN_API_KEY     — minted via /_twin/accounts
//   AOAI_TWIN_API_KEY          — minted via /_twin/resources/.../api_keys
//   AOAI_TWIN_RESOURCE         — the resource_id slug (e.g. r-XXXX)
//   AOAI_TWIN_DEPLOYMENT       — the deployment_id (e.g. chat)
//   AOAI_TWIN_API_VERSION      — Azure api-version (e.g. 2024-10-21)

package advisor

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestTwinsLive_Anthropic_WireOKSchemaFails(t *testing.T) {
	apiKey := os.Getenv("ANTHROPIC_TWIN_API_KEY")
	if apiKey == "" {
		t.Skip("set ANTHROPIC_TWIN_API_KEY")
	}
	tr, _ := TranslatorFor("anthropic", "")
	cli := &HTTPClassifier{
		Endpoint:   "https://anthropic.twins.la/v1/messages",
		APIKey:     apiKey,
		Translator: tr,
		Model:      "claude-3-5-sonnet-latest",
		Client:     &http.Client{Timeout: 10 * time.Second},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := cli.Classify(ctx, Input{
		Method: "GET", Scheme: "https", Host: "example.com", Port: 443, Path: "/",
		Identity: "twinslive", RuleSetVersion: "test",
		Directives: "Be brief.",
	})
	if err == nil {
		t.Fatalf("expected schema error from anthropic twin (echo bot); got nil")
	}
	if errors.Is(err, ErrAdvisorWire) {
		t.Errorf("got wire error against anthropic twin (means request was malformed): %v", err)
	}
	if !errors.Is(err, ErrAdvisorSchema) {
		t.Errorf("expected schema error (twin echoes text, no tool_use); got: %v", err)
	}
}

func TestTwinsLive_AOAI_WireOKSchemaFails(t *testing.T) {
	apiKey := os.Getenv("AOAI_TWIN_API_KEY")
	resource := os.Getenv("AOAI_TWIN_RESOURCE")
	deployment := os.Getenv("AOAI_TWIN_DEPLOYMENT")
	apiVersion := os.Getenv("AOAI_TWIN_API_VERSION")
	if apiKey == "" || resource == "" || deployment == "" || apiVersion == "" {
		t.Skip("set AOAI_TWIN_API_KEY, AOAI_TWIN_RESOURCE, AOAI_TWIN_DEPLOYMENT, AOAI_TWIN_API_VERSION")
	}
	endpoint := "https://aoai.twins.la/" + resource +
		"/openai/deployments/" + deployment +
		"/chat/completions?api-version=" + apiVersion
	tr, _ := TranslatorFor("aoai", "")
	cli := &HTTPClassifier{
		Endpoint:   endpoint,
		APIKey:     apiKey,
		Translator: tr,
		Model:      deployment,
		Client:     &http.Client{Timeout: 10 * time.Second},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := cli.Classify(ctx, Input{
		Method: "GET", Scheme: "https", Host: "example.com", Port: 443, Path: "/",
		Identity: "twinslive", RuleSetVersion: "test",
		Directives: "Be brief.",
	})
	if err == nil {
		t.Fatalf("expected schema error from aoai twin (echo bot); got nil")
	}
	if errors.Is(err, ErrAdvisorWire) {
		t.Errorf("got wire error against aoai twin (means request was malformed): %v", err)
	}
	if !errors.Is(err, ErrAdvisorSchema) {
		t.Errorf("expected schema error (twin echoes text, no tool_calls); got: %v", err)
	}
}
