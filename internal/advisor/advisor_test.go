package advisor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// TestOutput_NoListMutationField pins alignment principle §1
// (docs/alignment-principles.md): the LLM advisor's response shape
// must not include any field that names or implies a list mutation.
// Catches a regression that adds e.g. `suggested_rule` or
// `add_to_allow` back to the response shape.
func TestOutput_NoListMutationField(t *testing.T) {
	forbidden := map[string]bool{
		"suggested_rule": true,
		"add_to_allow":   true,
		"add_to_deny":    true,
		"remove_from_allow": true,
		"remove_from_deny":  true,
	}
	tp := reflect.TypeOf(Output{})
	for i := 0; i < tp.NumField(); i++ {
		f := tp.Field(i)
		jsonTag := strings.SplitN(f.Tag.Get("json"), ",", 2)[0]
		if forbidden[jsonTag] {
			t.Errorf("Output struct exposes list-mutation field %q (alignment principle §1) — the LLM must have no way to suggest list changes", jsonTag)
		}
	}
}

func newReq() *types.RequestEvent {
	return &types.RequestEvent{
		Method: "GET", Scheme: "https-intercepted", Host: "x.com",
		Port: 443, Path: "/foo", IdentityID: "id-1",
	}
}

func TestService_DisabledReturnsAskUser(t *testing.T) {
	s := New(Config{Enabled: false}, nil)
	d, _ := s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	if d.Effect != types.EffectAskUser {
		t.Errorf("disabled: got %s, want ask_user", d.Effect)
	}
}

func TestService_AllowAccepted(t *testing.T) {
	mock := &MockProvider{Output: Output{Effect: "allow", Confidence: "high", Reason: "ok"}}
	s := New(Config{Enabled: true, ConfidenceFloor: "medium"}, mock)
	d, _ := s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	if d.Effect != types.EffectAllow {
		t.Errorf("got %s, want allow", d.Effect)
	}
	if d.Source != types.SourceLLMAdvisor {
		t.Errorf("source: got %s", d.Source)
	}
}

func TestService_LowConfidenceFallsBackToAskUser(t *testing.T) {
	mock := &MockProvider{Output: Output{Effect: "allow", Confidence: "low", Reason: "iffy"}}
	s := New(Config{Enabled: true, ConfidenceFloor: "medium"}, mock)
	d, _ := s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	if d.Effect != types.EffectAskUser {
		t.Errorf("low-confidence: got %s, want ask_user", d.Effect)
	}
}

func TestService_MalformedEffectFallsBack(t *testing.T) {
	mock := &MockProvider{Output: Output{Effect: "blammo", Confidence: "high"}}
	s := New(Config{Enabled: true, ConfidenceFloor: "medium"}, mock)
	d, _ := s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	if d.Effect != types.EffectAskUser {
		t.Errorf("malformed effect: got %s, want ask_user fallback", d.Effect)
	}
}

func TestService_UnknownModifierStripped(t *testing.T) {
	mock := &MockProvider{Output: Output{Effect: "allow", Confidence: "high",
		Modifiers: []string{"redact_authorization_header", "delete_database"}}}
	s := New(Config{
		Enabled: true, ConfidenceFloor: "medium",
		KnownModifiers: map[string]bool{"redact_authorization_header": true},
	}, mock)
	d, _ := s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	if len(d.Modifiers) != 1 || d.Modifiers[0] != "redact_authorization_header" {
		t.Errorf("modifiers: got %v, want [redact_authorization_header]", d.Modifiers)
	}
}

func TestService_AdvisorErrorFallsBackPerOnUnavailable(t *testing.T) {
	mock := &MockProvider{Err: errors.New("boom")}
	s := New(Config{Enabled: true, OnUnavailable: "deny"}, mock)
	d, _ := s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	if d.Effect != types.EffectDeny {
		t.Errorf("on_unavailable=deny: got %s, want deny", d.Effect)
	}
}

func TestService_CachesByRequestShape(t *testing.T) {
	mock := &MockProvider{Output: Output{Effect: "allow", Confidence: "high"}}
	s := New(Config{Enabled: true, ConfidenceFloor: "medium", CacheTTL: time.Minute}, mock)
	for i := 0; i < 5; i++ {
		s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	}
	if mock.Calls != 1 {
		t.Errorf("provider called %d times, want 1 (cached)", mock.Calls)
	}
}

func TestService_CacheKeyIncludesRuleSetVersion(t *testing.T) {
	mock := &MockProvider{Output: Output{Effect: "allow", Confidence: "high"}}
	s := New(Config{Enabled: true, ConfidenceFloor: "medium", CacheTTL: time.Minute}, mock)
	s.Classify(context.Background(), newReq(), "v1", nil, nil, nil)
	s.Classify(context.Background(), newReq(), "v2", nil, nil, nil)
	if mock.Calls != 2 {
		t.Errorf("provider called %d times across distinct rule_set_versions, want 2", mock.Calls)
	}
}

// --------- HTTPClassifier transport tests (provider-aware) ---------

// captureServer records the headers and body of the most recent
// inbound request and replies with whatever JSON body is set.
type captureServer struct {
	*httptest.Server
	lastHeaders http.Header
	lastBody    []byte
	replyBody   []byte
	replyStatus int
}

func newCaptureServer(t *testing.T, replyStatus int, replyBody []byte) *captureServer {
	t.Helper()
	c := &captureServer{replyStatus: replyStatus, replyBody: replyBody}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.lastHeaders = r.Header.Clone()
		c.lastBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(c.replyStatus)
		_, _ = w.Write(c.replyBody)
	}))
	return c
}

func TestHTTPClassifier_AnthropicSendsXAPIKeyAndVersion(t *testing.T) {
	// Reply with a synthetic Anthropic Messages response carrying a
	// tool_use block with the classify_request arguments.
	reply := []byte(`{"type":"message","role":"assistant","stop_reason":"tool_use","content":[{"type":"tool_use","name":"classify_request","input":{"effect":"allow","confidence":"high","reason":"ok"}}]}`)
	srv := newCaptureServer(t, 200, reply)
	defer srv.Close()

	tr, _ := TranslatorFor("anthropic", "")
	cli := &HTTPClassifier{Endpoint: srv.URL, APIKey: "ak-test", Translator: tr, Model: "claude-3-5-sonnet-latest"}
	out, err := cli.Classify(context.Background(),
		Input{Method: "GET", Host: "x.com", Path: "/", Directives: "be careful"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if out.Effect != "allow" || out.Confidence != "high" {
		t.Errorf("decoded Output: got %+v, want effect=allow confidence=high", out)
	}
	if got := srv.lastHeaders.Get("x-api-key"); got != "ak-test" {
		t.Errorf("x-api-key = %q, want ak-test", got)
	}
	if got := srv.lastHeaders.Get("anthropic-version"); got == "" {
		t.Errorf("anthropic-version header missing")
	}
	if got := srv.lastHeaders.Get("Authorization"); got != "" {
		t.Errorf("Authorization header should be empty for anthropic; got %q", got)
	}
	// Request body must include directives (system) and serialized Input.
	if !strings.Contains(string(srv.lastBody), "be careful") {
		t.Errorf("request body missing directives: %s", string(srv.lastBody))
	}
	if !strings.Contains(string(srv.lastBody), `"model":"claude-3-5-sonnet-latest"`) {
		t.Errorf("request body missing model: %s", string(srv.lastBody))
	}
	if !strings.Contains(string(srv.lastBody), `"name":"classify_request"`) {
		t.Errorf("request body missing tool definition: %s", string(srv.lastBody))
	}
}

func TestHTTPClassifier_AOAISendsApiKeyHeader(t *testing.T) {
	reply := []byte(`{"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"classify_request","arguments":"{\"effect\":\"deny\",\"confidence\":\"high\",\"reason\":\"blocked\"}"}}]}}]}`)
	srv := newCaptureServer(t, 200, reply)
	defer srv.Close()

	tr, _ := TranslatorFor("aoai", "")
	cli := &HTTPClassifier{Endpoint: srv.URL, APIKey: "azure-key", Translator: tr, Model: "chat"}
	out, err := cli.Classify(context.Background(),
		Input{Method: "POST", Host: "x.com", Path: "/", Directives: "system msg"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if out.Effect != "deny" || out.Confidence != "high" {
		t.Errorf("decoded Output: got %+v, want effect=deny confidence=high", out)
	}
	if got := srv.lastHeaders.Get("api-key"); got != "azure-key" {
		t.Errorf("api-key header = %q, want azure-key", got)
	}
	if got := srv.lastHeaders.Get("Authorization"); got != "" {
		t.Errorf("Authorization header should be empty for aoai; got %q", got)
	}
	// Verify the system message contains both the trollbridge
	// baseline and the operator's directive (closes #54: composed
	// system prompt).
	var seen aoaiRequest
	if err := json.Unmarshal(srv.lastBody, &seen); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if len(seen.Messages) < 1 || seen.Messages[0].Role != "system" {
		t.Fatalf("request messages[0] not system: %+v", seen.Messages)
	}
	sys := seen.Messages[0].Content
	if !strings.Contains(sys, "system msg") {
		t.Errorf("system message missing operator directive 'system msg'; got %q", sys)
	}
	if !strings.Contains(sys, "Operating mode: review") {
		t.Errorf("system message missing trollbridge mode baseline; got %q", sys)
	}
	if seen.ToolChoice == nil || seen.ToolChoice.Function.Name != toolName {
		t.Errorf("tool_choice did not force classify_request: %+v", seen.ToolChoice)
	}
}

func TestHTTPClassifier_AnthropicWireErrorWrapsErrAdvisorWire(t *testing.T) {
	srv := newCaptureServer(t, 401, []byte(`{"error":{"type":"authentication_error","message":"invalid api key"}}`))
	defer srv.Close()
	tr, _ := TranslatorFor("anthropic", "")
	cli := &HTTPClassifier{Endpoint: srv.URL, APIKey: "bogus", Translator: tr}
	_, err := cli.Classify(context.Background(), Input{Method: "GET", Host: "x", Path: "/"})
	if err == nil {
		t.Fatalf("expected error on 401")
	}
	if !errors.Is(err, ErrAdvisorWire) {
		t.Errorf("error not classified as wire: %v", err)
	}
	if errors.Is(err, ErrAdvisorSchema) {
		t.Errorf("4xx should not classify as schema: %v", err)
	}
}

func TestHTTPClassifier_AOAITextOnlyResponseWrapsErrAdvisorSchema(t *testing.T) {
	// Echo bot: 200 OK but no tool_calls (mirrors the AOAI twin's
	// behavior). Should classify as schema, not wire.
	reply := []byte(`{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"[twin] echoing: ..."}}]}`)
	srv := newCaptureServer(t, 200, reply)
	defer srv.Close()
	tr, _ := TranslatorFor("aoai", "")
	cli := &HTTPClassifier{Endpoint: srv.URL, APIKey: "k", Translator: tr}
	_, err := cli.Classify(context.Background(), Input{Method: "GET", Host: "x", Path: "/"})
	if err == nil {
		t.Fatalf("expected schema error on text-only AOAI response")
	}
	if !errors.Is(err, ErrAdvisorSchema) {
		t.Errorf("error not classified as schema: %v", err)
	}
	if errors.Is(err, ErrAdvisorWire) {
		t.Errorf("200 OK should not classify as wire: %v", err)
	}
}

func TestHTTPClassifier_AnthropicTextOnlyResponseWrapsErrAdvisorSchema(t *testing.T) {
	// Anthropic twin returns text-only; should classify as schema.
	reply := []byte(`{"type":"message","role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":"[twin] echoing"}]}`)
	srv := newCaptureServer(t, 200, reply)
	defer srv.Close()
	tr, _ := TranslatorFor("anthropic", "")
	cli := &HTTPClassifier{Endpoint: srv.URL, APIKey: "k", Translator: tr}
	_, err := cli.Classify(context.Background(), Input{Method: "GET", Host: "x", Path: "/"})
	if err == nil {
		t.Fatalf("expected schema error on text-only anthropic response")
	}
	if !errors.Is(err, ErrAdvisorSchema) {
		t.Errorf("error not classified as schema: %v", err)
	}
}

func TestHTTPClassifier_NoTranslatorErrors(t *testing.T) {
	cli := &HTTPClassifier{Endpoint: "http://example.invalid", APIKey: "k"}
	_, err := cli.Classify(context.Background(), Input{Method: "GET", Host: "x", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "no Translator configured") {
		t.Errorf("expected explicit no-Translator error, got: %v", err)
	}
}

// --------- Translator unit tests (no transport) ---------

func TestAnthropicTranslator_BuildRequestUsesDefaultModelWhenEmpty(t *testing.T) {
	tr := anthropicTranslator{}
	body, hdr, err := tr.BuildRequest(Input{Host: "x", Path: "/"}, "", "k")
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if !strings.Contains(string(body), `"model":"`+AnthropicDefaultModel+`"`) {
		t.Errorf("default model not used: %s", string(body))
	}
	if hdr["x-api-key"] != "k" {
		t.Errorf("x-api-key header = %q", hdr["x-api-key"])
	}
}

func TestAnthropicTranslator_BuildRequestOmitsAuthWhenNoKey(t *testing.T) {
	tr := anthropicTranslator{}
	_, hdr, err := tr.BuildRequest(Input{Host: "x"}, "m", "")
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if _, ok := hdr["x-api-key"]; ok {
		t.Errorf("x-api-key header should be absent when api key is empty")
	}
}

// TestAOAITranslator_BuildRequestEmitsBaselineEvenWhenNoDirectives
// pins #54: the system message is now ALWAYS present (carries the
// trollbridge mode baseline). Pre-#54 it was suppressed when the
// operator's directives field was empty.
func TestAOAITranslator_BuildRequestEmitsBaselineEvenWhenNoDirectives(t *testing.T) {
	tr := aoaiTranslator{}
	body, _, err := tr.BuildRequest(Input{Host: "x", Path: "/"}, "chat", "k")
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	var seen aoaiRequest
	if err := json.Unmarshal(body, &seen); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(seen.Messages) != 2 {
		t.Fatalf("expected system + user messages; got %d: %+v", len(seen.Messages), seen.Messages)
	}
	if seen.Messages[0].Role != "system" || !strings.Contains(seen.Messages[0].Content, "Operating mode: review") {
		t.Errorf("system message missing review baseline; got %+v", seen.Messages[0])
	}
	if seen.Messages[1].Role != "user" {
		t.Errorf("expected user message at [1]; got %+v", seen.Messages[1])
	}
}

func TestTranslatorFor_FallsBackToAnthropic(t *testing.T) {
	tr, ok := TranslatorFor("nonsense", "")
	if ok {
		t.Errorf("expected ok=false for unknown provider")
	}
	if tr.Name() != "anthropic" {
		t.Errorf("expected anthropic fallback; got %s", tr.Name())
	}
}
