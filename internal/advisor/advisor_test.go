package advisor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dandriscoll/trollbridge/internal/types"
)

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

func TestHTTPClassifier_BearerAuthByDefault(t *testing.T) {
	srv := newAuthCaptureServer(t)
	defer srv.Close()
	cli := &HTTPClassifier{Endpoint: srv.URL, APIKey: "abc123"}
	if _, err := cli.Classify(context.Background(), Input{Method: "GET", Host: "h", Port: 80, Path: "/"}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got := srv.lastAuth; got != "Bearer abc123" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer abc123")
	}
	if got := srv.lastAPIKey; got != "" {
		t.Errorf("api-key header should be empty for Bearer scheme; got %q", got)
	}
}

func TestHTTPClassifier_AzureAPIKeySetsApiKeyHeaderNotBearer(t *testing.T) {
	srv := newAuthCaptureServer(t)
	defer srv.Close()
	cli := &HTTPClassifier{Endpoint: srv.URL, APIKey: "azure-key", AuthScheme: AuthAzureAPIKey}
	if _, err := cli.Classify(context.Background(), Input{Method: "GET", Host: "h", Port: 80, Path: "/"}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got := srv.lastAPIKey; got != "azure-key" {
		t.Errorf("api-key header = %q, want azure-key", got)
	}
	if got := srv.lastAuth; got != "" {
		t.Errorf("Authorization header should be empty for AOAI; got %q", got)
	}
}
