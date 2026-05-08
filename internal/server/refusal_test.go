package server

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// proxyStatusRe is a structural sanity check for the Proxy-Status
// header value. Asserts the intermediary identifier, error token,
// quoted details, and quoted request-id parameter all appear.
var proxyStatusRe = regexp.MustCompile(`^trollbridge; error=[a-z_]+; details="[^"]*"; request-id="[^"]+"$`)

func TestDenyResponse_PlainText_DefaultAccept(t *testing.T) {
	d := types.Decision{
		Effect: types.EffectDeny,
		Source: types.SourceDenyList,
		Reason: "matched deny list: 169.254.169.254",
	}
	hdrs, body, ct := denyResponse(d, "req-123", "")
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("expected text/plain content-type; got %q", ct)
	}
	if hdrs[HeaderRequestID] != "req-123" {
		t.Errorf("missing/wrong request-id header: %q", hdrs[HeaderRequestID])
	}
	want := "deny: matched deny list: 169.254.169.254"
	if hdrs[HeaderReason] != want {
		t.Errorf("Trollbridge-Reason: got %q want %q", hdrs[HeaderReason], want)
	}
	if !proxyStatusRe.MatchString(hdrs[HeaderProxyStatus]) {
		t.Errorf("Proxy-Status format off: %q", hdrs[HeaderProxyStatus])
	}
	if !strings.Contains(string(body), "matched deny list") {
		t.Errorf("plain body missing reason: %q", body)
	}
}

func TestDenyResponse_StarStarFallsBackToPlainText(t *testing.T) {
	d := types.Decision{Effect: types.EffectDeny, Reason: "x"}
	_, _, ct := denyResponse(d, "req-1", "*/*")
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("*/* should not trigger JSON; got %q", ct)
	}
}

func TestDenyResponse_JSONWhenAccepted(t *testing.T) {
	d := types.Decision{
		Effect: types.EffectDeny,
		Source: types.SourceRule,
		RuleID: "deny-cloud-metadata",
		Reason: "matched rule",
	}
	hdrs, body, ct := denyResponse(d, "req-42", "application/json")
	if ct != "application/json" {
		t.Fatalf("expected application/json content-type; got %q", ct)
	}
	var rb refusalBody
	if err := json.Unmarshal(body, &rb); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	if rb.Effect != "deny" || rb.RequestID != "req-42" || rb.RuleID != "deny-cloud-metadata" || rb.Reason != "matched rule" {
		t.Errorf("JSON body fields off: %+v", rb)
	}
	// Headers should still match the plain-text path.
	if hdrs[HeaderRequestID] != "req-42" {
		t.Errorf("request-id header: %q", hdrs[HeaderRequestID])
	}
	// details should include the rule prefix when source=rule.
	if !strings.Contains(hdrs[HeaderProxyStatus], `details="rule deny-cloud-metadata: matched rule"`) {
		t.Errorf("Proxy-Status details should prefix rule id: %q", hdrs[HeaderProxyStatus])
	}
}

func TestDenyResponse_JSONInComplexAccept(t *testing.T) {
	d := types.Decision{Effect: types.EffectDeny, Reason: "x"}
	for _, accept := range []string{
		"application/json",
		"text/html, application/json;q=0.9",
		"application/json; charset=utf-8",
	} {
		_, _, ct := denyResponse(d, "r", accept)
		if ct != "application/json" {
			t.Errorf("Accept=%q should return JSON; got %q", accept, ct)
		}
	}
}

func TestDenyResponse_NoJSONForUnrelatedAccept(t *testing.T) {
	d := types.Decision{Effect: types.EffectDeny, Reason: "x"}
	for _, accept := range []string{
		"text/plain",
		"text/html",
		"application/xml",
		"",
		"garbage//not-a-media-type",
	} {
		_, _, ct := denyResponse(d, "r", accept)
		if ct != "text/plain; charset=utf-8" {
			t.Errorf("Accept=%q should fall back to plain; got %q", accept, ct)
		}
	}
}

func TestProxyStatusToken_Effects(t *testing.T) {
	cases := map[types.Effect]string{
		types.EffectDeny:                "http_request_denied",
		types.EffectAskUserResolvedDeny: "http_request_denied",
		types.EffectAskUserTimedOut:     "proxy_internal_response",
		types.EffectAskUser:             "proxy_internal_response",
		types.EffectAskLLM:              "proxy_internal_response",
	}
	for e, want := range cases {
		if got := proxyStatusToken(e); got != want {
			t.Errorf("effect=%s: got token %q, want %q", e, got, want)
		}
	}
}

func TestProxyStatusDetails_RulePrefixOnlyForRuleSource(t *testing.T) {
	d := types.Decision{Source: types.SourceRule, RuleID: "r1", Reason: "x"}
	if got := proxyStatusDetails(d); got != "rule r1: x" {
		t.Errorf("rule source: got %q", got)
	}
	d2 := types.Decision{Source: types.SourceDenyList, RuleID: "host=foo", Reason: "y"}
	if got := proxyStatusDetails(d2); got != "y" {
		t.Errorf("non-rule source should not prefix: got %q", got)
	}
	d3 := types.Decision{Source: types.SourceRule, RuleID: "", Reason: "z"}
	if got := proxyStatusDetails(d3); got != "z" {
		t.Errorf("empty rule id should not prefix: got %q", got)
	}
}

func TestSFQuotedString_EscapesQuotesAndBackslash(t *testing.T) {
	got := sfQuotedString(`he said "hi" \n`)
	want := `"he said \"hi\" \\n"`
	if got != want {
		t.Errorf("sfQuotedString: got %q want %q", got, want)
	}
}

func TestSFQuotedString_StripsControlAndNonASCII(t *testing.T) {
	got := sfQuotedString("a\x00b\xff")
	if got != `"a?b?"` {
		t.Errorf("expected control + high bytes replaced with '?'; got %q", got)
	}
}

func TestDenyResponse_EmptyRequestIDDefendsWithSentinel(t *testing.T) {
	d := types.Decision{Effect: types.EffectDeny, Reason: "x"}
	hdrs, _, _ := denyResponse(d, "", "")
	if hdrs[HeaderRequestID] != "unknown" {
		t.Errorf("empty req id should fall back to %q; got %q", "unknown", hdrs[HeaderRequestID])
	}
}
