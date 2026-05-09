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
// and quoted request-id parameter all appear. Per the wire contract
// (issue #11), the `details` field MUST NOT appear — its absence is
// asserted separately in TestDenyResponse_NoReasonOnTheWire.
var proxyStatusRe = regexp.MustCompile(`^trollbridge; error=[a-z_]+; request-id="[^"]+"$`)

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
	if hdrs[HeaderReason] != "declined" {
		t.Errorf("Trollbridge-Reason: got %q want %q", hdrs[HeaderReason], "declined")
	}
	if !proxyStatusRe.MatchString(hdrs[HeaderProxyStatus]) {
		t.Errorf("Proxy-Status format off: %q", hdrs[HeaderProxyStatus])
	}
	if want := "trollbridge: request declined (request_id=req-123)"; string(body) != want {
		t.Errorf("plain body: got %q, want %q", body, want)
	}
}

// TestDenyResponse_NoReasonOnTheWire is the contract-level guard for
// issue #11: deny responses must not disclose the reason text on the
// wire, in any field. Audit-log access is the only path to reason.
func TestDenyResponse_NoReasonOnTheWire(t *testing.T) {
	d := types.Decision{
		Effect: types.EffectDeny,
		Source: types.SourceRule,
		RuleID: "deny-cloud-metadata",
		Reason: "matched cloud metadata: 169.254.169.254",
	}
	hdrs, body, _ := denyResponse(d, "req-x", "application/json")
	for _, h := range []string{HeaderRequestID, HeaderReason, HeaderProxyStatus} {
		v := hdrs[h]
		if strings.Contains(v, d.Reason) || strings.Contains(v, "169.254") {
			t.Errorf("header %q leaks reason: %q", h, v)
		}
		if strings.Contains(v, d.RuleID) {
			t.Errorf("header %q leaks rule id: %q", h, v)
		}
		if strings.Contains(v, "details=") {
			t.Errorf("header %q has details= field which is removed by contract: %q", h, v)
		}
	}
	if strings.Contains(string(body), d.Reason) || strings.Contains(string(body), "169.254") {
		t.Errorf("body leaks reason: %s", body)
	}
	if strings.Contains(string(body), d.RuleID) {
		t.Errorf("body leaks rule id: %s", body)
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
	if rb.Effect != "declined" || rb.RequestID != "req-42" {
		t.Errorf("JSON body fields off: %+v", rb)
	}
	if hdrs[HeaderRequestID] != "req-42" {
		t.Errorf("request-id header: %q", hdrs[HeaderRequestID])
	}
}

func TestDenyResponse_PendingEffect_CategoricalToken(t *testing.T) {
	for _, e := range []types.Effect{types.EffectAskUser, types.EffectAskLLM} {
		d := types.Decision{Effect: e, Reason: "needs review"}
		hdrs, body, _ := denyResponse(d, "req-p", "application/json")
		if hdrs[HeaderReason] != "pending" {
			t.Errorf("effect=%s: Trollbridge-Reason got %q want %q", e, hdrs[HeaderReason], "pending")
		}
		var rb refusalBody
		if err := json.Unmarshal(body, &rb); err != nil {
			t.Fatalf("body not JSON: %v", err)
		}
		if rb.Effect != "pending" {
			t.Errorf("effect=%s: body effect got %q want %q", e, rb.Effect, "pending")
		}
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
