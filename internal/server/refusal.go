package server

import (
	"encoding/json"
	"fmt"
	"mime"
	"strings"

	"github.com/dandriscoll/trollbridge/internal/types"
)

// HeaderRequestID is the response header carrying the trollbridge
// request id (matches the audit log's `request_id`). Set on every
// response — allow forwarding, deny refusal, CONNECT establishment.
const HeaderRequestID = "Trollbridge-Request-Id"

// HeaderReason is the long-standing custom header on deny / pending
// responses. Per the wire contract (issue #11), the value is the
// CATEGORICAL effect token only ("declined" or "pending"). The
// underlying reason text is in the audit log, keyed by request_id —
// not on the wire.
const HeaderReason = "Trollbridge-Reason"

// HeaderProxyStatus is the standardized RFC 9209 response header.
const HeaderProxyStatus = "Proxy-Status"

// HeaderHoldID surfaces the approvals-queue hold id on the 471
// pending response that fires when approvals.signal_after_seconds
// elapses. Consumer-aware tooling can use it to display the held
// state to a human or correlate with the operator's audit log
// (closes #43).
const HeaderHoldID = "Trollbridge-Hold-Id"

// StatusTrollbridgeDeclined is the wire status code for a request the
// proxy has actively declined (deny effect). 470 is unassigned in the
// IANA HTTP Status Code registry; per RFC 9110 §15 a client that does
// not recognize it falls back to 400-class semantics. The choice is
// deliberate: an agent's HTTP client surfacing "470" cannot confuse
// the response with an upstream 403 for unrelated reasons.
const StatusTrollbridgeDeclined = 470

// StatusTrollbridgePending is the wire status code for a request the
// proxy has held for human or LLM-advisor approval (ask_user / ask_llm
// effects, or their resolved-deny / timed-out variants when surfaced
// before resolution). 471 is unassigned in IANA's registry and pairs
// with 470 as the trollbridge-specific decline / pending pair.
const StatusTrollbridgePending = 471

// refusalBody is the JSON shape returned when the client signaled
// `Accept: application/json` on a declined or pending request. Per
// the wire contract (issue #11), the body MUST NOT carry the reason
// text or the rule id — those live in the audit log only. Operators
// retrieve them via the `request_id`.
type refusalBody struct {
	Effect    string `json:"effect"`
	RequestID string `json:"request_id"`
}

// denyResponse builds the deny-side response shape. Pure: no I/O,
// no mutable state. Returns the headers to set, the body bytes to
// write, and the Content-Type.
//
// Per the wire contract (issue #11), the response carries no reason
// text and no rule id — only categorical effect + request_id, plus
// the RFC 9209 Proxy-Status error token. Operators with audit-log
// access retrieve the reason via the request_id.
func denyResponse(d types.Decision, requestID, accept string) (headers map[string]string, body []byte, contentType string) {
	if requestID == "" {
		requestID = "unknown"
	}
	token := proxyStatusToken(d.Effect)
	category := categoricalEffect(d.Effect)

	headers = map[string]string{
		HeaderRequestID:   requestID,
		HeaderReason:      category,
		HeaderProxyStatus: formatProxyStatus(token, requestID),
	}
	if d.HoldID != "" {
		headers[HeaderHoldID] = d.HoldID
	}

	if acceptsJSON(accept) {
		b, err := json.Marshal(refusalBody{
			Effect:    category,
			RequestID: requestID,
		})
		if err == nil {
			return headers, b, "application/json"
		}
	}
	plain := plainTextBody(category, requestID)
	return headers, []byte(plain), "text/plain; charset=utf-8"
}

// categoricalEffect maps an internal Effect to the wire-side
// categorical token. Two values escape this function: "declined" for
// any deny variant, and "pending" for any ask variant. Reason text
// is intentionally omitted — agents see only what category fired.
func categoricalEffect(e types.Effect) string {
	switch e {
	case types.EffectAskUser, types.EffectAskLLM, types.EffectAskUserSignaled:
		return "pending"
	default:
		return "declined"
	}
}

func plainTextBody(category, requestID string) string {
	return "trollbridge: request " + category + " (request_id=" + requestID + ")"
}

// proxyStatusToken maps a Decision's effect to an RFC 9209 §2.5
// registered error token. http_request_denied for policy-driven
// denials; proxy_internal_response for proxy-generated denials
// (advisor unavailable, approval timeout, ask states that should
// never have reached the refusal path).
func proxyStatusToken(e types.Effect) string {
	switch e {
	case types.EffectAskUserTimedOut, types.EffectAskUser, types.EffectAskLLM, types.EffectAskUserSignaled:
		return "proxy_internal_response"
	default:
		return "http_request_denied"
	}
}

// formatProxyStatus emits an RFC 9209 / RFC 8941 structured-fields
// response header value:
//
//	trollbridge; error=<token>; request-id="<uuid>"
//
// The intermediary identifier (`trollbridge`) is required by the
// spec; `error` is a Token; `request-id` is a quoted string (RFC
// 8941 §3.3.3 escaping: backslash + double-quote). Per the wire
// contract (issue #11), the `details` parameter is intentionally
// omitted — disclosing the reason on the wire is what the contract
// is preventing.
func formatProxyStatus(token, requestID string) string {
	return fmt.Sprintf(
		`trollbridge; error=%s; request-id=%s`,
		token, sfQuotedString(requestID),
	)
}

// sfQuotedString quotes per RFC 8941 §3.3.3: surround with `"`,
// escape `\` → `\\` and `"` → `\"`. Visible-ASCII only; non-ASCII
// is replaced with `?` (the spec forbids it; trollbridge inputs
// are reasons and uuids — should never contain non-ASCII, but we
// defend rather than emit a malformed header).
func sfQuotedString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' || c == '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			b.WriteByte('?')
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// acceptsJSON returns true when the client sent an Accept header
// with a media range that matches `application/json` exactly.
// `*/*` (curl default) and absent header return false — plain text
// remains the default refusal body. Malformed Accept values fall
// back to false (defensive).
func acceptsJSON(accept string) bool {
	if accept == "" {
		return false
	}
	for _, part := range strings.Split(accept, ",") {
		mt, _, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		if mt == "application/json" {
			return true
		}
	}
	return false
}
