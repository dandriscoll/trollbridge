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

// HeaderReason is the long-standing custom header set on deny.
// Preserved alongside Proxy-Status for backwards compatibility.
const HeaderReason = "Trollbridge-Reason"

// HeaderProxyStatus is the standardized RFC 9209 response header.
const HeaderProxyStatus = "Proxy-Status"

// refusalBody is the JSON shape returned when the client signaled
// `Accept: application/json` on a denied request. Keys mirror the
// audit log's field names so an operator who has the response can
// grep the audit log on any of them.
type refusalBody struct {
	Effect    string `json:"effect"`
	Reason    string `json:"reason"`
	RuleID    string `json:"rule_id"`
	RequestID string `json:"request_id"`
}

// denyResponse builds the deny-side response shape. Pure: no I/O,
// no mutable state. Returns the headers to set, the body bytes to
// write, and the Content-Type.
func denyResponse(d types.Decision, requestID, accept string) (headers map[string]string, body []byte, contentType string) {
	if requestID == "" {
		requestID = "unknown"
	}
	token := proxyStatusToken(d.Effect)
	details := proxyStatusDetails(d)

	headers = map[string]string{
		HeaderRequestID:   requestID,
		HeaderReason:      string(d.Effect) + ": " + d.Reason,
		HeaderProxyStatus: formatProxyStatus(token, details, requestID),
	}

	if acceptsJSON(accept) {
		b, err := json.Marshal(refusalBody{
			Effect:    string(d.Effect),
			Reason:    d.Reason,
			RuleID:    d.RuleID,
			RequestID: requestID,
		})
		if err == nil {
			return headers, b, "application/json"
		}
	}
	plain := plainTextBody(d)
	return headers, []byte(plain), "text/plain; charset=utf-8"
}

func plainTextBody(d types.Decision) string {
	switch d.Effect {
	case types.EffectAskUser, types.EffectAskLLM:
		return "trollbridge: request requires approval"
	default:
		return "trollbridge: request denied: " + d.Reason
	}
}

// proxyStatusToken maps a Decision's effect to an RFC 9209 §2.5
// registered error token. http_request_denied for policy-driven
// denials; proxy_internal_response for proxy-generated denials
// (advisor unavailable, approval timeout, ask states that should
// never have reached the refusal path).
func proxyStatusToken(e types.Effect) string {
	switch e {
	case types.EffectAskUserTimedOut, types.EffectAskUser, types.EffectAskLLM:
		return "proxy_internal_response"
	default:
		return "http_request_denied"
	}
}

// proxyStatusDetails composes the human-readable details string.
// When a structured rule fired, the rule id is prefixed so
// operators can correlate without consulting the audit log first.
func proxyStatusDetails(d types.Decision) string {
	if d.RuleID != "" && d.Source == types.SourceRule {
		return "rule " + d.RuleID + ": " + d.Reason
	}
	return d.Reason
}

// formatProxyStatus emits an RFC 9209 / RFC 8941 structured-fields
// response header value:
//
//	trollbridge; error=<token>; details="<escaped>"; request-id="<uuid>"
//
// The intermediary identifier (`trollbridge`) is required by the
// spec; `error` is a Token; `details` and `request-id` are quoted
// strings (RFC 8941 §3.3.3 escaping: backslash + double-quote).
func formatProxyStatus(token, details, requestID string) string {
	return fmt.Sprintf(
		`trollbridge; error=%s; details=%s; request-id=%s`,
		token, sfQuotedString(details), sfQuotedString(requestID),
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
