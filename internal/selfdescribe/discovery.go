package selfdescribe

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// DiscoveryVersion is the schema version of the protocol discovery
// document. Bumped on breaking changes; additive changes (new keys)
// do not bump.
const DiscoveryVersion = "1"

// DiscoveryPath is the route the discovery handler registers on the
// magic host. The wire-side advertised URL combines `MagicHost` and
// `DiscoveryPath`.
const DiscoveryPath = "/discovery"

// Discovery is the schema of the protocol discovery JSON document
// served at /discovery on the magic host. Closes #95.
type Discovery struct {
	Version          string                  `json:"version"`
	Name             string                  `json:"name"`
	Description      string                  `json:"description"`
	Documentation    DiscoveryDocumentation  `json:"documentation"`
	StatusCodes      []DiscoveryStatusCode   `json:"status_codes"`
	Headers          []DiscoveryHeader       `json:"headers"`
	BodyShapes       DiscoveryBodyShapes     `json:"body_shapes"`
	AuditCorrelation DiscoveryAuditCorrelate `json:"audit_correlation"`
	Examples         []DiscoveryExample      `json:"examples"`
}

type DiscoveryDocumentation struct {
	ProxiedAgentGuide string `json:"proxied_agent_guide"`
	ClientSetupGuide  string `json:"client_setup_guide"`
	SelfDescribeIndex string `json:"self_describe_index"`
	Homepage          string `json:"homepage"`
}

type DiscoveryStatusCode struct {
	Code      int    `json:"code"`
	Name      string `json:"name"`
	Semantics string `json:"semantics"`
	RetrySafe bool   `json:"retry_safe"`
}

type DiscoveryHeader struct {
	Name      string   `json:"name"`
	AppearsOn []string `json:"appears_on"`
	Purpose   string   `json:"purpose"`
}

type DiscoveryBodyShapes struct {
	JSON      DiscoveryBodyJSON  `json:"json"`
	PlainText DiscoveryBodyPlain `json:"plain_text"`
}

type DiscoveryBodyJSON struct {
	ContentType string            `json:"content_type"`
	Selector    string            `json:"selector"`
	Schema      map[string]string `json:"schema"`
}

type DiscoveryBodyPlain struct {
	ContentType string `json:"content_type"`
	Selector    string `json:"selector"`
	Format      string `json:"format"`
}

type DiscoveryAuditCorrelate struct {
	Key         string `json:"key"`
	Description string `json:"description"`
}

type DiscoveryExample struct {
	Label    string `json:"label"`
	Request  string `json:"request"`
	Response string `json:"response"`
}

// BuildDiscovery returns the canonical discovery document. It is a
// pure constructor: same input (none) → same output. Tests assert
// every required field is populated.
func BuildDiscovery() Discovery {
	return Discovery{
		Version:     DiscoveryVersion,
		Name:        "trollbridge",
		Description: "trollbridge is an HTTP/HTTPS forward proxy that intercepts agent traffic and applies operator-configured policy. Some requests may be denied (470) or held for operator approval (471). This document describes the wire contract so agents can interpret responses without out-of-band documentation.",
		Documentation: DiscoveryDocumentation{
			ProxiedAgentGuide: "http://" + MagicHost + "/setup/proxied-agent.md",
			ClientSetupGuide:  "http://" + MagicHost + "/setup/instructions.md",
			SelfDescribeIndex: "http://" + MagicHost + "/setup",
			Homepage:          "https://github.com/dandriscoll/trollbridge",
		},
		StatusCodes: []DiscoveryStatusCode{
			{
				Code:      470,
				Name:      "trollbridge_declined",
				Semantics: "The proxy actively declined the request based on operator policy. The decision is final for this request; do not retry. The full reason text and rule id are in the operator's audit log, keyed by request_id (see audit_correlation).",
				RetrySafe: false,
			},
			{
				Code:      471,
				Name:      "trollbridge_pending",
				Semantics: "The request is held for operator (or LLM-advisor) approval. The agent has been signaled because approvals.signal_after_seconds elapsed; the request continues to be tracked in the approvals queue and may still be approved or denied. Trollbridge-Hold-Id correlates the response with the queued hold.",
				RetrySafe: false,
			},
		},
		Headers: []DiscoveryHeader{
			{
				Name:      "Trollbridge-Request-Id",
				AppearsOn: []string{"all responses"},
				Purpose:   "UUID matching the audit log's request_id field. Operators use this to correlate the on-wire response with the policy decision and reason text in the audit log.",
			},
			{
				Name:      "Trollbridge-Reason",
				AppearsOn: []string{"470", "471"},
				Purpose:   "Categorical effect token: 'declined' or 'pending'. Reason text and rule id are intentionally not on the wire; they live in the audit log only.",
			},
			{
				Name:      "Proxy-Status",
				AppearsOn: []string{"470", "471"},
				Purpose:   "RFC 9209 standardized response header naming the proxy ('trollbridge') and an error token ('http_request_denied' for policy denials, 'proxy_internal_response' for proxy-generated states such as held requests).",
			},
			{
				Name:      "Trollbridge-Hold-Id",
				AppearsOn: []string{"471 (when approvals.signal_after_seconds fires)"},
				Purpose:   "Identifier for the held request in the approvals queue. Operators use this to look up or act on the hold.",
			},
			{
				Name:      "Trollbridge-Discovery",
				AppearsOn: []string{"470", "471"},
				Purpose:   "URL of this protocol discovery document. Agents that ignore the header continue to work unchanged; aware agents fetch it for protocol context.",
			},
		},
		BodyShapes: DiscoveryBodyShapes{
			JSON: DiscoveryBodyJSON{
				ContentType: "application/json",
				Selector:    "Set 'Accept: application/json' on the request.",
				Schema: map[string]string{
					"effect":     "string; 'declined' or 'pending'",
					"request_id": "string; uuid matching the Trollbridge-Request-Id header",
				},
			},
			PlainText: DiscoveryBodyPlain{
				ContentType: "text/plain; charset=utf-8",
				Selector:    "Default when Accept does not include application/json.",
				Format:      "trollbridge: request <effect> (request_id=<uuid>)",
			},
		},
		AuditCorrelation: DiscoveryAuditCorrelate{
			Key:         "request_id",
			Description: "Every wire response carries a request_id; the audit log entry for the same request shares the value. Operators retrieve the policy reason and rule id by looking up the request_id in the audit log. The wire response intentionally omits these details so the proxy does not disclose policy reasoning to potentially-untrusted agents.",
		},
		Examples: []DiscoveryExample{
			{
				Label: "470 declined (plain text body)",
				Request: "GET https://example.com/ HTTP/1.1\n" +
					"Host: example.com\n",
				Response: "HTTP/1.1 470 status code 470\n" +
					"Trollbridge-Request-Id: 5f3e0c8a-4b2d-4f1a-9c8e-1d2b3a4f5e6a\n" +
					"Trollbridge-Reason: declined\n" +
					"Proxy-Status: trollbridge; error=http_request_denied; request-id=\"5f3e0c8a-4b2d-4f1a-9c8e-1d2b3a4f5e6a\"\n" +
					"Trollbridge-Discovery: http://" + MagicHost + DiscoveryPath + "\n" +
					"Content-Type: text/plain; charset=utf-8\n" +
					"\n" +
					"trollbridge: request declined (request_id=5f3e0c8a-4b2d-4f1a-9c8e-1d2b3a4f5e6a)\n",
			},
			{
				Label: "471 pending (JSON body, signaled hold)",
				Request: "GET https://example.com/ HTTP/1.1\n" +
					"Host: example.com\n" +
					"Accept: application/json\n",
				Response: "HTTP/1.1 471 status code 471\n" +
					"Trollbridge-Request-Id: 9b1c4d2e-7f6a-4c3b-8d2e-5f4a3b2c1d0e\n" +
					"Trollbridge-Reason: pending\n" +
					"Proxy-Status: trollbridge; error=proxy_internal_response; request-id=\"9b1c4d2e-7f6a-4c3b-8d2e-5f4a3b2c1d0e\"\n" +
					"Trollbridge-Hold-Id: hold-abc-123\n" +
					"Trollbridge-Discovery: http://" + MagicHost + DiscoveryPath + "\n" +
					"Content-Type: application/json\n" +
					"\n" +
					"{\"effect\":\"pending\",\"request_id\":\"9b1c4d2e-7f6a-4c3b-8d2e-5f4a3b2c1d0e\"}\n",
			},
		},
	}
}

// discoveryJSON is the pre-marshaled discovery document. Marshaled
// once at package init so per-request handler work is a single
// `w.Write(discoveryJSON)`. Init-time panic on marshal failure is
// the right escalation: the schema is hand-written code; if it
// cannot marshal, the build is broken.
var discoveryJSON []byte

func init() {
	d := BuildDiscovery()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("selfdescribe: discovery struct fails JSON marshal: %v", err))
	}
	discoveryJSON = append(b, '\n')
}

// discoveryHandler serves the protocol discovery JSON document at
// /discovery. The route is registered alongside the /setup/* family
// in Handler(); every request receives the pre-marshaled bytes.
func discoveryHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DiscoveryPath {
			notFound(w, r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(discoveryJSON)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(discoveryJSON)
	}
}
