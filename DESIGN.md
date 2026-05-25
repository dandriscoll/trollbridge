# trollbridge — Design Document

**Version:** 1 (draft, pre-implementation)
**Status:** Specification only. No code has been written yet. The
implementation plan in §18 stages the work.

trollbridge is an HTTP/HTTPS proxy that LLM agents route their network
traffic through, so that the agent's network access is **policy-
governed**, **inspectable**, and **auditable**. A deterministic policy
engine is the authoritative decision boundary; an optional LLM advisor
classifies and recommends, but never elevates a decision the
deterministic engine has not authorized.

This document uses RFC 2119 keywords (MUST, MUST NOT, SHOULD, SHOULD
NOT, MAY).

---

## Table of contents

 1. [Purpose and scope](#1-purpose-and-scope)
 2. [Threat model](#2-threat-model)
 3. [Primary user stories](#3-primary-user-stories)
 4. [System architecture](#4-system-architecture)
 5. [HTTP proxy behavior](#5-http-proxy-behavior)
 6. [HTTPS proxy behavior](#6-https-proxy-behavior)
 7. [TLS interception design](#7-tls-interception-design)
 8. [Policy model](#8-policy-model)
 9. [LLM decision model](#9-llm-decision-model)
10. [Deterministic rule engine](#10-deterministic-rule-engine)
11. [Request/response inspection pipeline](#11-requestresponse-inspection-pipeline)
12. [Allowlist and denylist behavior](#12-allowlist-and-denylist-behavior)
13. [CLI and configuration design](#13-cli-and-configuration-design)
14. [Deployment topologies](#14-deployment-topologies)
15. [Logging and audit trail](#15-logging-and-audit-trail)
16. [Failure modes](#16-failure-modes)
17. [Security boundaries](#17-security-boundaries)
18. [Implementation plan](#18-implementation-plan)
19. [Test plan](#19-test-plan)
20. [Open questions and design tradeoffs](#20-open-questions-and-design-tradeoffs)

---

## 1. Purpose and scope

trollbridge exists to make LLM-agent network access **safe by
construction**. Existing safety mechanisms — sandboxing, MCP tool
allow-lists, container egress firewalls — are necessary but not
sufficient: they either over-constrain (no network at all) or under-
constrain (blanket allow to a domain) the agent's actual needs.

trollbridge solves this by intermediating *every* HTTP and HTTPS request
the agent makes, so each request can be classified, allowed, denied,
modified, or held for human approval, with a record sufficient for
later review.

### 1.1 In scope

- HTTP forward-proxy support.
- HTTPS proxy support via the `CONNECT` method.
- Optional TLS interception with a locally-generated CA.
- A deterministic, file-defined policy engine.
- An optional LLM advisor that classifies and recommends decisions for
  unmatched requests.
- Structured audit logs.
- A CLI for operators.
- Recipes for local, container, and Incus-VM deployments.

### 1.2 Out of scope

- DNS proxying. trollbridge MAY observe `Host:` headers and `CONNECT`
  hostnames, but it does not act as a DNS resolver for clients.
- Raw-TCP / non-HTTP proxying. SOCKS support MAY be added later but is
  not in scope here.
- A multi-tenant shared service. trollbridge is designed to run **per
  agent VM** or **per agent fleet under one operator**, not as a SaaS.
- Any form of agent autonomy that lets the agent itself author or
  approve rules. Rule authorship is an operator-only operation.
- Provisioning agent runtime environments (Incus, Docker, etc.). The
  deployment topologies in §14 reference these but do not provision
  them.

### 1.3 Non-goals

- trollbridge is **not** an enforcement boundary by itself. Network
  isolation (firewall, Incus profile) MUST also exist, or the agent
  can simply bypass the proxy. §17 names this explicitly.
- trollbridge does **not** prevent malicious behavior conducted via
  *allowed* destinations and *allowed* request shapes. An agent that
  is allowed to reach `api.github.com` and make `GET` requests can
  exfiltrate via crafted query strings. Operators MUST scope rules
  narrowly to mitigate.

---

## 2. Threat model

### 2.1 Actors

- **Operator.** Trusted. Configures trollbridge, writes rules, reviews
  audit logs, approves held requests.
- **Agent.** Semi-trusted at best. May be a benign coding agent, may
  be a coding agent under prompt injection, may be a deliberately
  hostile agent under adversarial control. trollbridge MUST treat the
  agent as if it could attempt exfiltration or unauthorized access.
- **Origin server.** Untrusted. May serve malicious content, may
  attempt to fingerprint, may attempt to probe the proxy.
- **LLM provider.** Trusted for *decisioning* but not for *secrets*.
  trollbridge MUST NOT forward credentials, tokens, or full request
  bodies to the LLM unless the operator explicitly opts in per-rule.

### 2.2 What trollbridge is designed to defend against

- An agent attempting to reach a destination the operator has not
  allowed (host, port, URL, method).
- An agent attempting to send credentials, tokens, or PII to a
  destination that does not need them (redaction or scope-narrowing
  rules).
- An agent following a prompt-injection-induced URL fetch to an
  attacker-controlled origin.
- An agent making a high-stakes mutating call (DELETE, POST to a
  payments endpoint) without operator review.
- Long-running silent abuse: every request is audit-logged, so
  operator review can detect drift.

### 2.3 What trollbridge is NOT designed to defend against

These limitations MUST be documented to operators; the proxy alone is
not sufficient.

- **Direct network access that does not route through the proxy.**
  The agent VM MUST be firewalled so that egress to anywhere except
  trollbridge is dropped. Without this, the proxy is decorative.
- **DNS exfiltration.** If the agent can resolve arbitrary hostnames,
  it can encode data in DNS queries. The agent VM SHOULD use a
  controlled resolver.
- **Raw socket traffic** (non-HTTP TCP/UDP). trollbridge is HTTP-only.
  Other protocols MUST be blocked at the firewall.
- **Alternate proxies.** If the agent can choose its own proxy or
  bypass `HTTP_PROXY`, trollbridge does not see the request. The
  firewall must be the binding constraint, not the env var.
- **Encrypted payloads inside allowed HTTPS requests.** Even with TLS
  interception, an agent can base64 a payload inside an allowed JSON
  field. trollbridge MAY apply body-shape rules, but cannot
  semantically detect arbitrary encodings.
- **Malicious use of allowed destinations.** An agent allowed to write
  to `api.example.com` can write the wrong thing. trollbridge enforces
  *who* and *where*, not *what should be true* about the call.
- **Side channels via response timing or proxy errors.** A
  determined attacker can encode data into the *fact* of a request
  being made, regardless of body content. Operators concerned about
  this class need additional controls.
- **HTTP/3 / QUIC.** trollbridge is HTTP/1.1- and HTTP/2-aware over
  TCP. HTTP/3 runs over UDP; if egress UDP is permitted, an origin
  serving `Alt-Svc: h3=...` can negotiate the client off TCP and
  trollbridge sees no further traffic. Mitigation: the agent's
  firewall MUST drop egress UDP except for whatever resolver path
  the operator allows. trollbridge cannot help if the network does
  not constrain UDP.
- **Compromise of the operator's machine.** trollbridge runs on the
  operator's host or trusted machine. If that host is compromised, so
  is trollbridge. The CA private key in particular MUST be protected
  by host-level controls.

---

## 3. Primary user stories

### 3.1 Coding agent in an Incus VM

A developer runs Claude Code inside an Incus VM. The VM is firewalled:
the only outbound destination it can reach is the host-side trollbridge
on `192.168.x.y:8080`. The VM has the trollbridge CA installed in its
trust store. Inside the VM, the agent's environment exposes
`HTTPS_PROXY=http://192.168.x.y:8080`.

The agent runs `npm install`. trollbridge sees the CONNECT to
`registry.npmjs.org:443`, matches an `allow` rule for that host, and
forwards. The agent then attempts to fetch a URL it discovered from a
README: `https://attacker.example/payload.sh`. trollbridge has no rule
for `attacker.example`, the default mode is `ask`, the LLM advisor
classifies the request as a probable malicious payload fetch, and
trollbridge holds it pending operator approval. The operator sees the
held request via `trollbridge decisions --pending` and denies it.

### 3.2 Local development on a single host

A developer runs Codex CLI on their workstation. They run trollbridge as a
user-level daemon on `127.0.0.1:8080`, set `HTTPS_PROXY` in their
shell, and install the CA into their user trust store. trollbridge is
configured in `default-allow-with-audit` mode for trusted dev hosts
(e.g., `*.github.com`, `pypi.org`) and `default-ask` for everything
else. The audit log accumulates a record of every fetch.

### 3.3 Automation agent in a CI runner

A CI job runs a deployment agent. trollbridge runs as a sidecar
container alongside the agent, configured `default-deny` with an
explicit allowlist for the deployment targets (`api.cloudprovider.com/v1/...`,
specific paths only). The agent cannot make any other network call.
Audit log artifacts are uploaded with the build for later review.

### 3.4 Auditor reviewing past behavior

A reviewer wants to know whether an agent ever sent customer data
outside the organization. They run `trollbridge logs replay --rules
new-strict-rules.yaml` against last week's audit log; trollbridge
replays each decision against the new rules and reports which past
requests *would have been denied* under the stricter policy.

---

## 4. System architecture

trollbridge is a single Go binary. It is composed of seven internal
components, each with one responsibility.

```
                    ┌────────────────────────────────────────────────────┐
                    │                    trollbridge                      │
                    │                                                    │
   ┌──────┐         │  ┌──────────┐    ┌────────────────────────────┐    │   ┌────────┐
   │client│ ──TCP──▶│  │ Listener │───▶│ Dispatcher (CONNECT/HTTP)  │───▶│   │ origin │
   │ (LLM │         │  └──────────┘    └────────────────────────────┘    │──▶│ server │
   │agent)│         │                            │                       │   └────────┘
   └──────┘         │                            ▼                       │
                    │                  ┌────────────────────┐            │
                    │                  │  Policy engine     │            │
                    │                  │  (deterministic)   │            │
                    │                  └────────────────────┘            │
                    │                            │                       │
                    │                            ▼                       │
                    │             ┌──────────────────────────┐           │
                    │             │ LLM advisor (optional)   │──────────────▶ LLM provider
                    │             └──────────────────────────┘           │
                    │                            │                       │
                    │                            ▼                       │
                    │                  ┌────────────────────┐            │
                    │                  │  Approval queue    │            │
                    │                  └────────────────────┘            │
                    │                            │                       │
                    │                            ▼                       │
                    │                  ┌────────────────────┐            │
                    │                  │  Forwarder         │            │
                    │                  └────────────────────┘            │
                    │                            │                       │
                    │                            ▼                       │
                    │                  ┌────────────────────┐            │
                    │                  │  Audit logger      │──────────────▶ JSONL on disk
                    │                  │  (async buffered)  │            │
                    │                  └────────────────────┘            │
                    │                                                    │
                    │  ┌────────────┐                                    │
                    │  │ CA manager │   (signs leaf certs on demand      │
                    │  └────────────┘    when interception is enabled)   │
                    └────────────────────────────────────────────────────┘
```

**Listener** owns the TCP socket. Inputs: incoming connections.
Outputs: accepted connections handed to the dispatcher.

**Dispatcher** owns request shape. Inputs: a TCP connection from the
listener. Outputs: a normalized `RequestEvent` and a transport handle.
Distinguishes between plain HTTP, CONNECT, and (in interception mode)
TLS-terminated HTTPS.

**Policy engine** owns decisions. Inputs: a `RequestEvent`. Outputs: a
`Decision` (allow / deny / ask_user / ask_llm + metadata). MUST be
deterministic; same input MUST produce same output for a given rule
set version.

**LLM advisor** owns LLM round-trips. Inputs: a redacted
`RequestEvent` plus the rule set's advisor schema. Outputs: a
structured `Decision` candidate, validated against the schema, OR
"advisor unavailable." Never directly authoritative.

**Approval queue** owns held requests. Inputs: `RequestEvent` flagged
ASK_USER. Outputs: a hold ID returned to the dispatcher (which holds
the client connection open or returns 471 — Trollbridge pending —
with retry information, per config). Approvals/denials arrive via the
CLI or HTTP control API and are matched to held requests by hold ID.

**Forwarder** owns the upstream call. Inputs: a `RequestEvent` plus
an `allow` `Decision`. Outputs: the upstream response back to the
client.

**Audit logger** owns the immutable record stream. Inputs: a finalized
`Decision` plus surrounding context (request metadata, response
status, redaction summary). Outputs: a JSONL line on disk. Async
buffered; bounded.

**CA manager** owns the local CA when interception is enabled. Inputs:
a `host:port` for which a leaf cert is needed. Outputs: a signed leaf
cert, cached per host with a configurable TTL.

### 4.1 Data shapes (informative)

```go
type RequestEvent struct {
    ID             string
    SessionID      string
    IdentityID     string
    Timestamp      time.Time
    Method         string   // "CONNECT" / "GET" / "POST" / ...
    Scheme         string   // "http" / "https" / "https-intercepted"
    Host           string
    Port           int
    Path           string   // "" if CONNECT and not intercepted
    Headers        map[string][]string
    BodyAvailable  bool
    BodySize       int64
    BodySample     []byte   // up to MaxBodySample bytes; redacted
}

type Decision struct {
    Effect      string   // "allow" | "deny" | "ask_user" | "ask_llm"
    Source      string   // "rule" | "default" | "llm_advisor" | "approval_queue"
    RuleID      string   // "" if not from a rule
    AdvisorID   string   // "" if not from the LLM
    Reason      string   // human-readable explanation
    Scope       string   // "once" | "session" | "rule"
    Modifiers   []string // e.g., ["redact_authorization_header"]
    Expires     time.Time
}
```

---

## 5. HTTP proxy behavior

### 5.1 Plain HTTP requests

For a plain HTTP request (`GET http://example.com/path HTTP/1.1`),
trollbridge:

1. MUST parse the request line and absolute-form URI as defined in
   RFC 7230 §5.3.2.
2. MUST classify the client identity per §8.4.
3. MUST evaluate the policy engine against the request.
4. MUST audit-log the decision.
5. If `allow`, MUST forward the request to the origin and stream the
   response back to the client. Streaming MUST NOT buffer the entire
   response body before forwarding (this would break SSE and large
   downloads).
6. If `deny`, MUST return `470` with the refusal-response headers and
   body specified in §5.6.
7. If `ask_user`, MUST hold the request as defined in §8.5 (and, when
   the dispatcher returns instead of holding, MUST emit `471`).

### 5.2 Headers added or modified

trollbridge MUST add `Via: 1.1 trollbridge` per RFC 7230 §5.7.1 to
forwarded requests and responses.

trollbridge MUST strip `Proxy-Authorization` and `Proxy-Connection`
headers before forwarding.

trollbridge MUST add a `Trollbridge-Request-Id: <uuid>` header to
every response it sends — allow forwarding (HTTP and intercepted
HTTPS), deny refusal, CONNECT 200 establishment. The value matches
the `request_id` field in the audit log entry for the same request,
allowing an operator handed a request id by a client to look it up
in the audit log directly.

trollbridge MAY add a `Trollbridge-Decision-Id: <uuid>` header to
forwarded requests so the origin's logs can be correlated with
trollbridge's audit log.

trollbridge MUST NOT add any header that contains operator-private
information (CA fingerprint, rule names, identity IDs) to outbound
requests by default.

### 5.3 Methods

trollbridge MUST support all standard HTTP methods (GET, HEAD, POST,
PUT, PATCH, DELETE, OPTIONS, CONNECT). Custom methods MAY be allowed
or denied via rules.

### 5.4 Redirects

trollbridge MUST NOT follow redirects on behalf of the client. A 3xx
response MUST be forwarded as-is; the client follows the redirect,
which produces a new request that is re-evaluated independently.

### 5.5 Connection management

trollbridge MUST support HTTP/1.1 keep-alive on the client-facing side.
trollbridge MAY pool connections to upstream origins. Connection pools
MUST be keyed by `(scheme, host, port, identity)` so two identities
do not share an authenticated upstream connection.

### 5.6 Deny response shape

A request that the proxy actively declines or holds for approval MUST
receive the following response shape, on every refusal path (plain
HTTP, CONNECT pre-tunnel, and intercepted HTTPS):

- **Status.** `470` for declined requests, `471` for requests held
  for approval. Both codes are unassigned in the IANA HTTP Status
  Code registry; per RFC 9110 §15 a client that does not recognize
  them falls back to 400-class semantics. The choice is deliberate:
  these codes do not collide with any common upstream code, so a
  caller — even one whose HTTP library hides the response shape —
  can infer that the proxy itself produced the response, not the
  upstream service. Trollbridge does not emit `403 Forbidden` or
  `511 Network Authentication Required` for any policy outcome.
- **`Trollbridge-Request-Id`** header: the request's uuid (same as
  §5.2; required on every response, not just refusal).
- **`Proxy-Status`** header per RFC 9209:
  `trollbridge; error=<token>; request-id="<uuid>"`.
  - `error` is `http_request_denied` for policy-driven denials (rule
    deny, default-deny, inline-list deny, advisor deny, resolved
    deny). `error` is `proxy_internal_response` for proxy-generated
    states (advisor-unavailable fallback, approval timeout, ask
    states).
  - The `details=` parameter is intentionally **not** included.
    Operators retrieve the reason and rule id from the audit log by
    `request_id`. Disclosing reason on the wire would let a caller
    enumerate policy structure.
- **`Trollbridge-Reason`** header: the categorical effect token —
  `declined` or `pending` — and nothing else. Reason text is in the
  audit log only.
- **`Trollbridge-Discovery`** header: the URL of the protocol
  discovery JSON document
  (`http://config.trollbridge.dev/discovery`). Set on every 470 /
  471 response so an agent that has only the proxy address can
  fetch a machine-readable description of the wire contract from a
  deterministic, well-known URL. The document enumerates status
  codes, headers, body shapes, and the audit-log correlation rule.
  See [`docs/self-describing.md`](docs/self-describing.md) for the
  operator-facing summary of the discovery endpoints.
- **Body, content-negotiated:**
  - When the request `Accept` header contains a media range matching
    `application/json` (other than `*/*`), the body is
    `Content-Type: application/json` with shape
    `{"effect", "request_id"}`. `effect` is the categorical token
    (`declined` or `pending`); `request_id` matches the header. The
    body MUST NOT carry the reason or rule id — those live in the
    audit log only.
  - Otherwise the body is `Content-Type: text/plain; charset=utf-8`
    with the human-readable refusal text
    `trollbridge: request <effect> (request_id=<uuid>)`. This is the
    default for `Accept: */*`, missing `Accept`, and any non-JSON
    `Accept`.

A declined CONNECT MUST additionally set `Connection: close` so the
proxy connection terminates cleanly; clients that intend to retry
must open a new connection.

The same `request_id` value MUST appear in the response header, the
audit log entry, and (on the operational log) the contextual
`request_id` slog field.

A denied response over a CONNECT tunnel that has already been
established (i.e., intercepted HTTPS) follows the same shape as
plain HTTP. A denied CONNECT before tunnel establishment carries
the headers but most HTTP client libraries discard the response on
tunnel failure — operators must use the audit log for diagnosis.

Pool size MUST be bounded by `forwarder.max_idle_connections` (default
256) globally and `forwarder.max_idle_connections_per_host` (default
32) per pool key. When the global limit is reached, the oldest idle
connection MUST be closed before opening a new one. Pool exhaustion
MUST NOT block new requests indefinitely; a request that cannot
acquire a pooled or fresh connection within
`forwarder.connection_acquire_timeout_seconds` (default 5) MUST fail
with `502 Bad Gateway` and an audit-log entry.

---

## 6. HTTPS proxy behavior

### 6.1 The CONNECT method

A standard HTTPS request through an HTTP proxy uses RFC 7231 §4.3.6
CONNECT. The client sends:

```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
```

trollbridge MUST respond with `200 Connection Established` (on allow)
or `470` (on decline). After 200, the client and origin exchange TLS
bytes through the tunnel.

### 6.2 What trollbridge can see WITHOUT interception

When CONNECT is granted and TLS is **not** intercepted, trollbridge
sees:

- The destination `host:port` from the CONNECT line.
- The destination `Host:` header, which MAY differ from the CONNECT
  host on a CDN.
- The TLS Client Hello SNI (if trollbridge inspects the first bytes of
  the tunnel — see §6.3). The SNI is in cleartext and MUST match the
  CONNECT host or a deny rule SHOULD fire.
- Rough byte volumes and timing per direction.
- TLS version negotiated (visible from ClientHello/ServerHello).

trollbridge does **not** see, without interception:

- The HTTP method (GET, POST, ...).
- The URL path or query string.
- Request or response headers other than the CONNECT line.
- Request or response bodies.
- Any per-request identity inside the tunnel.

### 6.3 SNI inspection without interception

trollbridge SHOULD inspect the ClientHello's SNI extension before
completing the CONNECT tunnel, and MUST treat a SNI/host mismatch as
suspicious. Acting on this is configurable: deny by default, log by
default, or allow with the mismatch noted in the audit record.

SNI inspection is read-only and MUST NOT modify the bytes; the client
MUST see exactly the bytes the origin sent.

### 6.4 What trollbridge sees WITH interception

When TLS interception is enabled (§7), trollbridge sees the same things
it sees for plain HTTP: method, path, headers, body. The client
believes it is talking to the origin (because trollbridge presents a
cert signed by a CA the client trusts). The origin believes it is
talking to a normal HTTPS client (because trollbridge makes a real
TLS connection to it).

### 6.5 ALPN / HTTP/2

trollbridge MUST support ALPN. In intercept mode it MAY negotiate h1
on both the client side and the origin side, OR negotiate h2 on both
sides if the implementation includes h2 support. **The Phase 1
implementation MAY negotiate h1 only and downgrade h2 origins**; this
is acceptable as a known limitation and MUST be documented to
operators because some origins refuse h1.

### 6.6 WebSockets and other Upgrades

`Upgrade: websocket` over HTTP MUST be supported. trollbridge proxies
the upgrade, then forwards bytes in both directions until either side
closes. WebSocket frames MAY be inspected if interception is on, but
the inspection pipeline MUST handle long-lived streams without
buffering.

---

## 7. TLS interception design

### 7.1 Why interception

Without interception, trollbridge cannot enforce policy on URL paths,
methods, headers, or bodies for HTTPS requests. For an agent that
makes mostly HTTPS requests (which is most of them), this collapses
the policy surface to "host and port only." Interception is what
makes URL- and method-level rules meaningful for HTTPS.

### 7.2 The CA

trollbridge MUST be able to generate a local Certificate Authority on
first run via `trollbridge ca init`. The CA private key MUST be stored
on disk with `0600` permissions, owned by the trollbridge process
user. The CA cert (public) MUST be exportable via `trollbridge ca
export` for installation into client trust stores.

The CA cert MUST be marked with `BasicConstraints CA:TRUE` and
`pathLenConstraint:0` (the CA may sign leaf certs but no
intermediates).

### 7.3 Key parameters and lifetime

- Key type: RSA 4096 by default; ECDSA P-256 MAY be used if the
  operator opts in via `interception.leaf_key_type: ecdsa-p256`.
  ECDSA leaf cert generation is roughly an order of magnitude
  faster than RSA 4096, which matters when many new hosts are
  contacted in a short window (e.g., a fresh `npm install`). Some
  legacy clients do not handle ECDSA; RSA 4096 is the default for
  compatibility, ECDSA is the speed-conscious opt-in.
- CA validity: 10 years (configurable). trollbridge MUST emit a
  warning to stderr when the CA is within 30 days of expiry.
- Leaf cert validity: 1 year. Leaf certs are cached in memory; the
  cache MUST evict on cert expiry.
- Subject: `CN=trollbridge local CA <hostname> <YYYYMMDD>`.

### 7.4 Generation, storage, rotation

- **Generation**: `trollbridge ca init` generates a new CA and writes
  `trollbridge-ca.crt` (public) and `trollbridge-ca.key` (private).
  If files already exist at those paths, `ca init` MUST refuse with
  a clear error. With `--force`, trollbridge MUST archive each
  existing file to `<path>.<RFC3339-timestamp>.bak` before writing
  the new one. trollbridge MUST NEVER silently overwrite an existing
  CA private key file.
- **Storage**: paths configurable; default `./` (the directory
  trollbridge is run from) for ad-hoc installs and
  `/etc/trollbridge/` for system installs (operator sets
  `TROLLBRIDGE_CONFIG` or passes `-d /etc/trollbridge` to `init`).
  The private key MUST NOT ever be packaged into a Docker image,
  written to a public-readable path, or echoed to logs.
- **Rotation**: `trollbridge ca rotate` generates a new CA, writes it
  alongside the old, and starts signing new leaf certs from the new
  CA after a configurable grace period. Operators MUST install the
  new CA in client trust stores before the grace period ends.
  trollbridge MUST audit-log every CA rotation event.
- **Revocation**: trollbridge MAY publish a CRL on a local HTTP
  endpoint; clients that check CRLs MAY use it. Practically, leaf
  cert lifetimes are short enough that revocation is mostly handled
  by expiry. trollbridge MUST flush the leaf cert cache on operator
  command (`trollbridge ca flush-cache`).

### 7.5 Installing the CA into a client trust store

The install procedure differs by OS. trollbridge SHOULD print exact
commands rather than wave at "install the CA somewhere." The
`trollbridge ca install` subcommand is the canonical source: it
prints copy-pasteable commands tailored to the detected host OS,
and `--all-platforms` dumps every variant. The reference set of
platforms it MUST cover:

- **Debian / Ubuntu / Mint**: copy `trollbridge-ca.crt` to
  `/usr/local/share/ca-certificates/`, run `update-ca-certificates`.
- **Fedora / RHEL / CentOS / Rocky**: copy to
  `/etc/pki/ca-trust/source/anchors/`, run `update-ca-trust`.
- **Alpine**: same as Debian (`/usr/local/share/ca-certificates/` +
  `update-ca-certificates`).
- **Arch / Manjaro**: `trust anchor --store <cert>`.
- **macOS user keychain**: `security add-trusted-cert -d -r
  trustRoot -k ~/Library/Keychains/login.keychain-db <cert>`. The
  system keychain variant requires sudo.
- **Windows**: `certutil -addstore -f Root <cert>` (admin shell).

The subcommand additionally MUST emit per-runtime trust-bundle
env-var options for clients that ignore the system trust store:
Node (`NODE_EXTRA_CA_CERTS`), Python (`SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`), Go on Linux (`SSL_CERT_FILE`), curl
(`CURL_CA_BUNDLE`), and the Java `keytool` one-shot import.

`trollbridge ca install` is print-only by default. It MAY execute
the system-trust-store install commands itself when invoked with
`--apply`, subject to the following constraints:

- `--apply` requires elevated privileges (root on Linux/macOS).
  When the calling process is not root, the subcommand MUST refuse
  with a message naming `sudo` rather than spawning sudo itself.
- `--apply` is not supported on Windows or unrecognized Linux
  distributions; the subcommand MUST refuse with a message
  pointing the operator at the printed commands.
- `--apply` MUST prompt the operator with the resolved argv list
  and `Proceed? [y/N]:` before running anything, unless `--yes`
  was passed. Empty input or EOF MUST be treated as decline.
- `--apply` MUST NOT modify shell rc files, environment, or any
  per-runtime trust bundle (`NODE_EXTRA_CA_CERTS` etc.). Those
  remain print-only regardless of `--apply`.
- Step failure aborts the sequence and exits non-zero with the
  underlying tool's stderr surfaced to the operator.

The reverse operation is `trollbridge ca uninstall`, symmetric in
flag surface (`--config`, `--cert`, `--all-platforms`, `--apply`,
`--yes`) and in privilege rules. Per platform it removes the
destination cert from the trust-store drop-in directory and
re-runs the trust-store rebuild:

- Debian / Ubuntu / Mint / Alpine: `rm -f
  /usr/local/share/ca-certificates/trollbridge-ca.crt &&
  update-ca-certificates --fresh`.
- Fedora / RHEL / CentOS / Rocky: `rm -f
  /etc/pki/ca-trust/source/anchors/trollbridge-ca.crt &&
  update-ca-trust`.
- Arch / Manjaro: `trust anchor --remove trollbridge-ca`.
- macOS system keychain: `security delete-certificate -c
  trollbridge-ca /Library/Keychains/System.keychain`.
- Windows: `certutil -delstore -f Root trollbridge-ca` (admin shell).

The subcommand is print-only by default; `--apply` runs the
sequence under the same root + confirmation rules as `ca install`.
The cert resolution is informational — `uninstall` removes the
*destination* file in the trust store, not the source cert at
`interception.ca.cert_path`.

### 7.6 Inside an Incus VM

For the recommended Incus deployment (§14):

1. Operator generates the CA on the host.
2. Operator copies `trollbridge-ca.crt` into the VM image (cloud-init,
   bind mount, or `incus file push`) at install time.
3. Operator runs the appropriate `update-ca-certificates` /
   `update-ca-trust` inside the VM.
4. Operator sets `HTTPS_PROXY=http://<host-ip>:8080`,
   `HTTP_PROXY=http://<host-ip>:8080`, `NO_PROXY=localhost,127.0.0.1`
   in the VM's environment.
5. Operator firewalls the VM so its only egress is to `<host-ip>:8080`.

### 7.7 Risks of interception

TLS interception is a **trust break** the operator must accept
deliberately. trollbridge documentation MUST surface these risks:

- **The CA private key is a master key for the trust store.** Anyone
  who steals it can impersonate any HTTPS origin to that client. Host-
  level controls (file permissions, FDE) are essential.
- **Origin cert validation moves into trollbridge.** Clients can no
  longer detect a compromised origin themselves. trollbridge MUST
  perform full chain + hostname + expiry verification on the origin
  side, and MUST refuse to forward when verification fails (without
  an explicit per-rule override).
- **Pinned-cert clients break.** A client that pins
  `Let's Encrypt R3` will reject trollbridge's leaf. trollbridge MUST
  expose a `tls_intercept: false` rule modifier so specific
  destinations can pass through unintercepted.
- **Compliance.** Some software / EULAs forbid MITM. The operator is
  responsible for knowing whether interception is permitted in their
  context.

### 7.8 Origin verification under interception

When interception is on, trollbridge is the TLS client to the origin.
trollbridge MUST:

- Use the system trust store (or operator-configured trust store) to
  verify the origin's chain.
- Verify the origin's hostname against the CONNECT host (and SNI).
- Reject expired or revoked origin certs unless an explicit rule
  modifier overrides.
- Surface origin TLS failures to the client as a clear `502 Bad
  Gateway` with a `Trollbridge-Reason: origin-tls-failure` header.

---

## 8. Policy model

### 8.1 The decision

The policy engine produces exactly one `Decision` per request. The
`Decision`'s `Effect` is one of:

- `allow` — request is forwarded.
- `deny` — request is refused with 470 (or CONNECT-rejected).
- `ask_user` — request is held; an operator approves or denies via
  the CLI / control API.
- `ask_llm` — engine has no deterministic answer; the LLM advisor is
  invoked and returns a candidate Decision.

`ask_llm` MUST resolve to one of `{allow, deny, ask_user}` before
audit-logging finalizes; it never persists in the audit log as a
final effect.

### 8.2 Modes

The proxy operates in one of three top-level modes, configurable
globally and overridable per identity:

- **`default-deny`** — any request not matched by an `allow` rule is
  denied. Recommended for production agents and CI.
- **`default-allow`** — any request not matched by a `deny` rule is
  allowed. Acceptable only for trusted local-dev use where audit-log
  review is the primary control. trollbridge MUST log a startup
  warning when this mode is in use.
- **`default-ask`** — any request not matched by any rule is held
  for either LLM advisor or operator approval. Recommended for new
  setups.

### 8.3 Rule shape

A rule is a YAML object with `match`, `effect`, optional `modifiers`,
and metadata. `match` clauses combine with AND semantics. Multiple
rules combine in declared order; first match wins, with explicit
priority overrides. Example:

```yaml
- id: allow-github-api
  description: Coding agent may read GitHub API.
  match:
    host: api.github.com
    port: 443
    method: ["GET", "HEAD"]
    identity: coding-agent
  effect: allow
  modifiers:
    - redact_authorization_header
```

Rule fields trollbridge MUST support:

- `id` — string, unique. Used in audit logs and CLI references.
- `description` — string, human-readable.
- `match` — object containing any combination of:
  - `host` — exact string or list of strings; wildcard `*.example.com`
    SHOULD be supported.
  - `port` — integer or list of integers.
  - `path` — exact, prefix (`/api/`), or regex (`^/v1/.+$`). Regex MUST
    be opt-in via `path_regex:` to make accidental regex-as-string
    failures impossible.
  - `method` — string or list.
  - `header_match` — map of header → regex, all of which must match.
  - `body_pattern` — string or regex for request body inspection
    (requires interception + body inspection turned on).
  - `content_type` — string match.
  - `response_header_match` / `response_body_pattern` — for response-
    side rules; require post-response inspection (§11).
  - `identity` — string, must match resolved client identity.
  - `time` — cron-like window, e.g., `weekdays 09:00-18:00`.
  - `prior_decision` — predicate over the recent audit log (e.g.,
    "if the same identity hit this host in the last 60s with a
    `deny` decision, deny again without re-asking").
- `effect` — one of `allow | deny | ask_user`.
- `modifiers` — list of named transformations (e.g.,
  `redact_authorization_header`, `tls_intercept: false`,
  `prefer_mcp_tool: github`, `narrow: read_only`).
- `priority` — integer; higher wins. Default 100.
- `expires` — RFC 3339 timestamp; rule auto-removes after.

### 8.4 Identity

Client identity is resolved in the following order (highest priority
first):

1. **mTLS client certificate.** If the client presents a cert signed
   by an operator-configured client-CA, the cert's CN or SAN provides
   the identity. This is the only **strong** identity.
2. **Bearer token** in `Proxy-Authorization: Bearer <token>`,
   matched against operator-configured tokens.
3. **Source IP** matching a configured map.
4. **Header heuristic** (`X-Trollbridge-Identity` or similar) — treated
   as **advisory**, never as the sole identity.

If no identity matches, trollbridge MUST treat the request as
`identity: anonymous`. Rules that require a specific identity MUST NOT
match anonymous requests.

### 8.5 Holds and approvals

When effect is `ask_user`, trollbridge:

1. Generates a `hold_id`.
2. Holds the client connection, OR returns `471` (Trollbridge
   pending approval) with `Trollbridge-Hold-Id: <id>` and a
   `Retry-After: <seconds>` header (configurable per-rule).
3. Surfaces the held request to the operator via:
   - `trollbridge decisions --pending` (CLI)
   - HTTP control API on a separate port (`/v1/holds`)
4. Awaits operator action.

If no approval/denial arrives within `approvals.timeout_seconds`, the
hold MUST resolve to `deny` (configurable). The audit log MUST record
the timeout.

---

## 9. LLM decision model

### 9.1 Role

The LLM advisor is **classifier and recommender, never enforcer**.
The deterministic engine remains authoritative. The LLM:

- Receives structured request metadata (NOT full bodies by default).
- Returns a structured `Decision` candidate.
- Has its candidate validated by the engine before any effect.

### 9.2 When the advisor is invoked

The advisor is invoked when:

- Mode is `default-ask` and no rule matched.
- A rule with `effect: ask_llm` matched.
- `default-deny` mode is configured with `llm.consult_on_deny: true`
  AND the request is in a configured "consult-rather-than-silent-
  deny" list. (This is a Phase 4+ feature; the default is to deny
  silently and audit-log.)

The advisor is NOT invoked for `allow` or `deny` rules.

### 9.3 Prompt input

The advisor receives a JSON object with these fields and ONLY these
fields by default:

```json
{
  "method": "POST",
  "scheme": "https-intercepted",
  "host": "api.example.com",
  "port": 443,
  "path": "/v1/customers",
  "headers_redacted": {
    "Content-Type": "application/json",
    "User-Agent": "<redacted>",
    "Authorization": "<redacted-bearer>"
  },
  "body_summary": {
    "size_bytes": 4321,
    "content_type": "application/json",
    "structural_shape": "object: {customer_id:str, fields:[...]}"
  },
  "identity": "coding-agent",
  "tool": "claude-code",
  "rule_set_version": "2026-05-06-3",
  "allow_list": ["api.github.com", "*.npmjs.org"],
  "deny_list":  ["169.254.169.254", "pastebin.com"]
}
```

The `allow_list` / `deny_list` fields contain the operator's
current flat lists (§10.8) so the advisor can use them as
classification context. The advisor MUST NOT mutate either
list — see §10.8.1.

The advisor MUST NOT receive:

- Authorization tokens, API keys, or anything matching a credential
  pattern.
- Request body content unless the rule that triggered the consult
  explicitly opts in via `llm.send_body: true`. Even then, redactors
  run first.
- Response bodies. Response-side LLM consults are a separate, opt-in
  Phase 4+ feature.
- Prior advisor or LLM verdicts — any record of how this or another
  request was previously classified by an LLM. The advisor classifies
  from human input (the lists), the request shape, and the operator's
  directives only. See `docs/alignment-principles.md` §5.

### 9.4 Output schema

The advisor MUST return JSON matching this schema (exact form is
defined in code by a JSON Schema):

```json
{
  "effect": "allow",
  "scope": "once",
  "reason": "GitHub API listing repo issues; matches the operator's allow_list intent for source-control hosts.",
  "modifiers": ["redact_authorization_header"],
  "confidence": "high"
}
```

- `effect` is one of `{allow, deny, ask_user, narrow_scope,
  redact_and_retry, prefer_structured_tool}`.
- `scope` is one of `{once, session}`. Scoping further than the single
  request is advisory; the engine does not promote a scope into a
  durable rule.
- `modifiers` is a list of named transformations the engine knows.
- `confidence` is `{low, medium, high}`. Used by the engine to decide
  whether to apply or fall back to `ask_user`.

The response shape carries no field that names or implies a list
mutation. Per `docs/alignment-principles.md` §1, the LLM is never
involved in editing the operator's allow/deny lists, even as a
"suggestion." Mutation is human-only.

### 9.5 Validation

The engine MUST validate every advisor decision before applying:

1. Schema validation. Malformed JSON or missing fields → reject; fall
   back to `ask_user`.
2. **Non-elevation**. The advisor cannot upgrade the engine's
   deterministic answer. If a rule said "ask_llm because we're not
   sure," the advisor's `allow` is acceptable; if a rule said
   "ask_user because operator MUST approve," the advisor's `allow` is
   converted to `ask_user`. The non-elevation matrix is:
   - rule says `ask_llm` → advisor `allow|deny|ask_user|narrow|...` are all honored.
   - rule says `ask_user` → advisor decisions are recorded but the
     effect remains `ask_user`.
   - rule says `allow` or `deny` → advisor is not consulted at all.
3. **Confidence threshold**. `confidence: low` MUST NOT auto-allow;
   it falls back to `ask_user`. Configurable per identity.
4. **Modifier whitelist**. Only modifiers known to the engine are
   honored; unknown modifiers are dropped with an audit-log warning.

### 9.6 Provider, model, latency

trollbridge MUST be provider-agnostic; the LLM is configured by
`llm.provider`, `llm.model`, `llm.endpoint`, `llm.api_key_path`. The
default recommended provider in Phase 4 is whichever Anthropic
`claude` model is current at the time of implementation; the design
does not pin a model version.

The advisor's call MUST have a hard timeout (default 8 seconds).
Timeout falls back to `ask_user` (configurable to `deny`).

### 9.7 Caching

Advisor decisions are cached by `(rule_set_version, request_shape_hash)`
for `llm.cache_ttl` (default 5 minutes). This avoids paying the LLM
cost on every repeated request to the same host with the same
identity.

### 9.8 Replay

trollbridge MUST support `trollbridge logs replay --rules <file>`:
re-run policy decisions over a past audit log under a new rule set,
including re-consulting the LLM advisor (if the operator opts in),
and produce a report of which past decisions would change.

### 9.6 Quiet-moment generalization suggestion (closes #168)

Independent of the per-request advisor path, the daemon runs a
quiet-moment **suggestion lifecycle** that proposes generalizations
across the operator's existing allow / deny entries. The flow is
deliberately decoupled from request gating so it never interrupts
the operator during a burst of pending approvals.

**Quiet predicate.** The lifecycle fires only when (a) the
approvals queue is empty and (b) no inbound proxy request has
arrived for `approvals.suggestion.quiet_idle_seconds` (default
30 s).

**Deterministic detector.** When the predicate fires, `internal/
generalize` scans the allow list and the deny list independently
for any of three closed-set axes:

- **hostname below the TLD** — two or more hosts in the same list
  that share a common registrable-domain parent (computed via
  `golang.org/x/net/publicsuffix`, so `co.uk` is never wildcarded).
- **URL segment** — two or more entries sharing scheme+host+port+
  method and differing only in their final path segment.
- **method** — two or more entries sharing scheme+host+port+path
  and differing only in HTTP method.

Each candidate is `{axis, list (allow|deny), source_entries,
suggested_pattern}`. Single-entry inputs never produce a candidate
(the directive's "two or more" rule). The detector emits no LLM
call.

**Decline filter.** Each candidate's sorted source-entry set is
canonical-keyed and matched against `lists.declined_suggestions`
(see below). Matches are suppressed and emit
`decline_filter_suppressed` at INFO.

**LLM rank-and-narrate.** When ≥1 candidate survives the filter,
the advisor's `Suggest` shape (a SIBLING of the request-classifier
`Classify` shape — not an extension) ranks the candidate axes and
produces a one-line operator-facing reason. Per alignment principle
§1, the LLM's response is REJECTED if the ranking names an axis
not present in the input; the LLM cannot smuggle a pattern past
the deterministic detector. v1 ships a deterministic ranker as the
mainline; LLM-translator integration is a follow-up.

**TUI surface.** A single suggestion row appears in the approvals
pane below any pending holds. When a real hold arrives, the row is
hidden from the render tree; when the queue drains, the row
reappears. The TUI's accept / decline keystrokes POST to the
control plane's `/v1/suggestion/accept` / `/v1/suggestion/decline`.

**Accept path.** The chosen pattern is appended to `lists.allow`
or `lists.deny` via `internal/configwrite` (the same write path as
manual approve/deny persistence). The lifecycle never writes
directly; the operator's keystroke is the sole mutation trigger.

**Decline path.** When the suggestion's source-entry set has more
applicable axes left in the cycle, the row rotates to the
next-ranked axis (still the same source set). When all applicable
axes have been declined, ONE row is appended to
`lists.declined_suggestions` keyed on the sorted source-entry set,
and the same set is never re-offered until the operator removes
the row by hand.

**Telemetry.** Nine event constants in `internal/oplog/events.go`
cover every phase (detector ran, ask started, classified, ask
failed, offered, accepted, declined, decline-filter suppressed,
superseded) at INFO. The completeness rule mirrors the ask-case
coverage from #25/#33/#34/#35.

**Alignment principle.** The flow does NOT violate §1
("allow/deny lists are human-only"). The advisor cannot invent a
pattern — only rank within the deterministic detector's candidate
set — and the mutation gate is the operator's explicit Accept.
The import graph stays clean: `internal/advisor` does not import
`internal/configwrite`.

---

## 10. Deterministic rule engine

### 10.0 Decision pipeline

trollbridge evaluates each request in a fixed order. The first
stage that fires produces the decision; later stages do not run.

1. **Deny list (inline).** Match against `lists.deny` patterns
   from `trollbridge.yaml`. A match is a final deny. The rule
   engine is not consulted; the LLM advisor is not consulted; no
   approval is requested.
2. **Allow list (inline).** Match against `lists.allow` patterns
   from `trollbridge.yaml`. A match is a final allow. Same
   short-circuit semantics as the deny list.
3. **YAML rule engine.** Evaluate `policy.include` rules in
   priority order; first match decides. Rules MAY produce
   `allow` / `deny` / `ask_user` / `ask_llm`.
4. **LLM advisor.** Only invoked when the rule engine returned
   `ask_llm` (and the advisor is enabled). The advisor's
   recommendation is validated and never elevates the engine's
   answer.
5. **Approval queue.** Holds `ask_user` requests until an
   operator decides or the configured timeout fires.
6. **Default mode.** If nothing fired, `default-deny` /
   `default-allow` / `default-ask` resolves the request.

The flat-list tier exists so the common case ("the agent should
be able to reach github.com") is one line of plain text. The
YAML tier is for the cases that need structure: time windows,
body patterns, identity scoping, ask_user, ask_llm.

### 10.1 Authority

The deterministic decision is the **only** authoritative
boundary. The LLM advisor is consulted only when a rule
explicitly delegates (`effect: ask_llm`) or when the proxy is
in `default-ask` mode and no rule matched.

This ordering is non-negotiable: a malicious or jailbroken LLM
cannot bypass the flat deny list, the YAML rule engine's deny
rules, or the engine's authority over the advisor.

### 10.2 Evaluation

Rules are evaluated in declared order, with `priority` as the
tiebreaker (higher priority first). The first rule whose `match`
clauses all evaluate true determines the effect.

`match` clauses are evaluated in this order so that the engine can
short-circuit cheap checks before expensive ones:

1. `identity` (string compare; cheap)
2. `host` and `port` (string/int compare)
3. `method` (string compare)
4. `path` (string or regex)
5. `time` (current-time check)
6. `header_match` (header dict regex)
7. `prior_decision` (audit-log lookup; bounded to last N entries)
8. `content_type` (header read)
9. `body_pattern` (requires body inspection; only run if all above pass)

### 10.3 Conflict handling

Two rules with the same `priority` whose match clauses both fire on
the same request: the first declared wins. trollbridge MUST emit a
startup warning when conflicting rules are detected.

### 10.4 Hot reload

On `SIGHUP`, trollbridge MUST reload the rule file. If the new file is
malformed, trollbridge MUST keep running with the previous rules and
emit an error to stderr. Reload events MUST be audit-logged.

### 10.5 Rule version tagging

Each rule load assigns a `rule_set_version` (a hash of the rule file
content + load time). Every audit-log entry records the
`rule_set_version` that produced its decision, so replay analysis can
reproduce historical decisions exactly.

### 10.6 Default-mode resolution

If no rule matches:

- `default-deny` → effect `deny`, source `default`, reason
  `no rule matched`.
- `default-allow` → effect `allow`, source `default`, reason
  `no rule matched`. (Audit-logged at WARN level.)
- `default-ask` → effect `ask_llm` (if LLM advisor configured) or
  `ask_user` (otherwise).

### 10.7 Engine extensibility

The engine MUST expose a stable interface so a future operator can
swap the YAML rule store for an OPA/Rego engine or a custom one. The
interface (Phase 1):

```go
type Engine interface {
    Decide(req *RequestEvent) Decision
    RuleSetVersion() string
    Reload() error
}
```

Default implementation: the YAML engine. Other implementations are
out of scope for Phase 1 but the seam exists.

### 10.8 Flat allow / deny lists (fast path)

The flat lists are the simplest authoring surface and the
load-bearing reason most deployments do not need YAML rules at
all. They live as inline arrays inside `trollbridge.yaml`:

```yaml
lists:
  allow:
    - api.github.com
    - "*.npmjs.org"
    - pypi.org
    - files.pythonhosted.org
  deny:
    - 169.254.169.254
    - metadata.google.internal
    - metadata.azure.com
```

Each entry is a pattern of the form

```
[<METHOD>|*] [<scheme>://]host[:port][/path]
```

with these wildcard semantics:

- `METHOD` (optional prefix, closes #85)
  - omitted: any method (equivalent to `*`).
  - `*`: explicit any-method marker (interchangeable with omitting the prefix).
  - Uppercase HTTP verb (e.g., `GET`, `POST`, `CONNECT`):
    only matches that method. Method comparison is
    case-insensitive against the request method.
  - Any uppercase-letter token is accepted as a method; we do
    not whitelist a fixed verb set so operators can wire
    custom methods if needed.
- `host`
  - exact label match (case-insensitive): `api.github.com`
  - bare `*`: any host (use sparingly).
  - `*.example.com`: any subdomain of `example.com` (one or
    more labels). Does NOT match the apex `example.com`. This
    matches the YAML rule engine's existing host-wildcard
    semantics.
  - Mid-string wildcards (`api.*.example.com`) are NOT
    supported and MUST cause a parse error.
- `port`
  - omitted or `*`: any port.
  - integer 1..65535: exact port.
- `path` (after the first `/` of the pattern)
  - omitted or `/*`: any path (including `/`).
  - `/api/*`: prefix match (`/api/foo`, `/api/`, etc.).
  - `/exact`: exact match only.
  - Mid-string `*` in paths is NOT supported.
- `scheme` (optional prefix)
  - omitted: any scheme.
  - `https://` or `http://`: scheme-scoped match.

Pipeline placement is per §10.0: the deny list is checked
first, then the allow list, then the YAML engine. Deny wins on
overlap. A flat-list match short-circuits — no rule is
evaluated, no advisor consulted, no approval requested.

The audit log distinguishes flat-list decisions:
`decision_source` is `denylist` or `allowlist`, and `rule_id`
identifies the matched pattern entry so the operator can locate
it in `trollbridge.yaml`.

#### 10.8.1 Mutation is human-only

The flat lists are mutated only by:

1. The operator hand-editing `trollbridge.yaml` in any text
   editor.
2. The interactive console (`trollbridge run` with stdin
   attached to a tty); see §13.7. Console commands `allow X`
   / `deny X` / `remove X` invoke `internal/configwrite`,
   which atomically rewrites the YAML file in place.

The LLM advisor MUST NOT modify either list. The advisor's
output schema (§9.4) carries no list-mutation field — there is
no "suggested_rule" or equivalent in the wire shape. This is a
load-bearing safety property (see `docs/alignment-principles.md`
§1): a malicious or jailbroken advisor cannot expand its own
permitted destinations, even by routing a suggestion through the
operator.

#### 10.8.2 Mutation propagation

Console mutations update the in-memory list pointer in the
same call that writes the YAML file: `configwrite` returns,
and the server's `SetLists` runs synchronously before the
console acknowledges the operator's input. There is no file
watcher; no race window between disk and memory.

Operator hand-edits to `trollbridge.yaml` are picked up via
SIGHUP or `trollbridge rules reload`, which re-reads the
config and re-installs both the rule engine and the inline
lists. Until reload, the running proxy continues to use the
prior in-memory lists.

If a reload fails to parse, trollbridge MUST keep the prior
in-memory state and emit a warning. The proxy never serves
with a half-loaded list.

#### 10.8.3 Sorted insertion

When the console writes the YAML file (via `configwrite`),
new entries are inserted into a sorted position rather than
appended at the end. Sort key:

1. Reversed labels of the host (case-insensitive).
2. Wildcard `*` ordered AFTER literal labels at the same
   position. So `*.github.com` falls AFTER `api.github.com`
   rather than at the top of the list.
3. Port (numeric; omitted or `*` = 0, so `host` sorts before
   `host:443`).
4. Path string.
5. Raw entry text as a final stability tiebreak.

Surrounding comments and trailing inline comments inside the
`lists:` block are preserved by the YAML library; comments
elsewhere in `trollbridge.yaml` are unaffected.

Hand-edited entries are NOT re-sorted on reload. Sorting fires
only when the console writes (because that is when trollbridge
authors content).

#### 10.8.4 Advisor receives lists as read-only input

When the advisor is consulted, the request's `Input` (§9.3)
includes the operator's current allow and deny entries (capped
at 200 per list to bound the LLM input). This lets the advisor
classify a request in light of what the operator already
trusts or blocks. The lists remain read-only — see §10.8.1.

---

## 11. Request/response inspection pipeline

### 11.1 Pipeline stages

Each request passes through these stages in order:

1. **Parse.** Dispatcher emits a `RequestEvent` with method, host,
   port, path, headers. Bodies are not yet read.
2. **Identity.** Resolve client identity (§8.4).
3. **Pre-body decision.** Engine evaluates rules whose `match` clauses
   do not require the body. If a decision is reached without needing
   the body, the request proceeds.
4. **Body inspection (conditional).** If any pending rule requires
   body content (`body_pattern`, `content_type` of multipart with
   nested rules) AND the request has a body AND interception is on,
   trollbridge reads up to `inspection.max_request_body_bytes` (default
   1 MiB) into a buffer for inspection. Larger bodies are streamed
   without buffering, and rules that depend on body content cannot
   match — trollbridge MUST treat unmet body-dependent matches as
   unmatched, NOT as matched-but-hidden.
5. **Final decision.** Engine evaluates body-dependent rules.
6. **Redaction.** Modifiers apply (e.g., remove `Authorization`
   header before forwarding).
7. **Forward.** If allowed, forwarder makes the upstream call.
8. **Response inspection (conditional).** Same as request body, but
   for response bodies. Most rules only inspect responses when
   `response_body_pattern` is set.
9. **Audit-log write.** Final decision plus inspection metadata.

### 11.2 Streaming preservation

trollbridge MUST detect and preserve streaming responses:

- `Transfer-Encoding: chunked` — pass through chunk-by-chunk.
- `Content-Type: text/event-stream` — pass through line-by-line; do
  NOT buffer.
- WebSocket upgrade — bidirectional byte forwarding without buffering.
- Long-poll — no special handling needed; the connection is just
  open.

### 11.3 Body sampling

When the audit log requires a body sample (configurable per rule),
trollbridge captures the **first N bytes** (default 4 KiB) AFTER
redaction. The sample MUST be marked with `sample_truncated: true` if
the body exceeded N.

### 11.4 Modifiers

A modifier is a named transformation applied before forward (or
before audit-log write for response modifiers). Phase 1 modifiers:

- `redact_authorization_header` — replace `Authorization` value with
  `<redacted>`.
- `redact_cookie` — replace `Cookie` value with `<redacted>`.
- `redact_request_body_field: <jsonpath>` — replace the named JSON
  field's value with `<redacted>`.
- `tls_intercept: false` — pass this CONNECT through without
  interception even if the global mode says intercept.
- `narrow: read_only` — convert the method to `GET` if it was a
  mutating method (advisory; rejects writes by reformatting them as
  read attempts that the operator can examine in the audit log).

Future modifiers (Phase 4+): `prefer_structured_tool: <mcp-tool>`,
`mark_high_risk`, `slow_path` (rate-limit).

### 11.5 Failure during inspection

If body inspection fails (parse error, decode error, size limit
exceeded for a rule that required the body), trollbridge MUST fail
closed: the request is denied with a `Trollbridge-Reason:
inspection-failed` header and an audit-log entry naming the cause.
This MUST NOT leak the body content to the audit log.

---

## 12. Allowlist and denylist behavior

### 12.1 Modes

trollbridge supports the three top-level modes from §8.2. The
allowlist/denylist behavior under each:

- **`default-deny`** — operators write `allow` rules. Anything not
  matched is denied. This is an **allowlist** posture.
- **`default-allow`** — operators write `deny` rules. Anything not
  matched is allowed. This is a **denylist** posture.
- **`default-ask`** — both allow and deny rules narrow the ask
  surface; unmatched requests fall through to LLM/operator review.

Operators SHOULD prefer `default-deny` for production agent
environments and `default-ask` for new setups; `default-allow` is
appropriate only for trusted dev environments where audit-log review
is the primary control.

### 12.2 Allowlist guidance

- **Scope rules narrowly.** `allow github.com` is far less safe than
  `allow GET https://api.github.com/repos/MyOrg/*/issues`. The proxy
  enforces what is written; if the rule is broad, the protection is
  weak.
- **Method discipline.** GET/HEAD allowlist for read-only access is a
  meaningful control. POST/PUT/DELETE rules SHOULD be a separate
  rule with stricter `match` clauses, not "GET/POST" lumped.
- **Time windows.** A CI deployment agent that only deploys on
  weekdays SHOULD have `time` clauses; a weekend deploy is
  suspicious.

### 12.3 Denylist guidance

Denylist mode is inherently weaker because new attack destinations
appear continuously. Operators using `default-allow` SHOULD:

- Subscribe to a threat feed and import block rules.
- Periodically review the audit log for unexpected hosts.
- Switch to `default-ask` when the audit log volume is reviewable, or
  to `default-deny` once known-good destinations are enumerated.

### 12.4 Hierarchical rules

Rules MAY be split across multiple files; trollbridge MUST load all
files referenced under `policy.include:` in declared order. This
supports composition: a base rule set + per-environment additions.

### 12.5 Built-in suggested deny set

trollbridge SHOULD ship a `policy/suggested-denies.yaml` that operators
MAY include. It contains rules for known-bad classes (e.g.,
`metadata.google.internal`, `169.254.169.254`, common pastebin hosts,
known C2 infrastructure where lists are public). Operators MAY add
or remove from it. This file is curated by trollbridge maintainers and
MUST be auditable.

---

## 13. CLI and configuration design

### 13.1 CLI shape

```
trollbridge <command> [args] [flags]
```

A single binary, Cobra-style subcommands.

### 13.2 Required commands

| Command | Purpose |
|---|---|
| `trollbridge init` | Create a default `trollbridge.yaml` and CA. MUST print a human-readable summary to stdout listing every file created, their paths, the CA SHA-256 fingerprint, and the next-step commands (install CA into client trust store; review and edit rules). MUST refuse to overwrite existing files; `--force` archives them per §7.4. |
| `trollbridge validate` | Validate the configuration and rule set; reject unknown modifier names, unknown effect strings, conflicting rule IDs. Exit 0 on success, 1 on error. |
| `trollbridge doctor` | Pre-flight check: load the config and rule files; when `llm.enabled`, dispatch a real classification call against the configured provider with a synthetic input. Each step prints `OK` / `FAIL: <reason>`. Non-zero exit on any failure. Used to catch misconfigured endpoints / API keys / providers before `trollbridge run`. |
| `trollbridge run` | Start the proxy in the foreground. Reads config from `--config` or `TROLLBRIDGE_CONFIG`. |
| `trollbridge ca init` | Generate a new CA. Refuses if one exists unless `--force`. |
| `trollbridge ca export` | Print the CA cert (public) to stdout, or write to `--out <file>`. |
| `trollbridge ca install` | Print copy-pasteable commands to install the CA into the OS trust store (and per-runtime trust-bundle env vars). Detects the host OS; `--all-platforms` prints every variant. With `--apply` (and root), executes the system-trust-store steps after a `[y/N]` confirmation; `--yes` skips the prompt. Runtime env-var advice stays print-only. |
| `trollbridge ca rotate` | Roll the CA. New CA is generated; old is kept until `--retire` is passed. |
| `trollbridge ca flush-cache` | Drop cached leaf certs. Useful during rotation or after a rule change. |
| `trollbridge decisions [--since <duration>] [--pending]` | Stream recent decisions; `--pending` shows held requests. |
| `trollbridge approve <hold-id> [--scope once\|session\|rule]` | Approve a held request. |
| `trollbridge deny <hold-id>` | Deny a held request. |
| `trollbridge rules list` | Print loaded rules with their priorities. |
| `trollbridge rules add <file>` | Append a rule file to the active set. |
| `trollbridge rules reload` | Re-read rule files (equivalent to SIGHUP). |
| `trollbridge logs tail` | Tail the structured audit log, formatted for humans. |
| `trollbridge logs replay --rules <file> --since <duration>` | Replay past decisions against a new rule set; report differences. |
| `trollbridge logs review --since <duration>` | List audit entries from human or LLM decisions, ordered by time. Static-policy auto-decisions filtered out. (#114) |
| `trollbridge sessions` | Show active client sessions with identity and decision counts. |
| `trollbridge selftest --from-vm` | Phase 5+ helper. Run from inside the agent VM. Attempts a small set of direct connections to non-proxy destinations and reports whether the egress firewall blocked them; reports whether the proxy is reachable and whether the CA is trusted by the system. Used to confirm the deployment topology before trusting it. |
| `trollbridge version` | Print version and build info. |

`trollbridge` invoked with no subcommand MUST print top-level help to
stdout and exit 0 (matching the Cobra/POSIX convention). It MUST NOT
attempt to start the proxy without an explicit `run` subcommand —
silent startup-by-default is a footgun.

### 13.3 Flags common to all commands

- `--config <path>` (default `./trollbridge.yaml`, overridable via
  `TROLLBRIDGE_CONFIG` — typically set to
  `/etc/trollbridge/trollbridge.yaml` for system installs).
- `--log-level <debug|info|warn|error>` (default `info`). Also
  `TROLLBRIDGE_LOG_LEVEL`. Persistent across all subcommands.
- `--verbose, -v` is a `run`-subcommand-local alias for
  `--log-level=debug`. (It is not made persistent because
  `logs replay --verbose` already uses the same flag with a
  presentation-layer meaning of "print each flipped decision".)
  Operators of other subcommands can use `--log-level=debug`
  directly.

### 13.4 Configuration file shape

YAML, single file by default. Top-level keys:

```yaml
# Per-surface bind (host:port). Host aliases: lo = 127.0.0.1,
# all = 0.0.0.0. Bracket IPv6 literals: [fd00::1]:8081.
proxy:   lo:8080
control: lo:8081           # 0 disables the operator control plane
metrics: 0                 # 0 disables the (unimplemented) Prometheus endpoint

mode: default-ask          # default-deny | default-allow | default-ask

interception:
  enabled: false           # Phase 1: false. Set true for Phase 3+.
  ca:
    cert_path: /etc/trollbridge/trollbridge-ca.crt
    key_path: /etc/trollbridge/trollbridge-ca.key
  leaf_key_type: rsa-4096  # rsa-4096 (default, max compat) | ecdsa-p256 (faster)
  passthrough_hosts:       # never intercept these
    - "*.googleapis.com"

llm:
  enabled: false           # Phase 1-3: false. Set true for Phase 4+.
  provider: anthropic      # anthropic -> Bearer; aoai -> api-key (Azure OpenAI)
  model: claude-opus-4-7
  endpoint: https://api.anthropic.com
  api_key_path: /etc/trollbridge/llm.key
  timeout_seconds: 8
  cache_ttl_seconds: 300
  send_body: false
  on_unavailable: ask_user # ask_user | deny | allow

redaction:
  default_modifiers:
    - redact_authorization_header
    - redact_cookie
  body_redactors:
    - jsonpath: $.password
    - jsonpath: $.api_key
    - regex: "(?i)bearer [a-z0-9._-]+"

logging:
  audit_path: /var/log/trollbridge/audit.jsonl
  audit_buffer_size: 1024
  audit_overflow: deny     # deny | drop | block
  audit_level: all         # all | decisions | none
  operational_path: stderr

approvals:
  timeout_seconds: 300
  on_timeout: deny

forwarder:
  max_idle_connections: 256
  max_idle_connections_per_host: 32
  connection_acquire_timeout_seconds: 5

shutdown:
  grace_seconds: 30        # SIGTERM: drain in-flight, deny held requests

identities:
  - id: coding-agent
    match:
      mtls_cn: "agent.local"
  - id: ci-runner
    match:
      bearer_token_sha256: "<hash>"

lists:
  # Fast-path inline allow/deny (§10.8). Evaluated BEFORE the rule
  # engine and BEFORE the LLM advisor. A match here is the final
  # decision. The console REPL writes new entries back here.
  allow:
    - api.github.com
  deny:
    - 169.254.169.254
    - metadata.google.internal

policy:
  # Structured rules for advanced cases (time, body, ask_user, ask_llm).
  include:
    - rules/base.yaml
    - rules/dev-overrides.yaml

upstream:
  proxy: ""                # http://corporate-proxy:3128 if needed
  no_proxy:
    - localhost
    - 127.0.0.1
```

Rule files referenced under `policy.include` use the rule shape from
§8.3.

### 13.5 Help text discipline

`trollbridge --help` MUST list commands grouped by purpose (operate,
configure, audit, manage CA). Each command's `--help` MUST give a
one-line summary, the full flag list, and at least one example.

### 13.5.1 Error message shape

Configuration- and rule-load errors MUST name **what** failed,
**where** (file + position), what valid input looks like, and the
**fix**. Three concrete examples trollbridge MUST be capable of
producing:

- `Configuration error at line 42 of trollbridge.yaml:` `mode` must
  be one of `default-deny`, `default-allow`, `default-ask`. Got:
  `default-asks`. Fix: correct the typo.
- `Cannot read CA private key at /etc/trollbridge/trollbridge-ca.key:
  permission denied. Fix: ensure the trollbridge process user has
  read access (mode 0600, owned by trollbridge user), or run
  `trollbridge ca init` to generate a new CA.`
- `Rule load error in rules/dev-overrides.yaml at rule index 3
  (id: allow-internal-tools): missing required field` `effect`.
  Valid values: `allow | deny | ask_user | ask_llm`. Fix: add an
  `effect:` line under the rule's match clause.

Stack traces MUST NOT be the operator-facing error surface. A panic
or unrecoverable internal error MAY emit a stack to stderr at
`--log-level debug`, but the user-facing message MUST be a one-line
"<verb> failed: <reason>; <fix>" form.

### 13.6 Environment variables

trollbridge MUST honor:

- `TROLLBRIDGE_CONFIG` — path to the config file.
- `TROLLBRIDGE_LOG_LEVEL` — overrides config's log level.
- `HTTP_PROXY` / `HTTPS_PROXY` — trollbridge's *outbound* proxy (for
  upstream destinations), separate from the proxy trollbridge itself
  exposes.

trollbridge MUST NOT silently honor any env var that overrides
security-relevant config (mode, interception, CA paths). These are
file-only.

### 13.7 Operator UI

When `trollbridge run` is invoked with stdin attached to a
terminal, trollbridge MUST draw an alt-screen two-pane operator
UI on stdout that lets the operator both review held requests
and mutate the flat allow / deny lists in flight. The UI is
silently disabled when stdin is not a tty (systemd, Docker
without `-it`, Incus exec without a pty) so service deployments
are unaffected. The `--no-console` flag disables it explicitly.

Layout:

- **Approvals pane (top)** — lists pending holds and recent
  operations, refreshing automatically as the queue changes. Keys:
  `a` approve, `d` deny, `↑↓` (or `j`/`k`) select, `r` refresh now,
  `q` (or `Esc`) quit.
- **Pinned pending region** — pending (and other not-yet-resolved)
  holds render as a card floating at the bottom of the pane, like the
  generalize/suggestion card, so they stay on screen no matter how far
  the resolved history scrolls above them. The cursor crosses into the
  pending region by moving down past the last resolved row and leaves
  it by moving up off the top pending row; re-entering pending means
  scrolling all the way to the bottom again (#185).
- **Approving a resolved-away hold** — a hold can be resolved out from
  under the operator (timeout, advisor, double-press) while its row
  still shows pending. The hold id is a transient pointer; pressing `a`
  / `d` on such a row falls back to writing the request URL to the
  allow / deny list (the same path as the retroactive add on a resolved
  row) instead of surfacing a "hold not found" error (#184).
- **Row collapsing** — the approvals pane folds resolved operations
  that share a method, host, path directory (the URL path up to and
  including its last `/`), and status into a single row. CONNECT and
  TLS operations, recorded as a bare host with no path, fold by exact
  host (and port). The row shows the most recent operation's URL and a
  Braille glyph whose dot density scales logarithmically with the
  number of collapsed operations (closes #63, #119). Held / signaled /
  pre-decision operations are never folded — each stays an
  individually actionable row so the `a` / `d` keys always target one
  unambiguous request. The operator's selection stays anchored to a
  folded group across refresh ticks even as the group's most-recent
  representative changes. Collapsing is display-only: the audit log
  and the `/v1/ops` control-plane endpoint always carry the full,
  ungrouped record.
- **Console pane (bottom)** — operator commands as a typed prompt:
  - `allow <pattern>` — append `<pattern>` to the first configured
    allow file, validating the pattern first. The file is re-
    sorted (§10.8.3); the running daemon re-parses it on each write.
  - `deny <pattern>` — same for the first configured deny file.
  - `remove <pattern>` — remove the matching line (case-insensitive
    on the pattern field) from any configured allow/deny file.
    Removes from BOTH if the pattern appears in both.
  - `move allow|deny <pattern>` — atomically move a pattern between
    lists: removes from the other side (if present) and adds to the
    chosen side. The URLs panel's `a` (approve) and `d` (deny) keys
    drive this verb (closes #86).
  - `list [allow|deny|all]` — print the current patterns.
  - `reload` — re-parse the config into the running matcher.
  - `test [METHOD] <url>` — send one request through the proxy and
    print the response (proxy-host only).
  - `doctor` — run the same checks as `trollbridge doctor`.
  - `help` — list the commands.
  - `quit` / `exit` — leave the UI; the proxy keeps running.
- **Tab** switches focus between the panes; the focused pane's
  header is bold and the unfocused pane's is dim. **Ctrl-C** quits
  from any focus.

The operator UI runs in raw mode in the terminal alt-screen so the
host shell's scrollback is preserved on exit. The list files are
written via in-place YAML edits that preserve comments outside the
`lists:` subtree; the running daemon re-parses the file
after each mutation.

The operator UI MUST NOT be reachable from the network. The
control-plane HTTP API (§13.4 `approvals.control_listen`) is the
network-facing operator surface for approvals — `trollbridge
attach` drives the same UI remotely over that API, with the
local-host commands (`allow`, `deny`, `remove`, `list`, `reload`,
`test`, `doctor`) gated to a one-line "not available in attach
mode" hint until the control plane exposes them. Flat-list
mutation is intentionally local-only because it is load-bearing
security state.

---

## 14. Deployment topologies

`init` collapses these recipes onto three preset values keyed by
where the agent runs relative to the proxy: `local` (same host),
`local-vm` (a VM on the same host), and `remote` (a different
machine). Each subsection below names which preset its recipe maps
to.

### 14.1 Local (developer workstation)

*Init preset: `local`.*

trollbridge runs as a user process on `127.0.0.1:8080`. The developer
sets `HTTP_PROXY` / `HTTPS_PROXY` in their shell. The CA is installed
into the developer's user trust store.

This topology is the easiest to set up and the weakest defense: the
developer can simply unset `HTTPS_PROXY` to bypass. It is appropriate
for honest dev workflows where the audit log is the primary control.

### 14.2 Host-side daemon for an Incus VM (recommended)

*Init preset: `local-vm`.*

trollbridge runs on the Incus host, listening on the host's bridge IP
(`192.168.x.y:8080`). The agent runs in an Incus VM. The VM's network
profile constrains egress to `192.168.x.y:8080` only (typically a
combination of an Incus network ACL plus iptables on the host that
drops everything else). The CA cert is baked into the VM image at
build time.

The strength of this topology comes from the network constraint, not
from the proxy alone. The agent inside the VM cannot reach anything
except trollbridge — the agent's only path to the internet is through
the proxy, which is the property the proxy depends on.

### 14.3 Sidecar container

*Init preset: `local` when the sidecar shares the agent container's
network namespace (compose `network_mode: "service:..."`, k8s pod
networking); otherwise `local-vm` and bind on the compose-network
interface.*

trollbridge runs as a sidecar in a container pod or compose stack.
The agent container's egress is constrained by network policies to
the sidecar IP only. The CA is mounted into the agent container's
trust store at start.

This topology fits CI runners, GitHub Actions, and other ephemeral
agent environments.

### 14.4 System-wide host daemon

*Init preset: `local` when consumers are local processes only;
`local-vm` when consumers include VMs/containers reaching across a
bridge; `remote` when consumers are on other machines.*

trollbridge runs as a systemd service on a shared host where multiple
agents (or multiple developers) connect. Each agent's identity is
resolved via mTLS or token, and rules are scoped per-identity. This
is appropriate for an internal team's "shared agent network." The
CA private key MUST be operator-controlled with strict file
permissions; this is the highest-value secret in the system.

### 14.5 What the design does NOT cover

- Running trollbridge inside the agent's own VM. (The agent could
  trivially terminate the proxy.)
- Running trollbridge on a different network the agent has no path to
  reach. (Same problem.)

---

## 15. Logging and audit trail

### 15.1 Streams

trollbridge produces three log streams:

1. **Audit log** (JSONL, one entry per decision; the load-bearing
   record).
2. **Operational log** — leveled, human-readable narrative emitted
   via `log/slog` with a custom text handler. Format:
   `<rfc3339-nano> <LEVEL> trollbridge: <msg> [k=v ...]`. Sink is
   `os.Stderr` when `logging.operational_path: stderr` (the
   sentinel default), otherwise the configured filesystem path
   (opened append-only, mode 0640, parent dir 0750; fail-closed
   at startup if unwritable). Lines emitted from a request scope
   carry `request_id=<uuid>` for correlation against the audit
   log. At `--log-level=debug` the operational log also emits
   per-request lifecycle records keyed by `phase=`
   (`received | fastpath_eval | engine_eval | held | resolved |
   forwarded | response | error`).
3. **Metrics** (Prometheus exposition, off by default; on a separate
   port). *Not yet implemented; the `metrics_listen` config knob
   exists as a stub.*

Metric labels MUST be bounded. The core decision metric is
`trollbridge_decisions_total` with labels:

- `effect` — `allow | deny | ask_user_resolved_allow | ask_user_resolved_deny | ask_user_timed_out`
- `decision_source` — `allowlist | denylist | rule | default | llm_advisor | approval_queue | approval_timeout`
- `identity_id` — small operator-controlled set; bounded by config
- `host_class` — coarse classification (e.g., `internal | api | cdn |
  unknown`), NOT the raw host (raw host is unbounded cardinality)

The combination of `effect` and `decision_source` lets operators
distinguish "denies that hit a specific rule" from "denies that fell
through to default-deny" — the latter is signal that more allow rules
are needed.

### 15.2 Audit-log entry shape

Each entry MUST contain:

- `timestamp` — RFC 3339 UTC.
- `request_id` — UUID v4.
- `session_id` — UUID v4 per client connection.
- `identity_id` — string from §8.4.
- `client_addr` — `host:port` of the client.
- `method` — HTTP method (or `CONNECT`).
- `scheme` — `http` | `https-tunneled` | `https-intercepted`.
- `host` — destination host.
- `port` — destination port.
- `path` — URL path or `""` if not visible.
- `query_redacted` — the query string after redaction, or `""`.
- `decision` — `allow` | `deny` | `ask_user_resolved_allow` |
  `ask_user_resolved_deny` | `ask_user_timed_out`.
- `decision_source` — `allowlist` | `denylist` | `rule` |
  `default` | `llm_advisor` | `approval_queue` |
  `approval_timeout`.
- `rule_id` — string, `""` if not from a rule.
- `rule_set_version` — string.
- `llm_advisor_id` — string, `""` if not consulted.
- `llm_confidence` — `low | medium | high | n/a`.
- `llm_input_hash` — sha256 of the canonicalized advisor input
  (the JSON shape sent to the LLM). `""` when not consulted.
  Enables replay analysis to distinguish "same input → different
  decision" from "different input → different decision."
- `reason` — short human-readable explanation.
- `redaction_applied` — bool.
- `redacted_field_count` — int (number of header / body fields
  redacted from the *forwarded request* and from this audit entry).
- `body_inspection_status` — `not_required` | `inspected` |
  `truncated` | `failed`.
- `request_body_sample` — first N bytes after redaction, or `""`.
- `response_status` — int, or 0 if the upstream call did not happen.
- `response_size_bytes` — int.
- `latency_ms` — total time from request receive to client-side
  response complete.
- `error` — `""` or short error class.

### 15.2.1 Audit log file permissions

trollbridge MUST create the audit log file with mode `0640`, owned by
the trollbridge process user and group `trollbridge` (or the operator-
configured group). The audit log contains request metadata that
SHOULD NOT be world-readable. Operators who need cross-user audit
review SHOULD add reviewers to the configured group rather than
loosen file permissions.

### 15.3 Redaction in the audit log

The audit log MUST default to:

- `Authorization` header value redacted to `<redacted>`.
- `Cookie` header value redacted to `<redacted>`.
- Body sample redacted by all configured `body_redactors`.
- Query string parameters matching `(?i)token|key|secret|password`
  redacted to `<redacted>`.

The audit entry MUST set `redaction_applied: true` and
`redacted_field_count: N` so an auditor sees redaction occurred, per
the principle that the *property* (redacted) AND the *claim*
(redaction_applied flag) ship together.

The audit log MUST NEVER contain the CA private key, LLM API key,
operator file paths to secrets, or any credential the operator has
configured trollbridge to redact.

### 15.4 Async write

The audit logger writes asynchronously to disk via a bounded buffer.
On buffer overflow (writes slower than decisions):

- `audit_overflow: deny` (default) — trollbridge denies new requests
  with `Trollbridge-Reason: audit-buffer-full`. Audit-log loss would
  be a security-control loss, so denying is the safe behavior.
- `audit_overflow: drop` — trollbridge drops the audit entry, allows
  the request, and emits a metric increment. Acceptable only in
  environments where availability dominates auditability.
- `audit_overflow: block` — trollbridge blocks the dispatcher until
  the buffer drains. May cause client timeouts.

The audit logger filters entries by operator-controlled level
(`logging.audit_level`, #113):

- `all` (default) — every entry is written.
- `decisions` — only entries whose `decision_source` names a human
  (approval queue, including queue timeout) or the LLM advisor are
  written. Static-policy auto-decisions (rule, default, allowlist,
  denylist) are dropped at enqueue, as are failure and error entries
  (TLS handshake failures, transport errors, body-read failures),
  which carry a non-human/LLM `decision_source`: `decisions` is
  decisions only, by design — not "decisions plus security events".
  Filtered entries do not consume buffer slots; overflow accounting
  is unaffected.
- `none` — every entry is dropped. The audit file is still opened
  so operational metadata (audit-write-failure events on the
  operational log) survives.

Dashboards that count audit lines per minute see a level-dependent
floor; the operational log is unaffected by `audit_level`.

### 15.5 Rotation

trollbridge MUST support log rotation via SIGUSR1: close the current
file, reopen the configured path. External tools (logrotate)
complete the rotation.

### 15.6 Replay

`trollbridge logs replay --rules <new-rules.yaml> --since 7d` reads
each audit entry from the past 7 days, re-evaluates the decision
against `<new-rules.yaml>`, and emits a report:

- count of decisions unchanged
- count flipped allow→deny
- count flipped deny→allow
- examples of each flip

This supports the "would my new rules have been more restrictive?"
question that operators ask after an incident.

### 15.7 Compact human stream

`trollbridge logs tail` formats the JSONL as a single line per
decision: `<timestamp> <decision> <method> <host>:<port><path>
[reason]`. Color-coded by effect.

### 15.8 Review listing

`trollbridge logs review` (#114) reads the same JSONL and lists,
in chronological order, every entry whose `decision_source` is the
LLM advisor (`llm_advisor`) or a human (`approval_queue`, including
`approval_timeout`). Static-policy auto-decisions (`rule`,
`default`, `allowlist`, `denylist`) are filtered out so the
operator sees only the entries where active judgment occurred.
Per entry: a header line with `<timestamp>  <source-tag>  <effect>
<method> <host>:<port><path>  (<identity>)`; a `reason: …` line
(when present); and an `llm: model=… confidence=… input_hash=…`
trace line for LLM entries. Shares the categorization with the
`logging.audit_level: decisions` filter (§15.4) — both call
`(DecisionSource).IsHumanOrLLM()` on the entry's source.

---

## 16. Failure modes

| # | Failure | Recovery | Visibility |
|---|---|---|---|
| 1 | Origin server unreachable | 502 to client; audit-log entry. | Audit log + metric. |
| 2 | Origin TLS verification fails | 502 with `Trollbridge-Reason: origin-tls-failure`; audit log. | Audit log + metric. |
| 3 | LLM provider unavailable | Fall back per `llm.on_unavailable` (default `ask_user`); audit log. | Metric + operational log. |
| 4 | LLM returns malformed JSON | Reject; fall back to `ask_user`; audit log records advisor failure. | Audit log + metric. |
| 5 | Rule file malformed on startup | Refuse to start with clear error message. | Stderr + non-zero exit. |
| 6 | Rule file malformed on SIGHUP | Keep prior rules; emit error to stderr; metric incremented. | Operational log + metric. |
| 7 | CA private key missing/unreadable in intercept mode | Refuse to start. | Stderr + non-zero exit. |
| 8 | CA private key permissions too open | Refuse to start; suggest `chmod 0600`. | Stderr + non-zero exit. |
| 9 | Audit log disk full | Per `audit_overflow` (default `deny`). | Audit log entry on next-success + operational log. |
| 10 | Approval queue full | Deny new ASK_USER with clear message. | Audit log + metric. |
| 11 | Approval timeout | Resolve to `deny` (default); audit log records timeout. | Audit log. |
| 12 | trollbridge crashes mid-request | Client sees connection drop; partial audit-log record may exist. | Operational log + audit log. |
| 13 | Configuration reload mid-request | In-flight requests use prior rules; new requests use new rules. | Audit log records both versions. |
| 14 | Body inspection size limit exceeded for a rule that required body | Deny with `Trollbridge-Reason: inspection-failed`. | Audit log. |
| 15 | Client uses `Connection: Upgrade` to a protocol trollbridge doesn't understand | Deny CONNECT; audit log records protocol. | Audit log. |
| 16 | Origin uses `Transfer-Encoding: gzip` (deprecated) | Pass through; do not attempt to inspect compressed bodies in Phase 1. | Body inspection status `not_required`. |
| 17 | Origin sends bytes before trollbridge has decided (e.g., HTTP/2 push) | trollbridge MUST refuse server push by negotiating it off via SETTINGS. | Operational log if seen. |
| 18 | Race: two requests for the same destination during a rule reload | Each is decided against whichever rule version was active when it arrived; each audit entry records its `rule_set_version`. | Audit log. |
| 19 | Leaf cert generation fails (crypto rng exhausted, OOM during keygen) | 502 to client with `Trollbridge-Reason: cert-generation-failed`; audit log entry; metric `trollbridge_cert_generation_failures_total` increments. | Audit log + metric. |
| 20 | SIGTERM (graceful shutdown) | Stop accepting new connections; drain in-flight up to `shutdown.grace_seconds` (default 30s); resolve all pending approvals as `deny` with reason `shutdown`; flush audit-log buffer; exit 0. SIGKILL is the operator's escape hatch if shutdown stalls. | Operational log + audit-log entry per resolved hold. |

---

## 17. Security boundaries

### 17.1 Trust boundaries

- **Operator → trollbridge**: trusted. Operator owns the host,
  controls the CA, writes the rules.
- **trollbridge → agent**: trollbridge does NOT trust the agent.
  Identity is asserted by source-IP / mTLS / bearer token; client-
  supplied identity headers are advisory.
- **trollbridge → origin**: trollbridge does NOT trust origins. Origin
  TLS chains are verified against the operator-configured trust
  store. Origin response content is treated as data, not authority.
- **trollbridge → LLM advisor**: trollbridge trusts the advisor for
  recommendations only. It never elevates the advisor's effect. It
  redacts inputs before sending.

### 17.2 The "egress firewall is binding" rule

trollbridge by itself does not stop an agent from making a direct
TCP connection. The agent's environment MUST be configured so that:

- Direct outbound TCP/UDP to anywhere except trollbridge is dropped at
  the firewall (Incus profile, Docker network policy, host iptables).
- DNS resolution either goes through a controlled resolver or is
  proxied; otherwise the agent can use DNS as a covert channel.

Without these, trollbridge is theatrical.

### 17.3 What the proxy specifically defends against

- Reaching unauthorized destinations.
- Sending unauthorized methods (writes, deletes) to allowed
  destinations.
- Accidentally including credentials in a request to a destination
  that does not need them (redaction modifiers).
- Reaching new attacker-controlled hosts that prompt-injection attempts
  to make the agent visit (via `default-deny` or `default-ask`).
- Long-running silent abuse: every action is logged with rule
  attribution.

### 17.4 What the proxy specifically does NOT defend against

(Restated from §2 for visibility within the security-boundaries
section.)

- Bypass via direct connection (mitigation: firewall).
- DNS exfiltration (mitigation: controlled resolver).
- Raw socket traffic (mitigation: firewall).
- Alternate proxies (mitigation: firewall).
- Encrypted payloads inside allowed requests.
- Malicious use of allowed destinations.
- Side channels via timing or proxy errors.
- Compromise of the operator's host.

### 17.5 Secret handling

- The CA private key MUST live in a file readable only by trollbridge's
  process user, mode `0600`, owned by that user.
- LLM API keys MUST live in an operator-controlled file, NOT in the
  config YAML (the config references the path).
- trollbridge MUST NOT log either secret. trollbridge MUST refuse to
  start if either file's permissions are too permissive.
- `trollbridge ca export` writes only the public CA cert. There is no
  "export private key" command; if the operator wants to back up the
  private key, they copy the file directly.

### 17.6 LLM-input-side security

The LLM advisor is an external service the agent might be able to
*indirectly* reach if it controls request shape carefully. trollbridge
MUST:

- Send only the structured metadata in §9.3, not raw bodies (unless
  explicitly opted in).
- Treat the LLM's output as untrusted input: validate the schema,
  bound the modifiers to a whitelist, never execute strings, never
  load suggested rules without operator approval.
- Audit-log every advisor call with input hash and output, so an
  operator reviewing odd decisions can see what the advisor saw.

### 17.7 Replay-attack and decision-cache safety

The decision cache (per §9.7) is keyed by `(rule_set_version,
identity_id, request_shape_hash)`. A request whose shape matches a
cached `allow` for the same identity re-uses the decision. Identity
MUST be part of the key — otherwise two identities making the same-
shape request would share a cached decision, and per-identity rules
would silently misfire. This is **safe by construction** because the
deterministic engine is the cache primary; the cache cannot upgrade a
decision the engine would not currently make.

When rules change (`rule_set_version` rotates), the cache is
invalidated. A `trollbridge ca flush-cache` also flushes decision
caches.

---

## 18. Implementation plan

The implementation is staged in five phases. Each phase produces a
shippable subset; the design does not require all phases to land at
once.

### Phase 1 — Plain HTTP proxy + CONNECT + deterministic rules + structured logs

Build target: `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`
producing a static binary that runs on Alpine, Debian, Ubuntu, RHEL,
and macOS without runtime dependencies.

Deliverables:

- `trollbridge run` accepts plain HTTP and CONNECT; forwards both.
- Deterministic rule engine (YAML, in-memory) with `host`, `port`,
  `path`, `method`, `header_match`, `identity` clauses.
- `default-deny` and `default-allow` modes.
- JSONL audit log with the §15.2 fields except `llm_*`.
- CLI: `init`, `validate`, `run`, `decisions --since`, `rules list`,
  `rules reload`, `logs tail`, `version`.
- Identity via source-IP and bearer token.
- Tests: unit (rule engine, redaction), integration (real client
  round-trip, deny path, audit-log shape).

Phase 1 is a usable proxy for trusted-environment "just give me an
audit log" use cases.

### Phase 2 — Interactive approval flow + richer rules + CLI mgmt

Deliverables:

- `default-ask` mode and the approval queue.
- HTTP control API on `approvals.control_listen`.
- CLI: `approve`, `deny`, `decisions --pending`, `sessions`,
  `rules add`.
- Richer match clauses: `time`, `prior_decision`, `body_pattern` (no
  interception yet, so body matching only fires for plain HTTP).
- Approval timeout handling.

### Phase 3 — TLS interception + body inspection + redaction

Deliverables:

- CA generation, export, rotation, flush.
- TLS interception with on-demand leaf cert generation, cached.
- Body inspection up to the size limit, with streaming for over-
  limit bodies.
- Body redactors (jsonpath, regex).
- Origin TLS verification.
- ALPN handling (h1 by default; document h2 limitation).
- Tests: TLS interception integration, sweep test for "no plaintext
  secrets in audit log."

### Phase 4 — LLM advisor + classification + replay analysis

Deliverables:

- LLM advisor component, behind a provider-agnostic interface.
- Advisor schema validation + non-elevation guard.
- Decision cache.
- Confidence threshold falling back to `ask_user`.
- `trollbridge logs replay`.
- Tests: advisor unit (mock LLM with malformed/elevation/hallucinated
  responses), integration (replay against past audit log).

### Phase 5 — Hardening + Incus recipes + firewall integration + packaging

Deliverables:

- Incus VM image recipe (cloud-init, CA install, env vars).
- Firewall recipe (sample iptables / nftables snippets) that
  constrains agent VM egress to trollbridge only.
- systemd unit, deb/tarball packaging, optional container image.
- Documentation pages for each topology.
- Live-build observation: an operator-confirmed run of the proxy in
  the recommended Incus topology, with a real coding agent inside,
  exercising allow / deny / ask paths.
- Performance benchmarks for the latency claims in §11 / 19.

### What MUST NOT be skipped

Phase 1's audit log is the load-bearing security artifact even
without TLS interception. An operator who installs trollbridge for
HTTP-only or CONNECT-tunnel-only visibility is still getting real
value.

Phase 5's firewall + Incus integration is the difference between a
proxy that *could* enforce policy and a deployment that *does*. An
operator running trollbridge without the firewall is running a
suggestion box.

---

## 19. Test plan

### 19.1 Unit tests

- **Rule engine**: each match clause individually, combinations,
  conflict handling, priority ordering, declared-order tiebreaker.
- **Redactors**: each redactor against a character-class corpus
  (`%`, `+`, `&`, `=`, `:`, `/`, multi-byte UTF-8, very long values,
  empty values, repeated values).
- **CA manager**: cert generation, cache hit, cache eviction at
  expiry, rotation produces a different fingerprint.
- **Audit-log entry**: every required field present and
  type-correct.
- **LLM advisor**: schema validation rejects malformed JSON,
  elevation rejected, unknown modifier dropped, low confidence falls
  back.

### 19.2 Integration tests

- **Plain HTTP allow**: real `net/http` client with
  `HTTP_PROXY=http://127.0.0.1:<port>`; reach a stub origin; assert
  body returned.
- **Plain HTTP deny**: same, but with a deny rule; assert 470 +
  Trollbridge-Reason: declined.
- **CONNECT allow**: real client doing CONNECT; assert tunnel
  established.
- **CONNECT deny**: assert 470 to CONNECT.
- **CONNECT then HTTPS to stub**: full HTTPS-tunneled round trip.
- **TLS interception** (Phase 3): client with test CA installed;
  trollbridge intercepts; assert body modifier applied and audit log
  entry shape correct.
- **Audit log shape**: drive a known set of requests; parse JSONL;
  assert every required field per §15.2.
- **Rule reload (SIGHUP)**: send rules v1, request, assert decision;
  send rules v2, SIGHUP, request, assert different decision; audit log
  shows both `rule_set_version`s.
- **Approval flow** (Phase 2): trigger `ask_user`; assert hold; CLI
  approve; assert request unblocks.
- **Approval timeout**: trigger `ask_user`; do nothing; assert
  timeout deny.
- **LLM advisor unavailable** (Phase 4): mock LLM that returns 503;
  assert fallback per `llm.on_unavailable`.
- **LLM advisor elevation attempt** (Phase 4): mock LLM that returns
  `effect: allow` when rule said `ask_user`; assert effect remains
  `ask_user`. Specifically: a rule with `effect: ask_user` matches
  the request; the advisor (consulted via a request-shape match on
  a parallel `ask_llm` rule that fires later) returns
  `{"effect": "allow"}`; the engine MUST honor the earlier
  `ask_user` rule and the audit log MUST record both the `ask_user`
  resolution and the advisor's recommendation as a non-elevating
  hint.
- **ALPN h1 negotiation under interception** (Phase 3): point
  trollbridge at an h2-capable origin in intercept mode; verify that
  trollbridge negotiates `h1` on both sides and that the resulting
  request/response round-trips correctly.

### 19.3 Sweep tests

- **No plaintext secrets in audit log.** Drive requests whose bodies
  and headers contain `secret-XYZ`, `Bearer XYZ`, etc. After the
  test, `grep secret-XYZ audit.jsonl` MUST find zero matches.
- **No CA private key in any output.** Drive `trollbridge ca init`,
  `ca export`, `ca rotate`, then grep all written files for the
  private-key PEM marker; only `trollbridge-ca.key` MUST contain it.
- **Configuration reload coverage.** SIGHUP under various rule-file
  states (valid v2, malformed v2, identical to v1) — each behavior
  is asserted.

### 19.4 Deployment-contract tests (Phase 5)

- **Incus VM constraint test.** Stand up a test Incus VM with the
  recommended firewall profile; run a trollbridge instance on the
  host; from inside the VM attempt to `curl example.com` directly
  (without proxy env) — MUST fail with network unreachable. With
  proxy env set — MUST go through trollbridge.
- **Live build gate.** Per the global CI/IaC insight, the Phase 5
  closure deliverable is an *observed* end-to-end run on a real
  Incus host, recorded in the implementation note.

### 19.5 Performance benchmarks

- Plain HTTP latency overhead: `< 5ms` p95 on localhost (synthetic
  benchmark).
- CONNECT setup overhead: `< 10ms` p95.
- TLS interception per-host first-cert: `< 200ms` p95 (RSA 4096).
- TLS interception cached: `< 20ms` p95.

Each benchmark is recorded in the implementation note. The numbers
above are claims for the design; the implementer measures and either
confirms or revises.

### 19.6 Test runtime classification

trollbridge tests fall into four runtime classes; each class has a
matching test technology:

- Pure logic (rule engine, redactors) → in-process Go unit tests.
- Single-process wire behavior → in-process Go integration tests
  using `httptest` + a real proxy client.
- Multi-process / OS-trust-store behavior → subprocess tests that
  install the CA into a test-only trust store and run a real `curl`
  through the proxy.
- Incus / cross-machine behavior → scheduled-lane tests on Incus
  hosts (Phase 5).

A test that imports the proxy library and calls its functions does
NOT cover the wire runtime. The integration suite MUST exercise the
binary end-to-end.

---

## 20. Open questions and design tradeoffs

### 20.1 LLM provider lock-in

**Tradeoff.** Pinning to a specific LLM provider gets us a tighter
prompt and faster iteration. Provider-agnosticism gets us
substitutability and avoids tying the product to one vendor.

**Recommendation.** Provider-agnostic from day one; the advisor
component accepts any provider that returns JSON matching the §9.4
schema. The Phase 4 default is whichever Anthropic Claude model is
current at implementation time, because that is the trust boundary
the operator has already accepted by using these agents. Operators
MAY swap the default.

### 20.2 OPA/Rego vs. YAML rules

**Tradeoff.** YAML is readable but limited. Rego is expressive but
adds a dependency and a learning curve.

**Recommendation.** YAML for Phase 1–4. Phase 4+ adds an OPA
extension point behind the `Engine` interface; operators with
sophisticated policy needs can swap. For the typical agent use case
(a few dozen rules), YAML is enough.

### 20.3 In-process vs. out-of-process LLM advisor

**Tradeoff.** In-process keeps deployment simple. Out-of-process
isolates LLM crashes / memory pressure from the proxy.

**Recommendation.** In-process behind an interface. The interface
is the seam at which a future operator can extract the advisor into
a sidecar if scaling demands.

### 20.4 HTTP/2 in interception mode

**Tradeoff.** Speaking h2 on both client and origin requires
substantially more code (HPACK, stream multiplexing, server push).
Forcing h1 limits some origin behaviors (h2-only servers, server
push) but is simpler.

**Recommendation.** h1-only in Phase 3; document the limitation.
h2 lands in a later phase if usage demand justifies it.

### 20.5 What to do when the LLM disagrees with a rule

**Tradeoff.** When the LLM advisor recommends `deny` but a rule says
`allow`, who wins?

**Recommendation.** The rule wins, always. The advisor is
non-authoritative. The audit log records the advisor's
recommendation (so an operator who sees a series of "advisor said
deny" log entries can investigate whether the rule should be
narrowed).

### 20.6 Per-request vs. per-session decisions

**Tradeoff.** Per-request decisions are most defensive (every request
gets a fresh decision). Per-session caching is faster.

**Recommendation.** Decisions cache for `decisioncache.ttl_seconds`
(default 60). The cache is keyed by `(rule_set_version,
request_shape_hash)` so it cannot upgrade decisions across rule
changes. Operators concerned about defensive depth can set the TTL
to 0.

### 20.7 Should trollbridge proxy DNS too?

**Tradeoff.** DNS exfiltration is a real attack vector. Adding DNS
proxying expands scope but also expands the protection.

**Recommendation.** Out of scope for v1. Document the gap;
recommend that operators run a controlled DNS resolver for the agent
environment. A future trollbridge MAY add DNS proxying if user demand
justifies the complexity.

### 20.8 Should the proxy auto-suggest rules?

**Tradeoff.** "After a request is approved, suggest a rule" sounds
ergonomic. It also lets the LLM (indirectly) write its own rules
even when the surfacing is "advisory": the suggestion is in the
operator's eyeline, the operator clicks accept, the LLM has just
moved a host into the allow list.

**Recommendation.** The advisor produces no rule-suggestion
output. Per `docs/alignment-principles.md` §1, list authorship is
human-only — directly editing `trollbridge.yaml`, via TUI/CLI
commands, or via the approval-persist flow when the operator
approves a held request. The LLM has no field in its response
shape that names or implies a list mutation.

### 20.9 Should the proxy have a web UI?

**Tradeoff.** A web UI for approvals and log review is more
discoverable than a CLI. It is also another attack surface, more
code, and an additional thing the operator has to authenticate.

**Recommendation.** Phase 1–5 ship CLI-only. A separate project MAY
build a web UI on top of trollbridge's HTTP control API later. This
keeps trollbridge's surface area focused.

### 20.10 Versioning the audit log schema

**Tradeoff.** Auditors want stable schemas; the design will evolve.

**Recommendation.** Every audit-log entry includes
`trollbridge_version` and `audit_schema_version` fields.
Schema changes bump `audit_schema_version`; replay tooling reads the
field and applies appropriate parsing. Removing fields from the
audit log is forbidden in a minor version; only added fields are
allowed without bumping the major.

---

*End of design document.*
