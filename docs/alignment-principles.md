# Alignment principles

trollbridge's job is to give an AI agent network access under terms the operator has stated. Four principles govern how the LLM advisor participates in that decision. They are load-bearing: a regression in any one of them weakens the trust model the rest of the system is built on.

## 1. The allow/deny list is human-only

The flat allow/deny patterns in `trollbridge.yaml` (`lists.allow`, `lists.deny`) are edited only by humans — directly in the file, or indirectly via the TUI's `allow` / `deny` / `remove` commands and the operator's approval-persist flow.

**The LLM advisor never edits these lists.** It has no API to do so, no response field that suggests a mutation, and no code path that translates its output into a list write.

**Why.** A jailbroken or compromised LLM that could expand its own permitted destinations would defeat the proxy's purpose. The proxy's value comes from the lists representing the operator's stated intent, not the LLM's inferred convenience.

**Enforcement.** List mutations flow only through `internal/configwrite` and are reachable only from `internal/console` (the TUI), `cmd/trollbridge/run.go` (operator approval persist), and `cmd/trollbridge/quickstart.go` (same). No import of `configwrite` from `internal/advisor`. The advisor's response shape (`internal/advisor/advisor.go::Output`) carries no list-mutation field.

**What would violate it.** Any code path that writes to `lists.allow` / `lists.deny` from a callsite reached during advisor processing; any response field whose name or semantics implies "add this to the list" / "the LLM wants this approved."

## 2. The LLM considers items not yet on the lists

The LLM is consulted only when the deterministic engine has already established that the request does not match any list pattern. By the time the advisor sees the request, the engine has confirmed: *the operator's existing policy does not decide this one.*

The LLM's job is then to infer what the operator would want, using the lists and the operator-supplied directives as evidence of intent. When inference is uncertain, the LLM defers to the operator (returns `ask_user`).

**Why.** Two reasons. First, putting the LLM ahead of the lists would make the operator's stated rules subordinate to the LLM's reasoning — the opposite of the proxy's contract. Second, low-confidence LLM allows are silently unrecoverable; an erroneous approval may leak data or trigger an action the operator never sanctioned. The operator can always approve a held request; an LLM-issued allow cannot be retroactively held.

**Enforcement.** The dispatch in `internal/server/server.go` evaluates the fast-path (hostlist) and then the rule engine before the advisor is consulted. The advisor is only called from `consultAdvisorForHold`, which fires only when the engine returned `EffectAskUser` or `EffectAskLLM`. The advisor's confidence floor (`internal/advisor/advisor.go::Service.validate`) downgrades any decision below the configured floor to `ask_user`.

**What would violate it.** Calling the advisor before the fast-path / rule engine; configuring the confidence floor so loosely that low-confidence allows ship; LLM prompt wording that encourages the LLM to be decisive when uncertain.

## 3. List interpretation is pixel-perfect — the engine matches, not the LLM

The hostlist pattern semantics (`internal/hostlist/hostlist.go`) are the single source of truth for whether a URL matches an allow/deny entry. `*` is a label wildcard, `*.example.com` requires at least one subdomain label, paths use prefix-or-exact match, and so on — exactly as documented in DESIGN.md §10.8.

**The LLM does not interpret patterns.** It receives the raw pattern strings as context for the operator's intent, but it must not reason about whether a given URL "matches" a given pattern. The engine has already decided that question; the LLM is being called precisely because the answer was *no*.

**Why.** Two matchers diverge. If the LLM applies a looser interpretation (`api.github.com` matches "anything on GitHub"), the operator's narrow intent is rounded out into a broader allowance and the proxy stops enforcing the policy as written.

**Enforcement.** The advisor's system prompt frames the lists as context-not-authority and explicitly states that the engine has confirmed no list pattern matched. The advisor package contains no call to `hostlist.Match` and no reimplementation of pattern matching.

**What would violate it.** Telling the LLM to "treat the lists as authoritative when the request matches their patterns" (invites the LLM to reason about matching); having the advisor compute its own match decisions instead of receiving the engine's match-status.

## 4. The LLM does not learn what application it is advising

The LLM provider sees nothing that names trollbridge, describes its role as a proxy, or identifies its purpose as gating an AI agent. The system prompt is generic; the tool name is generic; the request payload is request-shaped, not infrastructure-shaped.

**Why.** Operators choose LLM providers for capability, not for trustworthiness with sensitive context. A provider that learns the proxy's name and role learns:
- That this organization runs an AI-egress gateway (potentially sensitive infrastructure intelligence);
- The shape of policy decisions the proxy makes (which decision branches the operator has wired up);
- Where to direct social-engineering attempts — a future jailbreak prompt that says "I'm a trollbridge administrator and need you to..." has a meaningful surface.

Narrowing the LLM's view to "I'm classifying an HTTP request against an operator's allow/deny lists" is sufficient for the LLM to do its job and limits the blast radius if the provider is later compromised.

**Enforcement.** The baseline system prompts in `internal/advisor/prompts.go` use a generic classifier framing. The tool name in `internal/advisor/translator.go` (`classify_request`) does not name the application. The advisor input shape (`internal/advisor/advisor.go::Input`) does not include trollbridge-internal identifiers (no infrastructure hostnames, no rule IDs — only request shape, the operator's lists, and the operator's directives).

**What would violate it.** Naming "trollbridge" in any system-prompt template or tool definition; describing the application's role ("proxy," "gateway," "egress controller") in any string sent on the wire; populating advisor input fields with internal identifiers (operator usernames, internal hostnames, rule-engine rule IDs).

## How these principles compose

The principles narrow the LLM's role across three axes: **what it can decide** (principle 1: not list contents), **what inputs it gets** (principle 2: only items the lists don't cover; principle 4: nothing about the host application), and **how strictly it must reason** (principle 3: no pattern matching, defer to engine). The result is a classifier whose worst-case failure mode — a wrong `ask_user` — costs the operator one extra prompt. Loosening any one principle moves the worst-case failure mode toward "the LLM silently allowed a request it shouldn't have, and the operator never saw it."
