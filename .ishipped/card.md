---
title: "trollbridge"
summary: "An LLM-powered HTTP/HTTPS proxy that lets AI agents reach the network under controlled, inspectable, policy-governed conditions."
icon: "./trollbridge_icon.png"
hero: "./trollbridge_infographic.png"
shipped: 2026-05-06
version: "0.6.0"
tags:
  - ai-agents
  - proxy
  - security
  - llm
  - go
  - policy
author:
  name: "Dan Driscoll"
  github: "dandriscoll"
links:
  - label: "Releases"
    url: "https://github.com/dandriscoll/trollbridge/releases"
    primary: true
  - label: "Design Doc"
    url: "https://github.com/dandriscoll/trollbridge/blob/main/DESIGN.md"
  - label: "Deployment Recipes"
    url: "https://github.com/dandriscoll/trollbridge/blob/main/docs/deploy.md"
---

## What is trollbridge?

trollbridge is an HTTP/HTTPS forward proxy purpose-built for AI agents.
It sits between an agent and the internet so every outbound request is
inspected, classified against policy, and either allowed, denied, or
held for human approval — with an LLM advisor recommending the call in
real time.

Single static Go binary. No runtime dependencies.

## Why a bridge for trolls?

Agents are powerful and unpredictable. Letting one roam the network
with raw egress is a footgun: prompt injection, exfiltration, runaway
loops, and credentials in the wrong place are all one tool-call away.
trollbridge gives operators a single chokepoint with:

- **Deterministic allow/deny lists** — the simple authoring surface
  for the 95% case, edited live from the operator UI.
- **Structured rules** — for the advanced cases that lists can't
  express.
- **LLM advisor** — every held request gets an independent
  recommendation (with reasoning) from a separate LLM, in parallel
  with the human operator.
- **Real-time approvals** — a two-pane TUI with a queue of pending
  holds and a typed console; manual decisions are sticky and
  persisted back to the YAML.
- **TLS interception** — optional MITM CA so HTTPS bodies can be
  inspected, not just hostnames.
- **JSONL audit log** — every request, decision, and rationale,
  correlatable by `request_id`.

## Quick start

```sh
# Grab a release binary, then:
./bin/trollbridge quickstart   # writes a minimal yaml + starts the proxy

# In another shell:
eval "$(trollbridge env)" && curl -sI https://example.com
```

When `trollbridge run` starts on a terminal, it draws an operator UI
in the alt-screen: pending holds in the upper pane (`a` approve, `d`
deny), a typed console in the lower pane (`allow`, `deny`, `list`,
`reload`, `doctor`, …). Pressing `a` or `d` writes the URL pattern
back to `lists.allow` / `lists.deny` so the next request to the same
URL skips the queue.

## Topology

trollbridge has two hosts in the general case:

- **proxy host** — runs `trollbridge run`. Owns the CA private key
  and the audit log.
- **consumer host** — any machine whose egress goes through the
  proxy. Owns the CA's public cert in its trust store.

For local development they collapse onto the same machine. For shared
agent fleets, the proxy lives on its own host and consumers attach
over mTLS.

## Self-describing endpoints

Once `trollbridge run` is up, an agent with only the proxy's address
can bootstrap itself: the proxy intercepts `Host: config.trollbridge.dev`
and serves bundled setup docs, environment exports, and the CA cert
directly — no DNS, no out-of-band file copying.

## Status

v0.6.0 ships LLM-advisor split (review vs. research modes),
per-request LLM consultation in parallel with the operator, Windows
amd64/arm64 release builds, and a refined SIGWINCH-driven resize
watcher in the TUI. MIT-licensed.
