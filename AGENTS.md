# AGENTS.md

This repo has **two** agent-facing surfaces. Pick the one that
matches the agent's role.

## Configuring agent

An LLM-driven coding agent (Claude Code, Cursor, Aider, OpenAI
Codex, or similar) that has been asked to **set up and run**
trollbridge for the user.

→ [`docs/configuring-agent.md`](docs/configuring-agent.md)

Long-form workflow: Step 0 through Step 9 covering install, init,
allow/deny lists, LLM advisor, TLS interception, validation, and
hand-back to the user.

## Proxied agent

An LLM-driven agent whose own HTTP/HTTPS egress **goes through**
trollbridge — the agent is calling out to the network, the proxy
sits between it and the upstream.

→ [`docs/proxied-agent.md`](docs/proxied-agent.md)

Short, copy-pasteable system-prompt fragment naming the wire
contract (HTTP 470 / 471, `Trollbridge-Request-Id`, the no-reason-
on-wire rule, the CONNECT-decline opacity hazard).

## Two hosts, not one

Both surfaces start from the same load-bearing fact: trollbridge
has two distinct hosts in the general case.

- **Proxy host** — runs `trollbridge run`. Owns the CA private
  key, the audit log, the LLM API key file. Privileged operations
  happen here.
- **Consumer host** — runs apps that proxy through trollbridge.
  Owns a copy of the CA's public cert in its system trust store.

In `local` topology these are the same machine; in `local-vm` and
`remote` they are different. Each agent-facing file labels its
commands by host.
