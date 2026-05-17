<p align="center">
  <img src="trollbridge_icon.png" alt="trollbridge logo" width="160">
</p>

# trollbridge

[![release](https://img.shields.io/github/v/release/dandriscoll/trollbridge)](https://github.com/dandriscoll/trollbridge/releases)
[![ci](https://github.com/dandriscoll/trollbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/dandriscoll/trollbridge/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/dandriscoll/trollbridge)](LICENSE)
[![go](https://img.shields.io/github/go-mod/go-version/dandriscoll/trollbridge)](go.mod)

![trollbridge — LLM-Powered Proxy & Security Gateway for AI Agents](trollbridge_infographic.png)

> **Let your agents run amok — but only where you say.**

trollbridge is the proxy your local agent calls out through. Read,
write, and run files freely on your machine; reach the network only
where you've authorized. New destinations hold one keystroke from
approval. Implemented in Go: a single static binary, no runtime
deps.

## What it does

- **Read, write, run.** trollbridge does not gate local files or
  processes. Your agent has full filesystem and shell access.
- **Outbound only where you say.** HTTP and HTTPS requests are
  checked against allow/deny lists and rule policy. Matches pass
  through with audit-log entries; non-matches don't.
- **Hold the rest for one keystroke.** Unapproved destinations
  pause and surface in the operator UI. Press `a` to approve (the
  destination joins `lists.allow`), `d` to deny. The held request
  resumes — no agent restart, no retry loop.

## Where to go from here

Three paths in — pick the one that matches what you're doing:

- **An LLM agent is installing trollbridge for me.** Hand the agent
  this URL:
  **`https://github.com/dandriscoll/trollbridge/blob/main/SETUP-AGENT.md`**
  (or, locally, [`SETUP-AGENT.md`](SETUP-AGENT.md)). The agent reads
  that single file, asks a handful of goal-level questions (block
  exfiltration? review every new destination? audit only?), and runs
  install → configure → run → verify end-to-end on Linux, macOS, or
  Windows.
- **I'm installing trollbridge on my own machine.** Continue reading
  this README — install, run, and verify steps are below.
- **I'm deploying trollbridge to a host (or to several).** Read
  [`PROXY-SETUP-AGENT.md`](PROXY-SETUP-AGENT.md) for the operator
  install walk-through, then [`docs/deploy.md`](docs/deploy.md) for
  topology recipes (user-mode, Incus VM, container sidecar).

## Install

```sh
curl -fsSL https://trollbridge.dev/install.sh | sh
```

The script picks the right tarball for your OS and arch, verifies the
release's SHA256SUMS, and installs `trollbridge` to `/usr/local/bin`.
Run `trollbridge version` to confirm.

**Windows:** the `curl|sh` installer is Linux/macOS only. On
Windows, download `trollbridge_<version>_windows_amd64.exe` from
the [releases page](https://github.com/dandriscoll/trollbridge/releases)
or follow the PowerShell snippet in
[`SETUP-AGENT.md`](SETUP-AGENT.md). Only user-mode is supported on
Windows.

Pre-built binaries for Linux and macOS (amd64 and arm64) are also
attached to each tagged release. The most recent build:
[`trollbridge_v0.7.14_linux_amd64.tar.gz`](https://github.com/dandriscoll/trollbridge/releases/download/v0.7.14/trollbridge_v0.7.14_linux_amd64.tar.gz)
— verify against that release's SHA256SUMS, extract, and
`sudo install -m 0755 trollbridge_v0.7.14_linux_amd64/trollbridge /usr/local/bin/trollbridge`.

## Run

```sh
trollbridge quickstart     # writes a minimal yaml + starts the proxy
# — or, for the interactive setup wizard:
trollbridge init           # picks user-mode or daemon-mode, asks a few questions
trollbridge run            # listens on 127.0.0.1:8080
```

`run` prints a copy-pasteable "try this next" banner with the
listen address and the quickest test recipe.

## Verify

In another shell:

```sh
trollbridge test https://example.com
# or, for any HTTP client in this shell:
eval "$(trollbridge env)" && curl -sI https://example.com
```

`trollbridge env` reads the listen address from `trollbridge.yaml`
in the current directory and emits the standard `HTTPS_PROXY` /
`HTTP_PROXY` / `NO_PROXY` exports (upper- and lowercase).

For verbose per-request operational output, run with `--verbose`,
`--log-level=debug`, or `TROLLBRIDGE_LOG_LEVEL=debug`. Operational
lines carry a `request_id=` field that correlates with the audit
log.

## Build from source

Requires Go 1.26+. See [`AGENTS.md`](AGENTS.md) for build and test
conventions.

```sh
git clone https://github.com/dandriscoll/trollbridge.git
cd trollbridge
make build
./bin/trollbridge quickstart
```

## Where to go next

- [`SETUP-AGENT.md`](SETUP-AGENT.md) — agentic onboarding (single
  entry for an LLM agent doing the install for you).
- [`PROXY-SETUP-AGENT.md`](PROXY-SETUP-AGENT.md) — operator install
  walk-through (CA, mTLS controller, TLS interception, two-host
  topologies).
- [`CLIENT-SETUP-AGENT.md`](CLIENT-SETUP-AGENT.md) — point an agent's
  own egress at a running trollbridge.
- [`PROXIED-AGENT.md`](PROXIED-AGENT.md) — system-prompt fragment
  for an agent whose egress *goes through* trollbridge.
- [`docs/deploy.md`](docs/deploy.md) — deployment recipes
  (user-mode, Incus VM, container sidecar).
- [`docs/operator-ui.md`](docs/operator-ui.md) — operator UI keymap,
  daemon mode, attach, CI validation (`trollbridge validate`).
- [`docs/self-describing.md`](docs/self-describing.md) — proxy
  bootstrap endpoints (`config.trollbridge.dev/*`).
- [`docs/alignment-principles.md`](docs/alignment-principles.md) —
  the four principles governing the LLM advisor's role.
- [`config.example.yaml`](config.example.yaml) — annotated
  configuration schema.
- [`rules/base.example.yaml`](rules/base.example.yaml) — structured
  rules (for advanced cases).
- [`llmtest/README.md`](llmtest/README.md) — LLM-advisor regression-
  testing framework.
- [`DESIGN.md`](DESIGN.md) — full design document.
- [`AGENTS.md`](AGENTS.md) — for coding agents working *on* the
  trollbridge codebase (build, test, conventions).
- [`packaging/`](packaging/) — systemd unit, Dockerfile, Incus
  cloud-init, firewall snippets.

## License

[MIT](LICENSE).
