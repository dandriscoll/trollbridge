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
approval. Single static Go binary, no runtime deps.

## What it does

- **Read, write, run.** trollbridge does not gate local files or
  processes. Your agent has full filesystem and shell access.
- **Outbound only where you say.** HTTP and HTTPS requests are
  checked against allow/deny lists and rule policy.
- **Hold the rest for one keystroke.** Unapproved destinations
  pause and surface in the operator UI. Press `a` to approve, `d`
  to deny. The held request resumes — no agent restart.

## Get started

**Try it** — install and run on your own machine (Linux or macOS):

```sh
curl -fsSL https://trollbridge.dev/install.sh | sh
trollbridge quickstart     # writes a minimal yaml + starts the proxy
trollbridge test https://example.com
```

Then point any HTTP client at it:

```sh
eval "$(trollbridge env)" && curl -sI https://example.com
```

**Have an agent set it up** — hand your LLM agent
[`SETUP-AGENT.md`](SETUP-AGENT.md) (or the raw URL
`https://github.com/dandriscoll/trollbridge/blob/main/SETUP-AGENT.md`).
It asks a few goal-level questions and runs install → configure →
verify end-to-end on Linux, macOS, or Windows.

**Read how it works** — start at
[trollbridge.dev](https://trollbridge.dev), then
[`DESIGN.md`](DESIGN.md) for the full spec.

## More

- **Windows or direct download.** Grab
  [`trollbridge_v0.7.14_linux_amd64.tar.gz`](https://github.com/dandriscoll/trollbridge/releases/download/v0.7.14/trollbridge_v0.7.14_linux_amd64.tar.gz)
  (or the matching `windows_amd64.exe` / `darwin_*` build) from the
  [releases page](https://github.com/dandriscoll/trollbridge/releases),
  verify against SHA256SUMS, extract, and
  `sudo install -m 0755 trollbridge_v0.7.14_linux_amd64/trollbridge /usr/local/bin/trollbridge`.
- **Deploying to a host or fleet.** [`PROXY-SETUP-AGENT.md`](PROXY-SETUP-AGENT.md) walks the operator install (CA, mTLS, TLS interception); [`docs/deploy.md`](docs/deploy.md) covers topologies (user-mode, Incus VM, container sidecar).
- **Pointing an agent's egress at a running trollbridge.** [`CLIENT-SETUP-AGENT.md`](CLIENT-SETUP-AGENT.md).
- **Operator UI keymap, daemon mode, audit log correlation (`request_id=`).** [`docs/operator-ui.md`](docs/operator-ui.md). Verbose per-request logs: `--verbose`, `--log-level=debug`, or `TROLLBRIDGE_LOG_LEVEL=debug`.
- **Building from source / contributing.** [`AGENTS.md`](AGENTS.md). Requires Go 1.26+.

## License

[MIT](LICENSE).
