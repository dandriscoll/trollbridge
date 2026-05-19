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

## Pair with a sandbox

**Worried about running your agent in yolo mode? Pair trollbridge with a sandbox.**

trollbridge gates *network egress* — what your agent reaches over HTTP and HTTPS. It does NOT gate the local filesystem or processes; the agent reads, writes, and runs anything on the machine it's on. That is the trade you make for keeping the agent productive. The matching half of the trade is bounding what "the machine it's on" means.

A handful of starting points, ordered by how directly trollbridge supports them:

- **[Incus VM (Linux)](docs/deploy.md#incus-vm-with-host-side-proxy-recommended)** — the documented happy path. Run the agent inside the VM; run trollbridge on the host; firewall the VM so its only egress is the proxy. `packaging/incus/launch.sh` walks the setup.
- **Linux containers** ([Podman rootless](https://podman.io/) or [LXC](https://linuxcontainers.org/)) — when "VM" is overkill and a container's isolation profile is enough. CI runners often land here.
- **macOS** — [Lima](https://lima-vm.io/), [OrbStack](https://orbstack.dev/), [Tart](https://tart.run/), or [Multipass](https://multipass.run/) all give you a Linux VM to run the agent in; trollbridge runs on the macOS host.
- **Windows** — [WSL2](https://learn.microsoft.com/windows/wsl/) is the common path (run the agent in a WSL distro, run trollbridge on Windows). For stronger isolation, use a Hyper-V VM.

Already running your agent under isolation you trust? trollbridge layers on top — point the agent's `HTTPS_PROXY` at the daemon and the existing isolation stays load-bearing. Already chose not to use a sandbox? That's a real choice; trollbridge's hold-and-approve flow and the audit log are the safety net for that path. Either way, the link to follow next is [`docs/deploy.md`](docs/deploy.md).

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
  [`trollbridge_v0.7.16_linux_amd64.tar.gz`](https://github.com/dandriscoll/trollbridge/releases/download/v0.7.16/trollbridge_v0.7.16_linux_amd64.tar.gz)
  (or the matching `windows_amd64.exe` / `darwin_*` build) from the
  [releases page](https://github.com/dandriscoll/trollbridge/releases),
  verify against SHA256SUMS, extract, and
  `sudo install -m 0755 trollbridge_v0.7.16_linux_amd64/trollbridge /usr/local/bin/trollbridge`.
- **Deploying to a host or fleet.** [`PROXY-SETUP-AGENT.md`](PROXY-SETUP-AGENT.md) walks the operator install (CA, mTLS, TLS interception); [`docs/deploy.md`](docs/deploy.md) covers topologies (user-mode, Incus VM, container sidecar).
- **Pointing an agent's egress at a running trollbridge.** [`CLIENT-SETUP-AGENT.md`](CLIENT-SETUP-AGENT.md).
- **Operator UI keymap, daemon mode, audit log correlation (`request_id=`).** [`docs/operator-ui.md`](docs/operator-ui.md). Verbose per-request logs: `--verbose`, `--log-level=debug`, or `TROLLBRIDGE_LOG_LEVEL=debug`.
- **Building from source / contributing.** [`AGENTS.md`](AGENTS.md). Requires Go 1.26+.

## License

[MIT](LICENSE).
