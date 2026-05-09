<p align="center">
  <img src="trollbridge_icon.png" alt="trollbridge logo" width="160">
</p>

# trollbridge

![trollbridge — LLM-Powered Proxy & Security Gateway for AI Agents](trollbridge_infographic.png)

An LLM-powered HTTP/HTTPS proxy that lets LLM agents reach network
resources under controlled, inspectable, policy-governed conditions.

The proxy is implemented in Go: a single static binary, no runtime
deps.

- [`DESIGN.md`](DESIGN.md) — full design document.
- [`AGENTS.md`](AGENTS.md) — instructions for an LLM coding agent
  asked to set up trollbridge for you.
- [`docs/proxied-agent.md`](docs/proxied-agent.md) — short
  system-prompt fragment for an agent whose egress *goes through*
  trollbridge (separate audience from `AGENTS.md`).
- [`docs/deploy.md`](docs/deploy.md) — deployment recipes.
- [`config.example.yaml`](config.example.yaml) — annotated config;
  the simple authoring surface lives inline as `lists.allow` /
  `lists.deny`.
- [`rules/base.example.yaml`](rules/base.example.yaml) —
  structured rules (for the advanced cases).
- [`packaging/`](packaging/) — systemd unit, Dockerfile, Incus
  cloud-init, firewall snippets.

## Install

Pre-built binaries for Linux and macOS (amd64 and arm64) are
attached to each tagged release on the
[releases page](https://github.com/dandriscoll/trollbridge/releases).

```sh
curl -L -o trollbridge.tar.gz \
  https://github.com/dandriscoll/trollbridge/releases/download/v0.4.7/trollbridge_v0.4.7_linux_amd64.tar.gz
# Verify against the release's SHA256SUMS file before extracting.
tar -xzf trollbridge.tar.gz
sudo install -m 0755 trollbridge_v0.4.7_linux_amd64/trollbridge /usr/local/bin/trollbridge
trollbridge version
```

## Build from source

Requires Go 1.26+.

```sh
git clone https://github.com/dandriscoll/trollbridge.git
cd trollbridge
make build
./bin/trollbridge init        # interactive in a TTY; default config otherwise
./bin/trollbridge run         # listens on 127.0.0.1:8080
```

When `run` starts on a terminal, it prints a copy-pasteable
"try this next" banner naming the listen address and the
quickest test recipe.

In another shell, send a request through the proxy:

```sh
trollbridge test https://example.com
# or, for any HTTP client in this shell:
eval "$(trollbridge env)" && curl -sI https://example.com
```

`trollbridge env` reads the listen address from `trollbridge.yaml`
in the current directory and emits upper- and lowercase
`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` exports.

For verbose per-request operational output, run with `--verbose`,
`--log-level=debug`, or `TROLLBRIDGE_LOG_LEVEL=debug`. Operational
lines carry a `request_id=` field that correlates with the audit
log.

## Approvals TUI

When the policy holds a request for operator approval, list and
resolve held requests in real time with:

```sh
trollbridge tui -c ~/.trollbridge/trollbridge.yaml
```

Keys: `a` approve · `d` deny · `↑↓` (or `j`/`k`) select · `r` refresh
now · `q` quit. The list refreshes automatically as the queue
changes; one-shot `trollbridge approve <id>` / `trollbridge deny <id>`
remain available for scripted use.

## Configuration (schema v3)

`trollbridge.yaml` is organised around four operator decisions:

1. **per-surface bind** — each of `proxy:`, `control:`, `metrics:`
   is a single `<host>:<port>` string. Host aliases: `all` =
   `0.0.0.0`, `lo` = `127.0.0.1`. Bracket IPv6 literals
   (`[fd00::1]:8081`). Surfaces are independent, so the proxy
   can listen on `all:8080` while the control plane stays on
   `lo:8081`. `metrics: 0` disables the (unimplemented)
   Prometheus endpoint.
2. **`lists`** — inline `allow:` / `deny:` patterns. The console
   REPL writes back to trollbridge.yaml; comments outside `lists:`
   survive. Each entry is `host[:port][/path]` with an optional
   `<scheme>://` prefix and `*` wildcards.
3. **`llm`** — provider / model / endpoint / api-key. Provider
   selects the auth header: `anthropic` (default) sends
   `Authorization: Bearer …`; `aoai` (Azure OpenAI) sends
   `api-key: …`.
4. **`llm.directives`** — inline multi-line system prompt for the
   advisor.

Run `trollbridge doctor -c <path>` after editing the YAML — it
loads the config, parses the rules and lists, and (when LLM is
enabled) issues a real classification call so misconfigured
endpoints / keys / providers fail loud before `trollbridge run`.

The control plane requires mTLS, signed by the same CA used for
TLS interception. First-run ritual:

```sh
sudo trollbridge ca init                          # generates /etc/trollbridge/trollbridge-ca.{crt,key}
sudo trollbridge ca client-cert <op-name>         # mint your client cert
sudo mv <op-name>.crt ~/.trollbridge/controller-client.crt
sudo mv <op-name>.key ~/.trollbridge/controller-client.key
```

The CA always lives at `/etc/trollbridge/trollbridge-ca.{crt,key}` —
the canonical path is the same on every machine, so a config
shared across hosts works without per-host edits.

The CLI auto-loads the cert/key from `~/.trollbridge/`; override with
`TROLLBRIDGE_CONTROLLER_CERT` / `TROLLBRIDGE_CONTROLLER_KEY`.

For TLS interception (separate from controller mTLS — same CA):

```sh
# Local install (run on the same host as `trollbridge run`):
trollbridge ca install --apply        # searches canonical paths;
                                      # requires root (sudo)

# Remote install (consumer app on a different host than the proxy):
#   1. From the trollbridge host:
#        scp trollbridge-ca.crt user@consumer:/usr/local/share/ca-certificates/
#   2. From the consumer host:
#        sudo trollbridge ca install --apply

# Then enable interception:
#   set interception.enabled: true in trollbridge.yaml
```

`trollbridge ca install` searches `/etc/trollbridge/trollbridge-ca.crt`
(the canonical default; cross-machine stable) and
`/usr/local/share/ca-certificates/trollbridge-ca.crt`. Pass
`--cert <path>` to override; the printed install commands always
use the absolute form so they paste cleanly into any shell or any
machine.

When `trollbridge run` is interactive, it presents a console
prompt for live edits to `lists.allow` / `lists.deny` in
trollbridge.yaml:

```
trollbridge> allow api.github.com
added api.github.com to allow (3 patterns total)
trollbridge> list allow
allow:
  127.0.0.1
  api.github.com
  localhost
(3 patterns)
```

Mutations write back to trollbridge.yaml in place via a
yaml.v3 Node-API edit — comments outside the `lists:`
subtree survive. The running daemon re-parses the file
after each mutation. List mutation is human-only — the
LLM advisor cannot modify `lists.allow` / `lists.deny`
under any circumstance.

See `docs/deploy.md` for deployment recipes and `DESIGN.md` for
the full specification.

## License

[MIT](LICENSE).
