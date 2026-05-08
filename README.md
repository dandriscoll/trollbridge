# drawbridge

An LLM-powered HTTP/HTTPS proxy that lets LLM agents reach network
resources under controlled, inspectable, policy-governed conditions.

The proxy is implemented in Go: a single static binary, no runtime
deps.

- [`DESIGN.md`](DESIGN.md) — full design document.
- [`AGENTS.md`](AGENTS.md) — instructions for an LLM coding agent
  asked to set up drawbridge for you.
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
[releases page](https://github.com/dandriscoll/drawbridge/releases).

```sh
# Replace v0.1.0 and the os/arch with the current release.
curl -L -o drawbridge.tar.gz \
  https://github.com/dandriscoll/drawbridge/releases/download/v0.2.0/drawbridge_v0.2.0_linux_amd64.tar.gz
# Verify against the release's SHA256SUMS file before extracting.
tar -xzf drawbridge.tar.gz
sudo install -m 0755 drawbridge_v0.2.0_linux_amd64/drawbridge /usr/local/bin/drawbridge
drawbridge version
```

## Build from source

Requires Go 1.26+.

```sh
git clone https://github.com/dandriscoll/drawbridge.git
cd drawbridge
make build
./bin/drawbridge --help
./bin/drawbridge init -d ~/.drawbridge
./bin/drawbridge validate -c ~/.drawbridge/drawbridge.yaml
./bin/drawbridge run -c ~/.drawbridge/drawbridge.yaml
```

For verbose per-request operational output:

```sh
./bin/drawbridge run -c ~/.drawbridge/drawbridge.yaml --verbose
# or, equivalently:
./bin/drawbridge --log-level=debug run -c ~/.drawbridge/drawbridge.yaml
# or, via env (works for any subcommand):
DRAWBRIDGE_LOG_LEVEL=debug ./bin/drawbridge run -c ~/.drawbridge/drawbridge.yaml
```

Operational lines carry a `request_id=` field that correlates with
the same field in the audit log.

Then in another shell, wire the client's proxy env:

```sh
eval "$(drawbridge env -c ~/.drawbridge/drawbridge.yaml)"
curl https://example.com   # subject to your policy
```

`drawbridge env` reads the listen address from your config and emits
the upper- and lowercase `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`
exports a client needs.

## Approvals TUI

When the policy holds a request for operator approval, list and
resolve held requests in real time with:

```sh
drawbridge tui -c ~/.drawbridge/drawbridge.yaml
```

Keys: `a` approve · `d` deny · `↑↓` (or `j`/`k`) select · `r` refresh
now · `q` quit. The list refreshes automatically as the queue
changes; one-shot `drawbridge approve <id>` / `drawbridge deny <id>`
remain available for scripted use.

## Configuration (schema v2)

`drawbridge.yaml` is organised around four operator decisions:

1. **`adapter`** — which network interface the daemon binds to
   (`lo` / `0.0.0.0` / a literal IP). Proxy, control plane, and
   metrics all bind on the same adapter; per-surface ports live
   under `ports:`.
2. **`lists`** — inline `allow:` / `deny:` patterns. The console
   REPL writes back to drawbridge.yaml; comments outside `lists:`
   survive. Each entry is `host[:port][/path]` with an optional
   `<scheme>://` prefix and `*` wildcards.
3. **`llm`** — provider / model / endpoint / api-key.
4. **`llm.directives`** — inline multi-line system prompt for the
   advisor.

The control plane requires mTLS, signed by the same CA used for
TLS interception. First-run ritual:

```sh
./bin/drawbridge ca init                         # generate the CA
./bin/drawbridge ca client-cert <op-name>        # mint your client cert
mv <op-name>.crt ~/.drawbridge/controller-client.crt
mv <op-name>.key ~/.drawbridge/controller-client.key
```

The CLI auto-loads the cert/key from `~/.drawbridge/`; override with
`DRAWBRIDGE_CONTROLLER_CERT` / `DRAWBRIDGE_CONTROLLER_KEY`.

For TLS interception (separate from controller mTLS — same CA):

```sh
# install drawbridge-ca.crt into your *client* trust store
# set interception.enabled: true in drawbridge.yaml
```

When `drawbridge run` is interactive, it presents a console
prompt for live edits to `lists.allow` / `lists.deny` in
drawbridge.yaml:

```
drawbridge> allow api.github.com
added api.github.com to allow (3 patterns total)
drawbridge> list allow
allow:
  127.0.0.1
  api.github.com
  localhost
(3 patterns)
```

Mutations write back to drawbridge.yaml in place via a
yaml.v3 Node-API edit — comments outside the `lists:`
subtree survive. The running daemon re-parses the file
after each mutation. List mutation is human-only — the
LLM advisor cannot modify `lists.allow` / `lists.deny`
under any circumstance.

See `docs/deploy.md` for deployment recipes and `DESIGN.md` for
the full specification.

## License

[MIT](LICENSE).
