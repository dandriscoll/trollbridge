# drawbridge

An LLM-powered HTTP/HTTPS proxy that lets LLM agents reach network
resources under controlled, inspectable, policy-governed conditions.

The proxy is implemented in Go: a single static binary, no runtime
deps.

- [`DESIGN.md`](DESIGN.md) — full design document.
- [`AGENTS.md`](AGENTS.md) — instructions for an LLM coding agent
  asked to set up drawbridge for you.
- [`docs/deploy.md`](docs/deploy.md) — deployment recipes.
- [`config.example.yaml`](config.example.yaml) — annotated config.
- [`allow.example.txt`](allow.example.txt) /
  [`deny.example.txt`](deny.example.txt) — flat allow/deny
  lists (the simple authoring surface; see DESIGN.md §10.8).
- [`rules/base.example.yaml`](rules/base.example.yaml) —
  structured rules (for the advanced cases).
- [`packaging/`](packaging/) — systemd unit, Dockerfile, Incus
  cloud-init, firewall snippets.

## Quickstart

```sh
make build
./bin/drawbridge --help
./bin/drawbridge init -d ~/.drawbridge
./bin/drawbridge validate -c ~/.drawbridge/drawbridge.yaml
./bin/drawbridge run -c ~/.drawbridge/drawbridge.yaml
```

Then in another shell:

```sh
export HTTPS_PROXY=http://127.0.0.1:8080
curl https://example.com   # subject to your policy
```

For TLS interception:

```sh
./bin/drawbridge ca init   # writes drawbridge-ca.{crt,key}
# install drawbridge-ca.crt into your client trust store
# set interception.enabled: true in drawbridge.yaml
```

When `drawbridge run` is interactive, it presents a console
prompt for live edits to the flat allow / deny lists:

```
drawbridge> allow api.github.com
added api.github.com to allow.txt (3 patterns total)
drawbridge> list allow
allow:
  127.0.0.1
  api.github.com
  localhost
(3 patterns)
```

The console writes are sorted (§10.8.3); the file watcher
(§10.8.2) picks up out-of-band edits within ~1 second.
List mutation is human-only — the LLM advisor cannot modify
allow.txt or deny.txt under any circumstance.

See `docs/deploy.md` for deployment recipes and `DESIGN.md` for
the full specification.

## License

[MIT](LICENSE).
