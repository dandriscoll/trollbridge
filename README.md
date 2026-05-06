# drawbridge

An LLM-powered HTTP/HTTPS proxy that lets LLM agents reach network
resources under controlled, inspectable, policy-governed conditions.

The proxy is implemented in Go: a single static binary, no runtime
deps. Phases 1–5 of the design plan have shipped (the live-build
observation in a real Incus environment is the operator's
deliverable; recipes below).

- [`DESIGN.md`](DESIGN.md) — full design document.
- [`docs/deploy.md`](docs/deploy.md) — deployment recipes.
- [`config.example.yaml`](config.example.yaml) — annotated config.
- [`rules/base.example.yaml`](rules/base.example.yaml) — example rules.
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

## Status

Phases 1–5 implemented. See `docs/deploy.md` for production
deployment recipes and `DESIGN.md` for the full specification.

## License

[MIT](LICENSE).
