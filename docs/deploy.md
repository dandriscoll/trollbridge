# Deploying trollbridge

Pre-implementation note: trollbridge is implemented through Phase 5
of the design plan. The recipes below have been authored but a
load-bearing live-build observation in a real Incus environment
is the operator's deliverable. Treat the recipes as starting
points to adapt to your environment.

## Topology choice

Per `DESIGN.md` §14 the four supported topologies are:

| Topology | Best for | Strength |
|---|---|---|
| Local laptop | Developer flow | Audit log; weak isolation |
| Incus VM, host-side proxy | Coding agents in dev/CI | Strong isolation if firewall is binding |
| Sidecar container | CI runners, ephemeral agents | Strong isolation via internal: true network |
| System-wide host daemon | Shared agent network | Isolation only as good as per-agent identity |

**The proxy is theatrical without a binding firewall.** The
agent's environment MUST be configured so direct network egress
goes nowhere except trollbridge.

## Quickstart: local laptop

```sh
make build                                # build bin/trollbridge
./bin/trollbridge init -d ~/.trollbridge    # creates yaml + rules
./bin/trollbridge validate -c ~/.trollbridge/trollbridge.yaml
./bin/trollbridge run -c ~/.trollbridge/trollbridge.yaml
```

In another shell:

```sh
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
curl http://example.com    # if declined by default-deny, expect HTTP 470
```

## Incus VM with host-side proxy (recommended)

1. On the host:

   ```sh
   sudo install -d -o trollbridge -g trollbridge -m 0755 /etc/trollbridge
   ./bin/trollbridge ca init \
     --cert-out /etc/trollbridge/trollbridge-ca.crt \
     --key-out  /etc/trollbridge/trollbridge-ca.key
   sudo cp packaging/systemd/trollbridge.service /etc/systemd/system/
   sudo systemctl enable --now trollbridge
   ```

2. Apply the firewall snippet:

   ```sh
   AGENT_VM_IP=10.10.10.5 \
   PROXY_LISTEN=10.10.10.1:8080 \
   DNS_RESOLVER=10.10.10.1:53 \
   sudo ./packaging/firewall/iptables.sh
   ```

3. Launch the agent VM:

   ```sh
   HOST_IP=10.10.10.1 \
   CA_PATH=/etc/trollbridge/trollbridge-ca.crt \
   ./packaging/incus/launch.sh agent-vm
   ```

4. Inside the VM:

   ```sh
   trollbridge selftest --from-vm
   # expect: direct outbound BLOCKED, via-proxy ok, CA trusted
   ```

## Container sidecar

See `packaging/docker/README.md`. Key points:

- Use a network with `internal: true` so the agent container
  can only reach the sidecar.
- Mount `trollbridge-ca.crt` into the agent's trust store.
- Set `HTTP_PROXY` / `HTTPS_PROXY` in the agent's env.
- `127.0.0.1:8080` for proxy; control plane port (default
  `:8081`) is **only** safe to expose if you have configured
  `approvals.control_auth_mode: bearer`.

## Control-plane authentication

The control plane (default `127.0.0.1:8081`) exposes approve /
deny / sessions / rules-reload. Anyone who can reach it can
approve held requests and reload the rule set.

For non-localhost binds, you MUST configure bearer-token auth:

```yaml
approvals:
  control_listen: 0.0.0.0:8081
  control_auth_mode: bearer
  control_bearer_token_sha256: "<sha256 hex of your token>"
```

Compute the hash:

```sh
echo -n "your-secret-token" | sha256sum | cut -d' ' -f1
```

Then operators authenticate with `Authorization: Bearer
your-secret-token`. The CLI subcommands (`approve`, `deny`,
`sessions`, `rules reload`) currently do NOT send this header
automatically; configure your operator workflow to wrap them
with curl + the right header for now (CLI bearer support is a
follow-up).

## Origin trust

Origin TLS verification uses the system trust store by
default. For environments behind a corporate CA:

```yaml
interception:
  enabled: true
  origin_trust:
    mode: mixed         # system | file | mixed
    path: /etc/trollbridge/corporate-ca.pem
```

`mode: file` uses **only** the supplied PEM, not the system
roots. `mode: mixed` uses both.

## Logs and audit

- Audit log: JSONL at `logging.audit_path`. One entry per
  decision. Mode 0640.
- Operational log: leveled (debug | info | warn | error). Sink is
  stderr by default; set `logging.operational_path: /path/to/file`
  to send it to a file (mode 0640, parent dir 0750, fail-closed at
  startup if unwritable). When the sink is a file, the systemd
  journal stream goes silent — operators who want both should run
  the binary under `tee` or accept the file as their canonical
  source.
- Raise verbosity for diagnosis: `trollbridge run --verbose`,
  `trollbridge --log-level=debug run …`, or
  `TROLLBRIDGE_LOG_LEVEL=debug` in the environment. At debug level
  every request emits per-phase records keyed by `request_id=`,
  which correlates against the same field in the audit log.
- Tail compactly: `trollbridge logs tail`.
- Replay: `trollbridge logs replay --rules /path/to/strict.yaml -v`
  re-runs decisions over the audit log against a new rule set
  and reports flips. (`-v` here is replay-local — it shows each
  flipped decision; it does not raise the operational log level.)

## Performance baseline

Sample local-host benchmark (`go test -bench`):

| Path | ns/op | µs/op |
|---|---|---|
| Plain HTTP allow round-trip | ~73,000 | ~73 |

Well under the DESIGN.md §19.5 < 5 ms claim for plain HTTP
overhead. Numbers vary; re-run on your hardware.
