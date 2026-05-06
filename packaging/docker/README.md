# drawbridge — container image

Build:

```sh
docker build -f packaging/docker/Dockerfile -t drawbridge:dev .
```

Run as a sidecar (compose example):

```yaml
services:
  drawbridge:
    image: drawbridge:dev
    volumes:
      - ./drawbridge.yaml:/etc/drawbridge/drawbridge.yaml:ro
      - ./drawbridge-ca.crt:/etc/drawbridge/drawbridge-ca.crt:ro
      - ./drawbridge-ca.key:/etc/drawbridge/drawbridge-ca.key:ro
      - ./audit:/var/log/drawbridge
    ports:
      - "127.0.0.1:8080:8080"   # proxy
      # - "127.0.0.1:8081:8081" # control plane (only enable if
      #                          # bearer-token auth is configured)
    networks:
      - shared
  agent:
    image: my-coding-agent:dev
    environment:
      HTTP_PROXY: "http://drawbridge:8080"
      HTTPS_PROXY: "http://drawbridge:8080"
      NO_PROXY: "localhost,127.0.0.1"
    volumes:
      - ./drawbridge-ca.crt:/etc/ssl/certs/drawbridge-ca.pem:ro
    networks:
      - shared

networks:
  shared:
    internal: true   # block direct egress; only the sidecar can leave
```

The `internal: true` network is the binding constraint: with it,
the agent container can only reach the sidecar. Without it, the
proxy is decorative (DESIGN.md §17.2).

For a real deployment also configure:

- A drawbridge.yaml `approvals.control_auth_mode: bearer` if you
  expose the control plane to anyone other than localhost.
- `interception.enabled: true` and a CA initialized via
  `drawbridge ca init`.
- `interception.passthrough_hosts` for cert-pinned origins.

The image runs as UID 65534. Bind-mounted host files must be
readable by that UID.
