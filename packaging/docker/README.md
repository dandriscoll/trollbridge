# trollbridge — container image

Build:

```sh
docker build -f packaging/docker/Dockerfile -t trollbridge:dev .
```

Run as a sidecar (compose example):

```yaml
services:
  trollbridge:
    image: trollbridge:dev
    volumes:
      - ./trollbridge.yaml:/etc/trollbridge/trollbridge.yaml:ro
      - ./trollbridge-ca.crt:/etc/trollbridge/trollbridge-ca.crt:ro
      - ./trollbridge-ca.key:/etc/trollbridge/trollbridge-ca.key:ro
      - ./audit:/var/log/trollbridge
    ports:
      - "127.0.0.1:8080:8080"   # proxy
      # - "127.0.0.1:8081:8081" # control plane (only enable if
      #                          # bearer-token auth is configured)
    networks:
      - shared
  agent:
    image: my-coding-agent:dev
    environment:
      HTTP_PROXY: "http://trollbridge:8080"
      HTTPS_PROXY: "http://trollbridge:8080"
      NO_PROXY: "localhost,127.0.0.1"
    volumes:
      - ./trollbridge-ca.crt:/etc/ssl/certs/trollbridge-ca.pem:ro
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

- A trollbridge.yaml `approvals.control_auth_mode: bearer` if you
  expose the control plane to anyone other than localhost.
- `interception.enabled: true` and a CA initialized via
  `trollbridge ca init`.
- `interception.passthrough_hosts` for cert-pinned origins.

The image runs as UID 65534. Bind-mounted host files must be
readable by that UID.
