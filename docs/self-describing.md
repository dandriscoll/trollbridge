# Self-describing endpoints

Once `trollbridge run` is up, an agent that has only the proxy's
address can fetch everything else it needs to bootstrap from the
proxy itself. The proxy intercepts requests where
`Host: config.trollbridge.dev` and serves bundled assets instead of
forwarding:

```sh
# With HTTP_PROXY=http://<proxy-host>:<port> set:
curl http://config.trollbridge.dev/setup                    # index
curl http://config.trollbridge.dev/setup/proxied-agent.md   # PROXIED-AGENT.md
curl http://config.trollbridge.dev/setup/instructions.md    # CLIENT-SETUP-AGENT.md
curl http://config.trollbridge.dev/setup/env                # shell exports
curl http://config.trollbridge.dev/setup/ca.crt             # CA cert (PEM); 404 if interception is off
curl http://config.trollbridge.dev/discovery                # JSON: wire protocol description (status codes, headers, body shapes)
```

Every 470 / 471 deny response also carries a `Trollbridge-Discovery`
header pointing at the discovery URL, so an agent that gets denied
can fetch the protocol document on the next request without prior
configuration.

`config.trollbridge.dev` is intentionally DNS-sinkholed — these
endpoints work *only* through the proxy, so a misconfigured client
that drops `HTTP_PROXY` cannot accidentally reach a real host. The
endpoints are open (no auth); the CA cert is public-by-design.

See [`DESIGN.md`](../DESIGN.md) for the full wire-protocol
specification.
