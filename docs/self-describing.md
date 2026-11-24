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

### Why `/setup/ca.crt` needs no auth

The endpoint serves only the CA *certificate*, the public half. The
private key never leaves the proxy host and is the thing to protect.
Locking the endpoint would hide nothing: with interception on, the
proxy sends the same certificate in the chain of every intercepted
HTTPS handshake (`[leaf, CA]`), so any client that can make one HTTPS
request through the proxy already has it. A setup token would add a
step to every agent's setup and protect nothing.

What does matter is that the certificate an agent installs is the
operator's. The agent fetches it over plain HTTP from the proxy it is
about to trust, so for a shared or remote proxy the agent should
compare its SHA-256 fingerprint with the one the operator got from
`trollbridge ca init` / `trollbridge ca install`. The response
carries a `Trollbridge-CA-SHA256` header (lowercase hex over the DER
bytes, the same form those commands print), which confirms the file
arrived intact; the operator's value, passed to the agent out of
band, is what confirms it is the right CA. `CLIENT-SETUP-AGENT.md`
step 3 has the commands.

See [`DESIGN.md`](../DESIGN.md) for the full wire-protocol
specification.
