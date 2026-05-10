// Package selfdescribe implements the proxy's self-describing HTTP
// surface (issue #38). When the proxy receives a request whose Host
// header (or absolute-URL host) is the magic name, the request is
// short-circuited away from the policy engine: a static handler
// serves embedded markdown / on-disk PEM bytes so an agent that has
// only the proxy's address can bootstrap itself (env vars, CA cert,
// proxied-agent prompt).
package selfdescribe

import _ "embed"

// Embedded markdown ships with the binary. The repo-root copies
// (PROXIED-AGENT.md, CLIENT-SETUP-AGENT.md) are the human-read
// authoritative source; drift_test.go fails the build if these
// embed copies fall out of sync with the repo-root files.

//go:embed PROXIED-AGENT.md
var proxiedAgentMD []byte

//go:embed CLIENT-SETUP-AGENT.md
var clientSetupMD []byte

// MagicHost is the reserved Host name. The user owns the parent
// `trollbridge.dev` domain; the `config` subdomain is intentionally
// DNS-sinkholed so misconfigured agents cannot reach an unrelated
// endpoint when their HTTP_PROXY ever fails open.
const MagicHost = "config.trollbridge.dev"
