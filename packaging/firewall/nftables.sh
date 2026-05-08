#!/usr/bin/env bash
# Sample nftables snippet that pins the agent VM's egress to the
# host-side trollbridge address. Run this on the Incus HOST.
set -euo pipefail

: "${AGENT_VM_IP:?set AGENT_VM_IP}"
: "${PROXY_LISTEN:?set PROXY_LISTEN, e.g. 10.10.10.1:8080}"
: "${DNS_RESOLVER:?set DNS_RESOLVER, e.g. 10.10.10.1:53}"

PROXY_HOST="${PROXY_LISTEN%:*}"
PROXY_PORT="${PROXY_LISTEN##*:}"
DNS_HOST="${DNS_RESOLVER%:*}"
DNS_PORT="${DNS_RESOLVER##*:}"

nft -f - <<EOF
table inet trollbridge_egress {
    chain forward {
        type filter hook forward priority 0; policy accept;

        # Allow agent → trollbridge over TCP.
        ip saddr ${AGENT_VM_IP} ip daddr ${PROXY_HOST} tcp dport ${PROXY_PORT} accept

        # Allow agent → controlled DNS.
        ip saddr ${AGENT_VM_IP} ip daddr ${DNS_HOST} udp dport ${DNS_PORT} accept
        ip saddr ${AGENT_VM_IP} ip daddr ${DNS_HOST} tcp dport ${DNS_PORT} accept

        # Allow established back.
        ip daddr ${AGENT_VM_IP} ct state established,related accept

        # Drop everything else from the agent.
        ip saddr ${AGENT_VM_IP} drop
    }
}
EOF

echo "nftables rules in place. Verify:"
echo "  nft list table inet trollbridge_egress"
