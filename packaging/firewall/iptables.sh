#!/usr/bin/env bash
# Sample iptables snippet that pins the agent VM's egress to the
# host-side trollbridge address. Run this on the Incus HOST.
#
# Variables:
#   AGENT_VM_IP    — the address of the agent VM on the Incus bridge
#   PROXY_LISTEN   — the host:port trollbridge listens on (e.g. 10.10.10.1:8080)
#   DNS_RESOLVER   — controlled DNS resolver address; the agent's
#                    DNS resolution goes here. If you omit this,
#                    DNS exfiltration is unmitigated.
#
# This is illustrative; adapt the chain names and bridge interface
# to your Incus network setup.
set -euo pipefail

: "${AGENT_VM_IP:?set AGENT_VM_IP}"
: "${PROXY_LISTEN:?set PROXY_LISTEN, e.g. 10.10.10.1:8080}"
: "${DNS_RESOLVER:?set DNS_RESOLVER, e.g. 10.10.10.1:53}"

PROXY_HOST="${PROXY_LISTEN%:*}"
PROXY_PORT="${PROXY_LISTEN##*:}"
DNS_HOST="${DNS_RESOLVER%:*}"
DNS_PORT="${DNS_RESOLVER##*:}"

# Allow agent → trollbridge over TCP only.
iptables -I FORWARD -s "$AGENT_VM_IP" -p tcp -d "$PROXY_HOST" --dport "$PROXY_PORT" -j ACCEPT
# Allow agent → controlled resolver over UDP and TCP (DNS).
iptables -I FORWARD -s "$AGENT_VM_IP" -p udp -d "$DNS_HOST" --dport "$DNS_PORT" -j ACCEPT
iptables -I FORWARD -s "$AGENT_VM_IP" -p tcp -d "$DNS_HOST" --dport "$DNS_PORT" -j ACCEPT
# Allow established/related back to the agent.
iptables -I FORWARD -d "$AGENT_VM_IP" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Drop everything else from the agent.
iptables -I FORWARD -s "$AGENT_VM_IP" -j DROP

echo "iptables rules in place. Verify:"
echo "  iptables -L FORWARD -nv | head"
echo
echo "Selftest from inside the agent VM:"
echo "  trollbridge selftest --from-vm"
