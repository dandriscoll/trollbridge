#!/usr/bin/env bash
# Convenience script that launches an Incus VM wired to a host-side
# trollbridge.
#
# Edits required: HOST_IP and CA_PATH at the top.
#
# Usage:
#   ./launch.sh agent-vm
set -euo pipefail

HOST_IP="${HOST_IP:-10.10.10.1}"
PROXY_PORT="${PROXY_PORT:-8080}"
CA_PATH="${CA_PATH:-/etc/trollbridge/trollbridge-ca.crt}"
IMAGE="${IMAGE:-images:debian/12}"
NAME="${1:-agent-vm}"

if [[ ! -r "$CA_PATH" ]]; then
  echo "trollbridge CA cert not found at $CA_PATH; run 'trollbridge ca init' first" >&2
  exit 1
fi

# Render cloud-init by inlining the CA cert.
TMP_INIT="$(mktemp)"
trap 'rm -f "$TMP_INIT"' EXIT
HERE="$(dirname "$0")"

# Prefix every CA line with 6 spaces so cloud-init's YAML stays
# valid (the marker is indented under content: |).
CA_INDENTED="$(sed 's/^/      /' "$CA_PATH")"

# Substitute placeholders.
sed \
  -e "s|{{HOST_IP}}|$HOST_IP|g" \
  -e "s|{{PROXY_PORT}}|$PROXY_PORT|g" \
  -e "/{{CA_CERT_PEM}}/{
    r /dev/stdin
    d
  }" \
  "$HERE/cloud-init.yaml" <<<"$CA_INDENTED" > "$TMP_INIT"

incus launch "$IMAGE" "$NAME" --vm \
  --config "user.user-data=$(cat "$TMP_INIT")"

echo "launched $NAME; once boot is complete, run:"
echo "  incus exec $NAME -- trollbridge selftest --from-vm"
echo "(after copying the trollbridge binary into the VM)."
