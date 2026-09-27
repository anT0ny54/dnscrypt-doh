#!/bin/sh
set -eu

CONFIG=/etc/dnscrypt-proxy.toml
DNSCRYPT=/usr/local/bin/dnscrypt-proxy
GATEWAY=/usr/local/bin/doh-gateway

"$DNSCRYPT" -config "$CONFIG" -check

"$DNSCRYPT" -config "$CONFIG" &
dns_pid=$!

# Give dnscrypt-proxy a moment to bind its local listeners before the gateway
# starts accepting public requests.
sleep 1

if ! kill -0 "$dns_pid" 2>/dev/null; then
  echo "dnscrypt-proxy exited during startup" >&2
  exit 1
fi

"$GATEWAY" &
gateway_pid=$!

cleanup() {
  trap - TERM INT HUP EXIT
  kill "$gateway_pid" "$dns_pid" 2>/dev/null || true
  wait "$gateway_pid" 2>/dev/null || true
  wait "$dns_pid" 2>/dev/null || true
}

trap cleanup TERM INT HUP EXIT

while :; do
  if ! kill -0 "$dns_pid" 2>/dev/null; then
    echo "dnscrypt-proxy stopped; shutting down" >&2
    exit 1
  fi
  if ! kill -0 "$gateway_pid" 2>/dev/null; then
    echo "DoH gateway stopped; shutting down" >&2
    exit 1
  fi
  sleep 2
done
