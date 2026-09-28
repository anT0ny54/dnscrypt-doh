#!/bin/sh
set -eu

CONFIG=/etc/dnscrypt-proxy.toml
DNSCRYPT=/usr/local/bin/dnscrypt-proxy
GATEWAY=/usr/local/bin/doh-gateway

"$DNSCRYPT" -config "$CONFIG" -check

# tini runs as PID 1 and reaps terminated children, so the kill -0 liveness
# checks in the supervision loop below are reliable (no zombie children).
# Readiness is intentionally NOT gated here with a fixed sleep: the gateway's
# /health endpoint reports 503 until the dnscrypt-proxy DoH listener accepts
# TCP connections, which lets the container orchestrator observe real readiness
# through its health check instead of racing a guessed startup delay.
"$DNSCRYPT" -config "$CONFIG" &
dns_pid=$!

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
