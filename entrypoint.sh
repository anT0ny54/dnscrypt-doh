#!/bin/sh
set -eu

CONFIG=/etc/dnscrypt-proxy.toml
DNSCRYPT=/usr/local/bin/dnscrypt-proxy
GATEWAY=/usr/local/bin/doh-gateway

# Initialize PIDs before installing traps so cleanup is safe if a signal or
# configuration failure occurs before either service has been launched.
dns_pid=
gateway_pid=

cleanup() {
  trap - TERM INT HUP EXIT
  if [ -n "$gateway_pid" ]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
  fi
  if [ -n "$dns_pid" ]; then
    kill "$dns_pid" 2>/dev/null || true
    wait "$dns_pid" 2>/dev/null || true
  fi
}

# Install traps before validating the config or starting services so every
# startup path uses the same shutdown cleanup.
trap 'exit 0' TERM INT HUP
trap cleanup EXIT

"$DNSCRYPT" -config "$CONFIG" -check

# tini handles PID-1 signal/reaping duties. This shell remains the direct
# parent of both services and reaps them via wait, so kill -0 can detect
# termination without relying on a fixed startup sleep.
# Readiness is intentionally NOT gated here with a fixed sleep: the gateway's
# /health endpoint reports 503 until the dnscrypt-proxy DoH listener completes
# a TLS handshake, which lets the container orchestrator observe real readiness
# through its health check instead of racing a guessed startup delay.
"$DNSCRYPT" -config "$CONFIG" &
dns_pid=$!

"$GATEWAY" &
gateway_pid=$!

# Block in wait -n until either service exits; wait -n also reaps the exited
# child, so the death is detected immediately instead of after a poll delay.
# kill -0 polling is deliberately not used for liveness: on shells that do not
# opportunistically reap background jobs, an unreaped child stays a zombie that
# kill -0 still reports as alive, so a crashed service would never be detected.
# Signals interrupt wait -n and run the traps installed above.
while :; do
  wait -n 2>/dev/null || true
  if ! kill -0 "$dns_pid" 2>/dev/null; then
    echo "dnscrypt-proxy stopped; shutting down" >&2
    exit 1
  fi
  if ! kill -0 "$gateway_pid" 2>/dev/null; then
    echo "DoH gateway stopped; shutting down" >&2
    exit 1
  fi
done
