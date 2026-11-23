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
  # Ignore further stop signals while draining. Restoring default handling here
  # let a repeated TERM kill this shell mid-drain, which skipped the gateway's
  # graceful shutdown and left dnscrypt-proxy running as an orphan.
  trap '' TERM INT HUP
  trap - EXIT
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

# Report a child as running only while its Linux process exists in a live
# state. kill -0 alone is insufficient: a shell may leave an exited child as a
# zombie, for which kill -0 still succeeds. Parsing /proc avoids relying on
# BusyBox ash's wait -n, which can miss an older child that exited before the
# wait began while a newer child keeps running.
child_running() {
  # An empty PID would expand to /proc//stat, which resolves to /proc/stat and
  # reads as a live process. Reject anything that is not a numeric PID.
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ -r "/proc/$1/stat" ] || return 1
  process_stat=
  read -r process_stat < "/proc/$1/stat" || return 1
  # The comm field is parenthesized and may contain spaces; strip through its
  # final ") " delimiter so the first remaining field is the process state.
  process_stat=${process_stat##*) }
  case "$process_stat" in
    Z*|X*) return 1 ;;
    *) return 0 ;;
  esac
}

# tini handles PID-1 signal/reaping duties. This shell remains the direct
# parent of both services. Readiness is intentionally NOT gated here with a
# startup sleep: /health reports 503 until the gateway completes a TLS
# handshake with dnscrypt-proxy, allowing the orchestrator to observe readiness.
"$DNSCRYPT" -config "$CONFIG" &
dns_pid=$!

"$GATEWAY" &
gateway_pid=$!

# Poll only process state, not readiness. A 500 ms interval detects a service
# exit promptly while forking `sleep` only twice a second (a 100 ms interval
# would fork it ten times a second on a 0.25 vCPU container), and it avoids
# depending on non-portable or shell-version-sensitive wait -n behavior.
# Explicit wait calls reap whichever child has exited before cleanup.
while :; do
  if ! child_running "$dns_pid"; then
    wait "$dns_pid" 2>/dev/null || true
    dns_pid=
    echo "dnscrypt-proxy stopped; shutting down" >&2
    exit 1
  fi
  if ! child_running "$gateway_pid"; then
    wait "$gateway_pid" 2>/dev/null || true
    gateway_pid=
    echo "DoH gateway stopped; shutting down" >&2
    exit 1
  fi
  sleep 0.5
done
