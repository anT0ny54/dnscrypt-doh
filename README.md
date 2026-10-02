# dnscrypt-proxy 2 + DoH gateway for SnapDeploy

A compact public DNS-over-HTTPS service designed for SnapDeploy's Small container size.

## Requested upstreams

| Name | DoH endpoint | IPv4 in stamp |
|---|---|---:|
| HaGeZiDNS1 | https://root.hagezi.org/dns-query | 188.34.161.210 |
| HaGeZiDNS2 | https://wurzn.hagezi.org/dns-query | 159.69.155.94 |
| HaGeZiDNS3 | https://juuri.hagezi.org/dns-query | 95.217.163.17 |

The configuration pins these three DoH resolvers with their published DNS stamps and disables the remote public-resolver list. The resolver addresses match HaGeZi's published server list.

## Rate limiting

Up to 99 `/dns-query` requests per fixed 60-second window per client IP. Malformed attempts also consume quota; `/health` and `/` are not rate-limited.

The gateway also applies global concurrency backpressure (default 8 simultaneous DoH requests) so an unusual burst cannot consume all 0.25 vCPU capacity. When the concurrency ceiling is reached, new requests receive HTTP 503 with `Retry-After: 1` rather than queueing indefinitely. Malformed requests are rejected before they consume a concurrency slot.

The IP limiter stores client identities in 64 shards with periodic cleanup. Entries are stored directly as small map values to avoid a per-client heap allocation, and each shard fails closed when full instead of scanning on the request path. Shard maps are allocated lazily so an unused `MAX_CLIENT_IPS` table does not pre-reserve map buckets across all shards. Per-shard capacity is rounded up, so the configured `MAX_CLIENT_IPS` is always fully usable (aggregate capacity can exceed it by at most 63 entries).

## Why this layout

SnapDeploy routes traffic through its managed edge and sends it to the container's HTTP port. The public-facing TLS certificate is therefore handled by SnapDeploy, while this container only needs a lightweight HTTP listener. `PORT` is read from the environment, as required by SnapDeploy.

Inside the container:

```text
Internet / client
        |
        | HTTPS
        v
SnapDeploy managed edge / TLS
        |
        | HTTP :8080
        v
Go DoH gateway
  - per-IP 99/60s limiter
  - 8 request concurrency ceiling (raise to 12, then 16 only after load testing)
  - bounded request size + DNS validation
        |
        | HTTPS localhost :8053
        v
 dnscrypt-proxy 2.1.18
  - small in-memory cache
  - p2 load balancing
  - 3 pinned HaGeZi DoH upstreams
```

The container runs [tini](https://github.com/krallin/tini) as PID 1 so terminated child processes are reaped, signal forwarding is reliable, and the entrypoint's supervision loop can trust `kill -0` liveness checks.

`entrypoint.sh` validates the dnscrypt-proxy config (`-check`), starts dnscrypt-proxy and the gateway, and exits with status 1 if either process dies. On `SIGTERM`/`SIGINT`/`SIGHUP` it exits with status 0 after stopping the gateway first (which drains in-flight requests for up to 5s) and only then stopping dnscrypt-proxy, so draining requests still have an upstream.

## Configuration

All settings are environment variables. Out-of-range or unparsable values silently fall back to the default (they do not stop the gateway from starting). Only an invalid `DOH_PATH` is rejected at startup (an unusable `PORT` also fails when binding).

| Variable | Gateway default | Image default | Valid range / notes |
|---|---|---|---|
| `PORT` | `8080` | `8080` | Listen port (managed by SnapDeploy) |
| `DOH_PATH` | `/dns-query` | `/dns-query` | Must start with `/`; cannot be `/` or `/health`; no `?`, `#`, `%` or whitespace; no empty, `.` or `..` segments. A single trailing `/` is allowed. Invalid paths abort startup |
| `RATE_LIMIT` | `99` | `99` | 1-1,000,000 requests per window per client IP |
| `RATE_WINDOW_SECONDS` | `60` | `60` | 1-86,400 |
| `MAX_DNS_MESSAGE_BYTES` | `4096` | `4096` | 512-65,535 |
| `MAX_CONCURRENCY` | `8` | `8` | 1-512 |
| `MAX_CLIENT_IPS` | `10000` | `10000` | 64-1,000,000 |
| `TRUST_PROXY_HEADERS` | `false` | **`true`** | `1/true/yes/on` or `0/false/no/off` |
| `GOMAXPROCS`, `GOGC`, `GOMEMLIMIT` | Go runtime defaults | `1`, `75`, `192MiB` | Go runtime tuning |

The Dockerfile bakes in the "Image default" column, so `.env.example` and `docker-compose.yml` only need to override values that differ. The path of the internal dnscrypt-proxy listener (`https://127.0.0.1:8053/dns-query`) is fixed in `main.go` and `dnscrypt-proxy.toml`; `DOH_PATH` only changes the public path.

## SnapDeploy deployment

1. Push this directory to GitHub.
2. In SnapDeploy, deploy the repository and keep the Small container size (512 MB / 0.25 vCPU).
3. No required secrets are needed. SnapDeploy manages `PORT` automatically.
4. `TRUST_PROXY_HEADERS=true` is already the Docker image default, so per-client rate limiting uses the client IP provided by SnapDeploy's managed edge instead of the edge's own address. Set it to `false` anywhere else unless your edge overwrites those headers (see the proxy-IP note below).
5. `DOH_PATH` may be customized but cannot be `/` or `/health` (those endpoints are reserved) and must be a clean path (see Configuration); the gateway refuses to start with an invalid path.
6. After deployment, the public DoH endpoint is:

```text
https://YOUR-APP.containers.snapdeploy.app/dns-query
```

or your configured custom domain on an Always-On container.

### Health check

```text
GET /health
```

The health endpoint is readiness-aware. It returns `503 {"status":"starting"}` until the gateway can complete a **TLS handshake** with the dnscrypt-proxy local DoH listener on `127.0.0.1:8053`, and `200 {"status":"ok"}` afterwards. A real TLS handshake (not a bare TCP dial) is required because Go's `net/http` logs a spurious `TLS handshake error ... EOF` for any connection that closes before the handshake completes — which would spam dnscrypt-proxy's log on every health check. The probe result is cached for 2 seconds (`upstreamProbeCacheTTL`) so frequent health checks (Docker `HEALTHCHECK` every 15s plus SnapDeploy's own checks) do not perform a fresh TCP+TLS handshake each time. The Dockerfile `HEALTHCHECK` and SnapDeploy's health check both observe this endpoint, so traffic is not routed to a container whose upstream is not yet listening. `/health` and `/` accept `GET` and `HEAD` only (anything else gets `405`).

### DoH endpoint behavior

`GET` and `POST` are supported on the configured `DOH_PATH`; any other method returns `405` with `Allow: GET, POST`.

- `POST` requires `Content-Type: application/dns-message` and a request body of at most `MAX_DNS_MESSAGE_BYTES` (default 4096, allowed range 512-65535); violations return `415` / `413`.
- `GET` carries the wire-format query in the `dns` query parameter, base64url-encoded without padding (RFC 8484). The encoded parameter is limited to 12288 characters (about 9216 decoded bytes, so this is the effective GET ceiling if `MAX_DNS_MESSAGE_BYTES` is raised above 9216; use POST for larger messages); violations return `414` / `413`.
- Every request message is fully validated as DNS wire format before forwarding: exactly one question; no answer or authority records in a query; additional records in a query are limited to EDNS(0) OPT (type 41); names must be at most 255 bytes; compression pointers must point strictly backwards; and at most 4096 resource records per message. Invalid messages return `400` (and consume rate-limit quota).
- Responses from the upstream must be valid DNS responses whose ID and question section exactly match the forwarded query; mismatches return `502`. Upstream failures return `502`; upstream timeouts return `504` (the per-request upstream deadline is 6s). Non-2xx upstream statuses (redirects are not followed), wrong content types and oversized messages are also rejected with `502`.
- When the concurrency ceiling is reached the gateway returns `503` with `Retry-After: 1`.
- Responses always carry `Cache-Control: no-store`; caching is left to dnscrypt-proxy's in-memory cache.
- Rate-limited clients receive `429` with `Retry-After` set to the configured window length in seconds (`RATE_WINDOW_SECONDS`).

### Simple test

A standards-compatible DoH client can use the endpoint directly. For a quick browserless smoke test with curl:

```bash
curl -sS -H 'accept: application/dns-message' \
  -H 'content-type: application/dns-message' \
  --data-binary @query.bin \
  https://YOUR-DOMAIN/dns-query -o response.bin
```

`query.bin` must contain a valid DNS wire-format query.

## Performance knobs

The image pins the build/runtime components rather than accepting an independently overridable dnscrypt-proxy version/checksum pair. This keeps the checksum verification bound to the exact source version used by the build.

The defaults are intentionally conservative for the Small instance:

- `GOMAXPROCS=1` prevents the Go runtime from overscheduling a 0.25-vCPU task.
- `GOGC=75` reduces idle heap growth.
- `GOMEMLIMIT=192MiB` bounds the Go gateway heap independently of the container limit while keeping the gateway well inside the 512 MB task budget.
- `dnscrypt-proxy` uses an in-memory cache of 32,768 entries to absorb repeated queries without a separate database.
- `max_clients=256` applies only to the localhost DNS client side; the public IP limiter is separate.
- The public IP limiter defaults to `MAX_CLIENT_IPS=10000`, enough for many distinct client IPs without allowing unbounded identity churn on a 0.25-vCPU instance.
- `MAX_CONCURRENCY=8` is the baseline for 0.25 vCPU. Increase to 12 and then 16 only after load testing; higher values can increase CPU contention and health-check failures.
- `MAX_DNS_MESSAGE_BYTES=4096` is the default. Raise it to 8192 only when client compatibility requires larger DNS messages.
- The gateway buffers and validates each DNS request/response within `MAX_DNS_MESSAGE_BYTES` before forwarding or responding.
- Full rate-limit shards fail closed without scanning the whole shard on every new client attempt; periodic cleanup removes expired identities. Shard maps are allocated lazily so an unused `MAX_CLIENT_IPS` table does not pre-reserve map buckets across all 64 shards, and per-shard capacity is rounded up so the configured limit is never silently under-provisioned.
- The HTTP transport connection ceilings (`MaxConnsPerHost`, `MaxIdleConnsPerHost`) are tied to `MAX_CONCURRENCY`, so the advertised concurrency limit is not silently capped lower by the transport.
- The upstream deadline is owned by a single per-request context timeout (`6s`); it is not duplicated in `http.Client.Timeout` or `ResponseHeaderTimeout`, keeping timeout behavior predictable.
- HTTP connection reuse is enabled between the Go gateway and the local dnscrypt-proxy DoH listener.
- Advertised request/response `Content-Length` values above the configured DNS message limit are rejected before body processing.
- The HTTP server enforces `ReadHeaderTimeout: 2s`, `ReadTimeout`/`WriteTimeout: 7s`, `IdleTimeout: 30s`, and a 16 KiB header budget. On `SIGTERM`/`SIGINT` the gateway drains in-flight requests for up to 5s before closing.

## Important proxy-IP note

The gateway binary defaults to `TRUST_PROXY_HEADERS=false`, but the Docker image sets it to `true` for SnapDeploy. It only trusts `CF-Connecting-IP` and the first `X-Forwarded-For` address when explicitly enabled, because trusting unsanitized forwarding headers lets clients spoof their IP and bypass per-client rate limits. Keep it enabled only when the edge in front of the container overwrites those headers with the true client IP:

```text
TRUST_PROXY_HEADERS=true
```

This is correct for SnapDeploy's managed edge. Set `TRUST_PROXY_HEADERS=false` when the container port is reachable directly (for example the published `8080:8080` port in `docker-compose.yml`). IPv6 zone identifiers in these headers are stripped, so they cannot be used to mint extra rate-limit identities.

## Local build and run

```bash
docker compose up --build
```

The multi-stage Dockerfile downloads and checksum-verifies pinned Go and dnscrypt-proxy sources, builds dnscrypt-proxy, runs `go test` and `go vet` on the gateway, and builds it. `TARGETARCH` (`amd64` or `arm64`) is filled in automatically by BuildKit. The listener is published on `http://localhost:8080` with `TRUST_PROXY_HEADERS=true` unless you override it (see Configuration).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not used in 15 minutes) |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not used in 15 minutes) |

## ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:

- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`

## License

See [`LICENSE`](LICENSE).
