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

The gateway also applies global concurrency backpressure (default 128 simultaneous DoH requests) so an unusual burst cannot consume all 0.25 vCPU capacity. When the concurrency ceiling is reached, new requests receive HTTP 503 rather than queueing indefinitely. Malformed requests are rejected before they consume a concurrency slot.

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
  - 128 request concurrency ceiling
  - bounded request size + DNS validation
        |
        | HTTPS localhost :8053
        v
 dnscrypt-proxy 2.1.5
  - small in-memory cache
  - p2 load balancing
  - 3 pinned HaGeZi DoH upstreams
```

The container runs [tini](https://github.com/krallin/tini) as PID 1 so terminated child processes are reaped, signal forwarding is reliable, and the entrypoint's supervision loop can trust `kill -0` liveness checks.

## SnapDeploy deployment

1. Push this directory to GitHub.
2. In SnapDeploy, deploy the repository and keep the Small container size (512 MB / 0.25 vCPU).
3. No required secrets are needed. SnapDeploy manages `PORT` automatically.
4. Set `TRUST_PROXY_HEADERS=true` in the app environment so per-client rate limiting uses the client IP provided by SnapDeploy's managed edge instead of the edge's own address. Leave it `false` anywhere else unless your edge overwrites those headers.
5. `DOH_PATH` may be customized but cannot be `/` or `/health` (those endpoints are reserved); the gateway refuses to start with a colliding path.
6. After deployment, the public DoH endpoint is:

```text
https://YOUR-APP.containers.snapdeploy.app/dns-query
```

or your configured custom domain on an Always-On container.

### Health check

```text
GET /health
```

The health endpoint is readiness-aware: it returns `503 {"status":"starting"}` until the gateway can establish a TCP connection to the dnscrypt-proxy DoH listener, and `200 {"status":"ok"}` afterwards. The Dockerfile `HEALTHCHECK` and SnapDeploy's health check both observe this, so traffic is not routed to a container whose upstream is not yet listening.

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

The defaults are intentionally conservative for the Small instance:

- `GOMAXPROCS=1` prevents the Go runtime from overscheduling a 0.25-vCPU task.
- `GOGC=75` reduces idle heap growth.
- `GOMEMLIMIT=192MiB` bounds the Go gateway heap independently of the container limit while keeping the gateway well inside the 512 MB task budget.
- `dnscrypt-proxy` uses an in-memory cache of 32,768 entries to absorb repeated queries without a separate database.
- `max_clients=256` applies only to the localhost DNS client side; the public IP limiter is separate.
- The gateway buffers and validates each DNS request/response within `MAX_DNS_MESSAGE_BYTES` before forwarding or responding.
- Full rate-limit shards fail closed without scanning the whole shard on every new client attempt; periodic cleanup removes expired identities. Shard maps are allocated lazily so an unused `MAX_CLIENT_IPS=256` table does not pre-reserve map buckets across all 64 shards, and per-shard capacity is rounded up so the configured limit is never silently under-provisioned.
- The HTTP transport connection ceilings (`MaxConnsPerHost`, `MaxIdleConnsPerHost`) are tied to `MAX_CONCURRENCY`, so the advertised concurrency limit is not silently capped lower by the transport.
- The upstream deadline is owned by a single per-request context timeout (`6s`); it is not duplicated in `http.Client.Timeout` or `ResponseHeaderTimeout`, keeping timeout behavior predictable.
- HTTP connection reuse is enabled between the Go gateway and the local dnscrypt-proxy DoH listener.
- Advertised request/response `Content-Length` values above the configured DNS message limit are rejected before body processing.

## Important proxy-IP note

The gateway defaults to `TRUST_PROXY_HEADERS=false`. It only trusts `CF-Connecting-IP` and the first `X-Forwarded-For` address when explicitly enabled, because trusting unsanitized forwarding headers lets clients spoof their IP and bypass per-client rate limits. Enable it only when the edge in front of the container overwrites those headers with the true client IP:

```text
TRUST_PROXY_HEADERS=true
```

Do this for SnapDeploy's managed edge; do not do it on a network where clients can set those headers themselves.

## Build-time version pins

- Alpine runtime/build image: `3.24.1`
- Go compiler: `1.23.2`
- dnscrypt-proxy: `2.1.5`

The build verifies the SHA-256 checksum of the downloaded Go toolchain for amd64/arm64 and of the dnscrypt-proxy 2.1.5 source tarball. dnscrypt-proxy is built from the tagged 2.1.5 source with vendored dependencies.

## Files

- `Dockerfile` — multi-stage, minimal runtime image (tini as PID 1, checksum-verified downloads)
- `main.go` — DoH gateway, DNS wire validation, readiness-aware health endpoint, and bounded per-IP limiter
- `main_test.go` — gateway and DNS validation regression tests
- `dnscrypt-proxy.toml` — pinned HaGeZi resolver stamps + local DoH listener
- `entrypoint.sh` — startup validation + two-process supervision under tini
- `docker-compose.yml` — optional local test
- `.env.example` — optional environment overrides

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
