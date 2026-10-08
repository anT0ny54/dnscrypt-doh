# dnscrypt-proxy 2 + DoH gateway for SnapDeploy

A compact public DNS-over-HTTPS service designed for SnapDeploy's Small container size (512 MB / 0.25 vCPU).

## Requested upstreams

| Name | DoH endpoint | IPv4 in stamp |
|---|---|---:|
| HaGeZiDNS1 | `https://root.hagezi.org/dns-query` | 188.34.161.210 |
| HaGeZiDNS2 | `https://wurzn.hagezi.org/dns-query` | 159.69.155.94 |
| HaGeZiDNS3 | `https://juuri.hagezi.org/dns-query` | 95.217.163.17 |

The configuration pins these three DoH resolvers with their DNS stamps and disables the remote public-resolver list.

## Request flow

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
  - per-IP fixed-window rate limit
  - global concurrency ceiling
  - bounded request/response validation
        |
        | HTTPS 127.0.0.1:8053
        v
dnscrypt-proxy 2.1.18
  - small in-memory cache
  - p2 load balancing
  - 3 pinned HaGeZi DoH upstreams
```

SnapDeploy supplies the public TLS certificate and routes HTTP to the container port. The gateway therefore serves plain HTTP on all interfaces (`0.0.0.0:$PORT`) and relies on the edge for TLS; only the gateway-to-dnscrypt-proxy hop is loopback-only (`127.0.0.1:8053`, self-signed certificate generated at image build time). `PORT` is read from the environment as required by SnapDeploy.

## Process supervision

The container runs [tini](https://github.com/krallin/tini) as PID 1 for signal forwarding and PID-1 reaping duties. The entrypoint shell remains the direct parent of dnscrypt-proxy and the gateway, reaps them with `wait`, and uses `kill -0` liveness checks.

`entrypoint.sh`:

1. Validates the dnscrypt-proxy configuration with `-check`.
2. Starts dnscrypt-proxy and then the gateway.
3. Exits with status 1 if either process dies.
4. On `SIGTERM`, `SIGINT`, or `SIGHUP`, stops the gateway first so in-flight requests can drain for up to 5 seconds, then stops dnscrypt-proxy.

## Configuration

All gateway settings are environment variables. Invalid or out-of-range numeric values fall back to the defaults. The gateway exits during startup for an invalid `DOH_PATH` or if its listen port cannot be bound.

| Variable | Gateway default | Image default | Valid range / notes |
|---|---|---|---|
| `PORT` | `8080` | `8080` | HTTP listen port; normally managed by SnapDeploy |
| `DOH_PATH` | `/dns-query` | `/dns-query` | Canonical absolute path; must not be `/` or `/health`, or contain `?`, `#` or `%` |
| `RATE_LIMIT` | `99` | `99` | 1-1,000,000 requests per window per client (IPv4 address or IPv6 /64) |
| `RATE_WINDOW_SECONDS` | `60` | `60` | 1-86,400 |
| `MAX_DNS_MESSAGE_BYTES` | `8192` | `8192` | 512-65,535 |
| `MAX_CONCURRENCY` | `8` | `8` | 1-16 |
| `MAX_CLIENT_IPS` | `8192` | `8192` | 64-32,768 tracked clients (IPv4 addresses or IPv6 /64 prefixes) |
| `TRUST_PROXY_HEADERS` | `false` | `true` | `1/true/yes/on` or `0/false/no/off` |
| `GOMAXPROCS`, `GOGC`, `GOMEMLIMIT` | Go runtime defaults | `1`, `100`, `160MiB` | Applies independently to each Go process |

### `DOH_PATH` rules

A custom path must be reachable exactly as configured. The gateway rejects:

- paths not starting with `/`;
- `/` and `/health`, which are reserved;
- paths containing `?`, `#` or `%` (the mux matches the decoded URL path, so a percent-escape in the configured path could never match a normal request);
- repeated slashes or dot segments that Go's `http.ServeMux` would clean and redirect before dispatch.

A single trailing slash is allowed.

The internal upstream URL `https://127.0.0.1:8053/dns-query` is fixed in `main.go` and `dnscrypt-proxy.toml`; `DOH_PATH` changes only the public path.

## Rate limiting and backpressure

The default allows 99 `/dns-query` requests per fixed 60-second window per client. A client is an IPv4 address, or the /64 prefix of an IPv6 address, so a single IPv6 subscriber cannot obtain extra quota by rotating addresses inside its /64. Malformed requests on supported methods consume quota; `/health` and `/` are not rate-limited.

The limiter uses 64 shards, lazy per-shard maps, direct map-value entries, and a global atomic entry cap. This avoids false `503` responses caused by one hash shard filling before the configured client-table limit is reached. Its cleanup interval is the configured window capped at 30 seconds.

A global concurrency semaphore defaults to 8 simultaneous DoH requests. It is acquired before request-body/base64 parsing so CPU and memory spent on decoding are bounded under request floods. When full, new requests receive HTTP 503 with `Retry-After: 1`; the slot is released for every response path.

## SnapDeploy deployment

1. Push this directory to GitHub.
2. Deploy it in SnapDeploy with the Small container size.
3. No secrets are required; SnapDeploy manages `PORT`.
4. Keep `TRUST_PROXY_HEADERS=true` so the gateway uses the client IP supplied by SnapDeploy's managed edge.
5. If desired, set a canonical custom `DOH_PATH`.
6. The public endpoint is:

```text
https://YOUR-APP.containers.snapdeploy.app/dns-query
```

or the configured custom domain on an Always-On container.

## Endpoints

### `GET /health`

Returns `200` with `{"status":"ok","service":"minimal-hagezi-doh","uptime":"..."}` when the gateway can complete a real TLS handshake with the local dnscrypt-proxy DoH listener; otherwise it returns `503` with the same fields and `"status":"starting"`. Both TCP establishment and the TLS handshake are bounded by a 500 ms deadline, and the result is cached for 2 seconds so orchestrator checks do not create excessive handshake load.

A real TLS handshake is required because a bare TCP open/close is logged by Go's HTTP server as a spurious TLS EOF. `GET` and `HEAD` are supported; other methods return 405.

### `GET /`

Returns a small service-information JSON response.

### DoH requests

`GET` and `POST` are supported on `DOH_PATH`; other methods return 405 with `Allow: GET, POST`.

- `POST` requires `Content-Type: application/dns-message` and a body no larger than `MAX_DNS_MESSAGE_BYTES`.
- `GET` requires an RFC 8484 `dns` parameter containing raw URL-safe base64 without padding. The encoded parameter is limited to 12,288 characters, which caps the decoded message at 9,216 bytes; `MAX_DNS_MESSAGE_BYTES` values above that only take effect for `POST`.
- Requests are validated as DNS wire format before forwarding: exactly one question, no answer or authority records, EDNS OPT-only additional records, 255-byte name limit, strict backward compression pointers, and a 4096-record ceiling.
- Upstream responses must be valid DNS responses with matching ID and question section.
- Upstream errors return 502; upstream timeouts return 504; the upstream deadline is 6 seconds and covers response-body reads.
- Non-2xx upstream statuses, redirects, invalid content types, and oversized responses are rejected with 502.
- Successful responses carry `Cache-Control: no-store`; dnscrypt-proxy retains its own bounded in-memory cache.
- Rate-limited clients receive 429 with `Retry-After` equal to `RATE_WINDOW_SECONDS`.

## Proxy-header trust

The gateway binary defaults to `TRUST_PROXY_HEADERS=true`; the image sets it to `true` for SnapDeploy. When enabled, it trusts `CF-Connecting-IP` and the first `X-Forwarded-For` value. Enable this only when the front edge overwrites those headers, because trusting spoofable headers lets clients bypass per-client rate limits.

Set it to `false` when the port is directly reachable. The provided Compose service does this for local runs. IPv6 zone identifiers are stripped before rate limiting.

## Performance notes

The image sets:

- `GOMAXPROCS=1`
- `GOGC=100`
- `GOMEMLIMIT=160MiB`

Those Go settings apply independently to the gateway and dnscrypt-proxy. The 512 MB container also uses:

- dnscrypt-proxy cache: 16,384 entries
- localhost DNS client ceiling: 16
- public client-identity ceiling: 8,192
- gateway concurrency ceiling: 8 (16 hard cap)
- default DNS message size: 8,192 bytes

The gateway binds its socket before announcing startup, validates the configured path before serving, drains for up to 5 seconds on shutdown, and does not follow upstream redirects.

## Local build and run

```bash
docker compose up --build
```

The Compose service optionally loads variables from `.env` (this needs Docker Compose 2.24 or newer):

```bash
cp .env.example .env
```

The explicit Compose `environment` mapping takes precedence over `.env`, so `TRUST_PROXY_HEADERS` in `.env` is ignored by Compose. By default, Compose overrides the image setting to `TRUST_PROXY_HEADERS=true` because the local port is directly reachable SnapDeploy's edge. The published port follows `PORT` when it is set in `.env`.

The multi-stage Dockerfile checksum-verifies the pinned Go and dnscrypt-proxy archives, runs the gateway tests and `go vet`, and builds both binaries. The runtime image runs as the unprivileged `doh` user, exposes port 8080, and defines a `HEALTHCHECK` that requests `/health` every 15 seconds.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns.mydoh.workers.dev/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` |

## ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:

- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`

## License

See [`LICENSE`](LICENSE).
