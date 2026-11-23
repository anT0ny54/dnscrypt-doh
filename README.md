# dnscrypt-proxy 2 + DoH gateway for SnapDeploy

A compact public DNS-over-HTTPS service designed for SnapDeploy's Small container size (512 MB / 0.25 vCPU).

## Requested upstreams

| Name | DoH endpoint | IPv4 in stamp |
|---|---|---:|
| HaGeZiDNS1 | `https://root.hagezi.org/dns-query` | 188.34.161.210 |
| HaGeZiDNS2 | `https://wurzn.hagezi.org/dns-query` | 159.69.155.94 |
| HaGeZiDNS3 | `https://juuri.hagezi.org/dns-query` | 95.217.163.17 |

The configuration pins these three DoH resolvers with their DNS stamps. `dnscrypt-proxy.toml` defines no `[sources]` table, so the remote public-resolver list is never fetched.

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
dnscrypt-proxy 2.1.20
  - small in-memory cache
  - p2 load balancing
  - 3 pinned HaGeZi DoH upstreams
```

SnapDeploy supplies the public TLS certificate and routes HTTP to the container port. The gateway therefore serves plain HTTP on all interfaces (`:$PORT`) and relies on the edge for TLS; only the gateway-to-dnscrypt-proxy hop is loopback-only (`127.0.0.1:8053`, self-signed certificate generated at image build time). `PORT` is read from the environment as required by SnapDeploy.

## Process supervision

The container runs [tini](https://github.com/krallin/tini) as PID 1 for signal forwarding and PID-1 reaping duties. The entrypoint shell remains the direct parent of dnscrypt-proxy and the gateway, checks each child's Linux process state every 500 ms, and explicitly reaps an exited service before shutting the other one down. It does not rely on BusyBox `ash`'s `wait -n`, which has edge cases where an already-exited older child can be missed while a newer child remains running; nor does it use `kill -0` alone, since that can report a zombie as alive.
Signal and exit traps are installed before configuration validation and service startup, so a stop signal during the startup window runs the same cleanup. The one exception is a signal that arrives in the few microseconds between a service's fork and the shell recording its PID: the shell then cannot stop that service directly, but tini, as PID 1, ends every remaining process when the entrypoint exits. Once shutdown begins, further `SIGTERM`, `SIGINT`, or `SIGHUP` signals are ignored until both services have stopped, so a repeated signal cannot cut the gateway's drain short or leave dnscrypt-proxy running. Child PIDs are validated as numeric before their process state is read.

`entrypoint.sh`:

1. Validates the dnscrypt-proxy configuration with `-check`.
2. Starts dnscrypt-proxy (logging to stderr; no `log_file`, so the unprivileged user never reopens `/dev/stdout`) and then the gateway.
3. Checks both child process states every 500 ms and exits with status 1 if either process dies.
4. On `SIGTERM`, `SIGINT`, or `SIGHUP`, stops the gateway first so in-flight requests can drain for up to 5 seconds, then stops dnscrypt-proxy. Signals received during this shutdown are ignored.

## Configuration

All gateway settings are environment variables. Invalid or out-of-range numeric values fall back to the defaults. The gateway exits during startup for an invalid `DOH_PATH` or if its listen port cannot be bound.

| Variable | Gateway default | Image default | Valid range / notes |
|---|---|---|---|
| `PORT` | `8080` | `8080` | HTTP listen port, 1-65,535; the gateway and health check fall back to `8080` for invalid values. Docker Compose also uses `PORT` for published-port interpolation, so Compose overrides must be valid. Normally managed by SnapDeploy |
| `DOH_PATH` | `/dns-query` | `/dns-query` | Canonical absolute path; must not be `/` or `/health`, or contain `?`, `#` or `%` |
| `RATE_LIMIT` | `99` | `99` | 1-1,000,000 requests per window per client (IPv4 address or IPv6 /64) |
| `RATE_WINDOW_SECONDS` | `60` | `60` | 1-86,400 |
| `MAX_DNS_MESSAGE_BYTES` | `8192` | `8192` | 512-65,535 |
| `MAX_CONCURRENCY` | `16` | `16` | 1-16; hard ceiling for the 0.25 vCPU tier |
| `MAX_CLIENT_IPS` | `8192` | `8192` | 64-32,768 tracked clients (IPv4 addresses or IPv6 /64 prefixes) |
| `TRUST_PROXY_HEADERS` | `false` | `true` | `1/true/yes/on` or `0/false/no/off`; Compose defaults to `false` for direct local publishing |
| `GOMAXPROCS`, `GOMEMLIMIT` | Go runtime defaults | `1`, `160MiB` | Applies independently to each Go process |

The image itself sets only `PORT`, `TRUST_PROXY_HEADERS`, `GOMAXPROCS` and `GOMEMLIMIT`. Every other value in the table comes from the gateway's built-in defaults in `main.go`, so the "Image default" column is the same as the gateway default for those rows.

### `DOH_PATH` rules

A custom path must be reachable exactly as configured. The gateway rejects:

- paths not starting with `/`;
- `/` and `/health`, which are reserved;
- paths containing `?`, `#` or `%` (query/fragment delimiters and percent signs make the configured decoded path ambiguous with its escaped URL spelling);
- repeated slashes or dot segments, which create non-canonical and ambiguous URL paths.

A single trailing slash is allowed.

The internal upstream URL `https://127.0.0.1:8053/dns-query` is fixed in `main.go` and `dnscrypt-proxy.toml`; `DOH_PATH` changes only the public path.

## Rate limiting and backpressure

The default allows 99 `/dns-query` requests per fixed 60-second window per client. A client is an IPv4 address, or the /64 prefix of an IPv6 address, so a single IPv6 subscriber cannot obtain extra quota by rotating addresses inside its /64. Malformed requests on supported methods consume quota; `/health` and `/` are not rate-limited.

The limiter normalizes IPv4-mapped IPv6 addresses to plain IPv4 before keying, and uses 64 shards, lazy per-shard maps, direct map-value entries, and a global atomic entry cap. A shard map is only allocated after a new identity successfully reserves a global table slot, so rejected identities do not create empty maps when the table is full. This avoids rejecting a client merely because one hash shard fills before the configured client-table limit is reached. Cleanup releases a shard map when its last expired entry is removed, returning its bucket storage instead of retaining it through later client churn. Its cleanup interval is the configured window capped at 30 seconds. Request admission and cleanup share a non-decreasing logical clock derived from wall time and monotonic elapsed time; an atomic maximum also clamps delayed, out-of-order samples from concurrent shards. A backwards system-clock correction cannot move limiter time into an earlier window, and the logical clock keeps advancing with elapsed real time so quota windows and `Retry-After` countdowns do not freeze. Requests from an already-tracked client that exceed their quota receive HTTP 429 with `Retry-After` set to the remaining whole seconds until the next logical window boundary; when the global client-tracking table is full, new identities receive HTTP 503 with `Retry-After: 1` instead of being misreported as per-client rate limits.

A global concurrency semaphore defaults to 16 simultaneous DoH requests. It is acquired before request-body/base64 parsing so CPU and memory spent on decoding are bounded under request floods. When full, new requests receive HTTP 503 with `Retry-After: 1` (the same response used for client-table-capacity and invalid-client-IP failures); the slot is released for every response path. Any request body a handler leaves unread is bounded by a dedicated 2-second deadline (best effort, via `http.ResponseController`), including bodies on unsupported methods, unknown paths, and requests rejected by concurrency or rate/client admission, so net/http's post-handler cleanup does not wait for the full 7-second request-read timeout. For admitted DoH requests, the deadline starts immediately before parsing so admission time does not reduce the body-read budget. A DoH `POST` body uses the same deadline while being read; the deadline is cleared only after an accepted body reaches EOF. It must be cleared then because net/http's background connection read would otherwise hit it while the request waits for the upstream and cancel the request context, aborting slow but valid lookups with a 502. Validation rejections and streaming size-limit exits that leave a body unread retain the short deadline while net/http handles those bytes. The upstream wait is bounded by its own 6-second context.

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

Returns `200` with `{"service":"minimal-hagezi-doh","status":"ok","uptime":"..."}` when the gateway can complete a real TLS handshake with the local dnscrypt-proxy DoH listener; otherwise it returns `503` with the same fields and `"status":"starting"`. The TCP dial and the TLS handshake share a single 500 ms deadline (one context covers both), and the result is cached for 2 seconds so orchestrator checks do not create excessive handshake load. If a check arrives while another probe is still running (the handshake can take up to 500 ms), it receives the last cached result instead of waiting; the first check after the probe completes reports the fresh state.

A real TLS handshake is required because a bare TCP open/close is logged by Go's HTTP server as a spurious TLS EOF. `GET` and `HEAD` are supported; other methods return 405 with a JSON error body.

### `GET /`

Returns a small service-information JSON response with three fields: `service`, `endpoint` (the configured `DOH_PATH`), and `rateLimit`. The `rateLimit` text is `<RATE_LIMIT> requests/<RATE_WINDOW_SECONDS>s per client (IPv4 address or IPv6 /64)`, matching the limiter's client identity. `GET` and `HEAD` are supported; other methods return 405 with `Allow: GET, HEAD` and a JSON error body.

### Unknown paths

Any other path returns 404 with a JSON error body, consistent with every other error response. The gateway dispatches paths directly rather than through `http.ServeMux`, so dot segments and repeated slashes are not silently redirected to a different endpoint. It also rejects alternate percent-encoded spellings of a registered path (for example, `/%68ealth` or `/dns%2Dquery`) instead of routing them after URL decoding. Canonical escaping for characters that require it remains supported.

### DoH requests

`GET` and `POST` are supported on `DOH_PATH`; other methods return 405 with `Allow: GET, POST` and a JSON error body.

- `POST` requires `Content-Type: application/dns-message` and a body no larger than `MAX_DNS_MESSAGE_BYTES`. Request and upstream-response bodies are read through one size-bounded helper that pre-sizes its buffer from `Content-Length`.
- `GET` requires exactly one RFC 8484 `dns` parameter containing raw URL-safe base64 without padding, in canonical form: a spelling whose unused final padding bits are nonzero is rejected, so each DNS message has exactly one accepted GET URL. Duplicate `dns` parameters, malformed query strings, and line breaks inside the encoded value are rejected. The encoded parameter is hard-capped at 12,288 characters, which caps the decoded message at 9,216 bytes; with the default `MAX_DNS_MESSAGE_BYTES=8192` the binding limit is 10,923 characters (`base64.RawURLEncoding.EncodedLen(8192)`). `MAX_DNS_MESSAGE_BYTES` values above 9,216 therefore only take effect for `POST`. The encoded ceiling is `EncodedLen(MAX_DNS_MESSAGE_BYTES)`, and that alone bounds the decoded GET message, so no separate decoded-size check runs.
- A long single-parameter query is rejected with 414 before parsing. Only `&` counts as a tolerated parameter separator: `url.ParseQuery` rejects query settings containing `;`, so a semicolon does not exempt an oversized query from the fast-fail. Extra query parameters remain tolerated; in that case the total query is bounded by `MaxHeaderBytes`, and the `dns` value is independently checked against its encoded-size ceiling.
- DNS message structure is validated before forwarding: exactly one uncompressed question, no answer or authority records in queries, and at most one root-owned EDNS OPT record anywhere in the query's additional section (as permitted by [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891)). This gateway deliberately accepts only OPT in client-query Additional records: TSIG- and SIG(0)-signed queries are rejected because the gateway does not authenticate transaction signatures. Upstream responses may contain TSIG or SIG(0), but those records are only structurally checked for required final-record placement under [RFC 8945](https://www.rfc-editor.org/rfc/rfc8945) (which obsoletes RFC 2845) and [RFC 2931](https://www.rfc-editor.org/rfc/rfc2931); their cryptographic signatures are not verified by the gateway. The parser also validates EDNS option framing, rejects trailing bytes, enforces the 255-byte name limit, and applies a 4,096-record ceiling. Compression pointers in resource-record owner names must point backward to an earlier non-root label sequence whose full label data and terminating root octet occur before the pointer itself; a name may contain literal labels before its one pointer, but the pointer target may not be another pointer. Pointers to root terminators, overlapping label data, and nested pointer chains are rejected, following the defensive guidance in [RFC 9267 Section 2](https://www.rfc-editor.org/rfc/rfc9267.html#section-2). Label payload bytes are treated as opaque octets, not as name-encoding markers. Upstream responses reject duplicate or misplaced OPT records and malformed EDNS option framing. Other RR-type-specific RDATA is kept opaque after its declared length is bounds-checked; the gateway validates DNS message framing rather than interpreting every RR type's internal schema.
- Upstream responses must be valid DNS responses with matching ID, opcode, and question. DNS question names are compared case-insensitively as required by DNS name semantics; QTYPE and QCLASS must match exactly.
- Upstream errors return 502; upstream timeouts return 504; the upstream deadline is 6 seconds and covers response-body reads.
- The gateway requires exactly HTTP 200 from its fixed local dnscrypt-proxy upstream as a deliberately strict integration contract. This is narrower than generic DoH semantics: [RFC 8484 Section 4.2.1](https://www.rfc-editor.org/rfc/rfc8484#section-4.2.1) describes successful 2xx responses for valid DNS messages. Any non-200 status (including other 2xx codes), redirects, invalid content types, and oversized responses are rejected with 502.
- Small upstream error bodies are drained to EOF within the configured size cap so the loopback connection can be reused. Known-oversized bodies are rejected without reading them, and unknown-length bodies are read only up to the cap plus one byte; a connection is discarded when its body cannot be fully drained within that bound.
- Successful responses carry `Cache-Control: no-store`; dnscrypt-proxy retains its own bounded in-memory cache.
- Rate-limited clients receive 429 with `Retry-After` set to the remaining whole seconds until the next logical fixed-window boundary. A backwards wall-clock correction does not move limiter time backwards or pause its progression; elapsed monotonic time keeps the retry countdown moving.

## Proxy-header trust

The gateway binary defaults to `TRUST_PROXY_HEADERS=false`; the container image sets it to `true` for the SnapDeploy deployment behind its managed edge. Docker Compose intentionally defaults to `false` because it publishes the container port directly and must not assume a trusted proxy is in front. Compose resolves `TRUST_PROXY_HEADERS` from the shell or project `.env`, so you can explicitly set it to `true` only when a trusted edge overwrites the forwarding headers before they reach the gateway.

Keep `true` only while a front edge overwrites `CF-Connecting-IP` and `X-Forwarded-For`. If the port is directly reachable with no such edge, use `false`: trusting spoofable headers lets clients bypass per-client rate limits. IPv6 zone identifiers are stripped before rate limiting either way.

## Performance notes

The image sets:

- `GOMAXPROCS=1`
- `GOMEMLIMIT=160MiB`

Those Go settings apply independently to the gateway and dnscrypt-proxy. The 512 MB container also uses:

- dnscrypt-proxy cache: 16,384 entries
- localhost DNS client ceiling: 16
- public client-identity ceiling: 8,192
- gateway concurrency ceiling: 16
- default DNS message size: 8,192 bytes

The `/health` and `/` JSON responses are encoded from fixed-field structs, so the orchestrator's fixed-interval polls do not allocate a map on every request; their keys remain in alphabetical order. The gateway binds its socket before announcing startup, validates the configured path before serving, drains for up to 5 seconds on shutdown, and does not follow upstream redirects. The aggregate inbound request-header limit (including the request line), loopback-upstream response-header limit, and local health-check response-header limit are each 16 KiB; these cap the complete header blocks, not individual fields. The upstream transport also limits connections to the configured concurrency, while DNS response bodies have their own message-size bound. The HTTP request-read timeout is 7 seconds, with a 2-second header timeout. A best-effort 2-second read deadline is applied to every request body a handler leaves unread, including bodies rejected by routing, method, concurrency, or rate/client-admission checks. For admitted DoH requests, the deadline starts immediately before body/query parsing, not while waiting for admission. DoH `POST` bodies use that same short deadline while being read; it is cleared only after EOF so the background connection read cannot cancel a valid request while it waits for upstream. Rejected or oversized bodies that remain unread keep the short deadline while net/http handles them. The 13-second response-write deadline overlaps that read window — net/http resets it when a request's headers are read — and is sized as 7 seconds of request reading plus the full 6-second upstream deadline, so a slow accepted request is not cut off before the upstream budget expires.

## Local build and run

The module declares `go 1.27`; use Go 1.27 or newer for local checks. The
Dockerfile pins Go 1.27.4 and refuses to produce an image when the test suite
or `go vet` fails.

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go test -cover -count=1 ./...
go vet ./...
```

The `-count=1` flag forces a fresh test run instead of reusing Go's test cache.
`go test -cover -count=1 ./...` prints statement coverage for the gateway
package.

For additional DNS parser hardening, run the fuzz target for a bounded period:

```bash
go test -fuzz=FuzzParseDNSMessage -fuzztime=30s ./...
```

```bash
docker compose up --build
```

The Compose service optionally loads variables from `.env` (this needs Docker Compose 2.24 or newer):

```bash
cp .env.example .env
```

Keep real settings in `.env` or a variant such as `.env.local`, `.env.production`, or `production.env`. A single pattern, `*.env*`, makes Git ignore these files at any directory depth, with a root-anchored exception for only `/.env.example`; nested files named `.env.example` remain ignored. Docker uses the recursive `**/*.env*` pattern to exclude the same files from the build context. The root template remains available in Git but is not needed in the image.

The image bakes in `TRUST_PROXY_HEADERS=true` for SnapDeploy. Compose deliberately overrides that with a local default of `false`, because its published port is directly reachable; the value can be overridden from the shell or project `.env` when an actual trusted proxy overwrites forwarding headers (see "Proxy-header trust"). The supplied `.env.example` also uses `false` for this reason. Compose explicitly passes its resolved `PORT` value into the container and uses the same value for the host/container port mapping, including when a shell environment variable overrides `.env`.

The multi-stage Dockerfile checksum-verifies the pinned Go and dnscrypt-proxy archives, runs the gateway tests and `go vet`, and builds both binaries. File modes and ownership in the runtime image are set with `COPY --chmod`/`--chown` (BuildKit) instead of a separate `RUN chmod`, which would duplicate the binaries in an extra layer. The `.dockerignore` keeps the build context minimal: it excludes documentation, Compose files, Git and workflow metadata, local `.env*` and `*.env*` files at any directory depth (using Docker’s `**` wildcard), ZIP release artifacts and the workflow-generated `keep-alive.txt`, so only the Dockerfile, `go.mod`, `main.go`, `main_test.go`, `dnscrypt-proxy.toml` and `entrypoint.sh` reach the builder. These are exactly the files the Dockerfile copies, and `main_test.go` is required because the build runs `go test`. The runtime image installs only the `ca-certificates` and `tini` packages (no unused `tzdata`), includes the required binaries, configuration, entrypoint and local certificate, runs as the unprivileged `doh` user, exposes port 8080, and defines a `HEALTHCHECK` that runs `doh-gateway -healthcheck` every 15 seconds. That mode requests `/health` on the port the gateway binds, using the gateway's own validation and `8080` fallback, so the check cannot drift from the server's port handling. It connects directly to the loopback listener, does not follow redirects, and requires the gateway service identity and `status: "ok"` in the bounded JSON response, preventing an unrelated local service from accidentally making the health check pass.

## Testing

The test suite in `main_test.go` covers:

- **DNS wire format:** one uncompressed question, opaque high bytes in label payloads, the 255-byte name boundary, single-hop backward compression pointers to non-root labels in resource-record owner names (including valid literal-label prefixes followed by a pointer to a prior complete name, and rejection of nested pointers, root-terminator targets, and target label data overlapping the pointer), the 4,096-record ceiling, EDNS option framing, one root-owned OPT record at any Additional-section position, rejection of TSIG/SIG(0)-signed client queries, duplicate/misplaced OPT rejection, and final-record placement for TSIG and SIG(0) in upstream responses.
- **GET and POST input:** strict raw base64url decoding, rejection of non-canonical base64url spellings, and line-break rejection, duplicate/malformed query parameters, oversized-query fast-fail without rejecting valid extra parameters, the encoded-to-decoded size bound, content-type and body-size validation, streaming limits for unknown-length POST bodies, and read-deadline behavior for admitted and rejected bodies.
- **Rate limiting:** IPv6 /64 grouping, IPv4-mapped address normalization, lazy sharded maps, global client-table capacity, concurrent per-client quota enforcement, out-of-order clock-sample clamping, monotonic-clock rollback protection, `Retry-After` values, 429/503 responses, cleanup, and release of empty shard maps.
- **Body reading:** the size-bounded reader's exact-hint single-allocation guarantee (`TestReadLimitedExactHintAllocatesOnce`, no regrowth when the body matches its Content-Length), its `limit+1` bound for both initial capacity and growth (`TestReadLimitedInitialCapacityDoesNotExceedLimitPlusOne`, `TestReadLimitedLimitPlusOneBoundsGrowth`), its handling of over-limit, oversized-hint, and lying-hint inputs (`TestReadLimited`), its `io.ErrNoProgress` guard after 100 consecutive zero-byte, nil-error reads (`TestReadLimitedReturnsErrNoProgressForStalledReader`), and its results under short, randomized reads with a fixed seed (`TestReadLimitedRandomizedChunkedReads`).
- **HTTP routing and client identity:** the root endpoint's rate-limit description (which must name the same client identity the limiter uses), proxy-header parsing, path validation, JSON 404 responses, non-redirecting rejection of repeated slashes/dot segments/encoded aliases, canonical path escaping, allowed methods, and JSON responses on `/health` and `/`.
- **Upstream and health handling:** response ID/opcode/question matching, HTTP status and content-type validation, redirect rejection, bounded response/error-body reads and 16 KiB response-header ceilings for both the loopback upstream response and local health-check response, upstream timeout handling, health-probe caching, the shared dial-plus-handshake deadline, and `-healthcheck` port resolution and exit codes.

The Docker build runs `go test ./...` and `go vet ./...` before producing the image.

## Repository keep-alive

`.github/workflows/Keep-Alive.yml` runs daily (03:17 UTC) and on manual dispatch. It rewrites the tracked `keep-alive.txt` with a UTC timestamp and pushes a `[skip ci]` commit, so GitHub's inactivity rule does not disable scheduled workflows on a quiet fork. The file is tracked (it is not in `.gitignore`) and is excluded from the Docker build context by `.dockerignore`.

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md).

## 🔗 Related projects (not part of this repository)

The services below are maintained separately and are **not** part of this repository, its build pipeline, or its release cycle. They are listed here for convenience only.

### 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns.mydoh.workers.dev/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` |

### ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:

- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`

## License

See [`LICENSE`](LICENSE).
