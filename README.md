# Minimal HaGeZi DoH for SnapDeploy (512 MB / 0.25 vCPU)

A compact public DNS-over-HTTPS service designed for SnapDeploy's Small container size.

## Requested upstreams

| Name | DoH endpoint | IPv4 in stamp |
|---|---|---:|
| HaGeZiDNS1 | https://root.hagezi.org/dns-query | 188.34.161.210 |
| HaGeZiDNS2 | https://wurzn.hagezi.org/dns-query | 159.69.155.94 |
| HaGeZiDNS3 | https://juuri.hagezi.org/dns-query | 95.217.163.17 |

The configuration pins these three DoH resolvers with their published DNS stamps and disables the remote public-resolver list. The stamps and endpoints are from HaGeZi's current DNS server documentation.

## Rate limiting

Up to 99 `/dns-query` requests per fixed 60-second window per client IP. Malformed attempts also consume quota; `/health` and `/` are not rate-limited.

The gateway also applies global concurrency backpressure (default 128 simultaneous DoH requests) so an unusual burst cannot consume all 0.25 vCPU capacity. When the concurrency ceiling is reached, new requests receive HTTP 503 rather than queueing indefinitely.

The IP limiter stores up to 250,000 client identities with 64 shards and periodic cleanup. This is deliberately bounded so a public endpoint cannot grow its in-memory IP table without limit.

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
  - bounded request size
        |
        | HTTP localhost :8053
        v
 dnscrypt-proxy 2.1.18
  - small in-memory cache
  - wp2 load balancing
  - 3 pinned HaGeZi DoH upstreams
```

## SnapDeploy deployment

1. Push this directory to GitHub.
2. In SnapDeploy, deploy the repository and keep the Small container size (512 MB / 0.25 vCPU).
3. No required secrets are needed. SnapDeploy manages `PORT` automatically.
4. After deployment, the public DoH endpoint is:

```text
https://YOUR-APP.containers.snapdeploy.app/dns-query
```

or your configured custom domain on an Always-On container.

### Health check

```text
GET /health
```

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
- `GOMEMLIMIT=192MiB` keeps the gateway well inside the 512 MB task budget.
- `dnscrypt-proxy` uses an in-memory cache of 32,768 entries to absorb repeated queries without a separate database.
- `max_clients=256` applies only to the localhost DNS client side; the public IP limiter is separate.
- HTTP connection reuse is enabled between the Go gateway and the local dnscrypt-proxy DoH listener.

There is no safe universal "maximum users" number for a 0.25-vCPU public DNS service: the practical ceiling depends mainly on query rate, cache hit rate, client RTT, and how much work the upstream resolvers must perform. The configuration therefore protects the task with hard bounded memory and concurrency instead of pretending that a specific user count can be guaranteed.

## Important proxy-IP note

By default the gateway trusts `CF-Connecting-IP` and the first `X-Forwarded-For` address because SnapDeploy documents its managed edge as Cloudflare/Caddy in front of the Fargate task. If you deploy this image somewhere that does not sanitize those headers before forwarding requests, set:

```text
TRUST_PROXY_HEADERS=false
```

## Build-time version pins

- Alpine runtime/build image: `3.24.1`
- Go compiler: `1.23.2`
- dnscrypt-proxy: `2.1.18`

The build verifies the SHA-256 checksum of the downloaded Go toolchain for amd64/arm64. dnscrypt-proxy is built from the tagged 2.1.18 source with vendored dependencies.

## Files

- `Dockerfile` — multi-stage, minimal runtime image
- `main.go` — DoH gateway and bounded per-IP limiter
- `dnscrypt-proxy.toml` — pinned HaGeZi resolver stamps + local DoH listener
- `entrypoint.sh` — startup validation + two-process supervision
- `docker-compose.yml` — optional local test
- `.env.example` — optional environment overrides
