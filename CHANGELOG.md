# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not
use semantic versioning; the pinned Go and dnscrypt-proxy versions live in the
Dockerfile.

## [Unreleased]

### Added

- `.gitignore` covering local `.env` files and `*.zip` release/upload archives.

### Changed

- `readDNSQuery` now has a single parse path: the POST and GET branches only
  extract the raw message, then one shared `parseDNSMessage` call validates it.
  This also removes the shadowed `qEnd`/`ok` variables the duplicated blocks
  needed.
- The DoH handler reports every error through a small `writeError` helper
  instead of ~20 repeated inline `writeJSON(... map[string]string{...})` calls;
  response bodies and status codes are unchanged.
- The fixed upstream is now described by the `fixedUpstreamHost` /
  `fixedUpstreamURL` constants and stored on the server as plain strings, so
  the hot path no longer re-serializes a `*url.URL` for every request and the
  startup `url.Parse` (with its unreachable error branch) is gone.
- Header parsing uses `strings.Cut` instead of `strings.Split`/`SplitN`
  (`X-Forwarded-For` first hop and the `Content-Type` media type), avoiding a
  slice allocation per request; `getenvInt` parameters no longer shadow the
  Go `min`/`max` built-ins.
- The runtime image sets file modes and ownership with `COPY --chmod` /
  `--chown` instead of a trailing `RUN chmod ... && chown ...`, which copied the
  binaries into an additional layer and inflated the image.
- Startup/bind log messages and the README now say the gateway listens on
  `:$PORT` (all interfaces, dual-stack) instead of the inaccurate `0.0.0.0`.
- The Keep-Alive workflow no longer ends with a whitespace-only line.
- The Docker build context now excludes local `.env` files and the generated
  `keep-alive.txt`, avoiding unnecessary context transfer and keeping local
  environment values out of the builder.
- Rate-limit `Retry-After` now reports the remaining seconds until the active
  fixed window resets instead of always asking clients to wait a full window.
- Removed redundant DNS-name validation branches after confirming their
  conditions were already guaranteed by the surrounding compression-pointer
  and label-type checks.
- Extended the HTTP response-write deadline to 13 seconds (7 seconds for
  request reading plus the 6-second upstream deadline), so accepted slow
  requests are not cut off before the documented upstream budget can expire.
- Updated the checksum-pinned Go build toolchain from 1.27.1 to 1.27.3,
  staying on the same Go 1.27 release line while taking the latest patch fixes.
- `docker-compose.yml` explicitly passes the resolved `PORT` into the container,
  keeping the gateway listener aligned with the published port even when a shell
  environment variable overrides the project `.env` file.
- `docker-compose.yml` no longer hard-codes `TRUST_PROXY_HEADERS` in its
  `environment:` block. The value now comes from `.env` when set, or from the
  image's baked-in `true` default otherwise, so a local override is no longer
  silently ignored.
- `addrHash` uses `binary.LittleEndian.Uint64` instead of a hand-rolled byte
  loop (readability only; the compiler generates equivalent code).
- `probeUpstream` reuses a shared read-only `tls.Config` instead of allocating
  a new one on every health probe.
- `validDNSMessage` was refactored into `parseDNSMessage`, which also returns
  the offset just past the question section, so the DoH handler no longer
  re-parses the question section to compare upstream responses. The
  `validDNSMessage` signature is unchanged.
- `.dockerignore` now excludes documentation, CI, and Compose files
  (`.github/`, `CHANGELOG.md`, `README.md`, `LICENSE`, `docker-compose.yml`,
  `.env.example`, `.dockerignore`) from the Docker build context, shrinking
  what gets sent to the builder; only the Dockerfile, `main.go`,
  `main_test.go`, `go.mod`, `entrypoint.sh`, and `dnscrypt-proxy.toml` are
  needed.
- The read-only `/health` and `/` handlers share one `allowGetOrHead` helper
  for their GET/HEAD method guard instead of two identical inline copies;
  responses are unchanged (405 with `Allow: GET, HEAD`). A new test covers it.
- The Keep-Alive workflow uses a plain `git add -- keep-alive.txt` instead of
  `git add -f`; see the matching entry under Fixed.
- The `log_level` comment in `dnscrypt-proxy.toml` no longer claims that
  setting disables query logging (it does not); it now states that query
  logging is simply not configured and that `log_file` only redirects the
  application log to stdout. The settings themselves are unchanged.

### Removed

- `rateLimiter.allow`, a wrapper with no production callers; it now lives in
  `main_test.go` next to the tests that use it.
- The `windowSec == 0` guard in `secondsUntilWindowReset` (and its test case):
  `newRateLimiter` guarantees a window of at least one second, so it was
  unreachable.
- The explicit `Proxy: nil` transport field (the zero value already means no
  proxy) and a redundant duplicate length check in `dnsQuestionEqual`.
- Dead code: `dnsQuestionSection` and its `TestDNSQuestionSection` test. It
  became unreachable when question-section comparison switched to the
  `qEnd` offsets returned by `parseDNSMessage`; `parseDNSMessage` already
  covers the same validation.
- `validDNSMessage` moved from `main.go` into `main_test.go`: after the
  `parseDNSMessage` refactor it had no production callers left — only tests
  used it, so it no longer ships in the gateway binary.

### Fixed

- `parseDNSMessage` returned a non-zero `qEnd` together with `ok == false` when
  a message had trailing bytes, contradicting its documented contract; it now
  returns `0, false` on every failure path. (No caller used `qEnd` on failure,
  so behavior was unaffected.)
- A client trickling a `POST` body could hold a concurrency slot for the full
  7-second request-read timeout (one client at the default rate limit could
  saturate all 8 slots). The body read now has its own 2-second deadline.
- The rate limiter now evaluates quota windows after acquiring each shard lock,
  and cleanup reads the current window under that lock. This avoids stale-window
  decisions and prevents cleanup from deleting entries created just after a
  fixed-window boundary.
- DoH GET requests now reject malformed query strings and duplicate `dns`
  parameters instead of silently choosing the first repeated value.
- Upstream response validation now compares DNS question names case-insensitively
  and also requires the response opcode to match the query, while retaining
  exact QTYPE/QCLASS checks.
- `PORT` is now parsed as a numeric port in the range 1-65,535, with invalid
  or out-of-range values falling back to the default rather than failing at bind time.
- Global client-table exhaustion now returns HTTP 503 with `Retry-After: 1`,
  while an individual client's exhausted quota still returns HTTP 429. An
  unparseable client address is also reported as a service-side 503 instead of
  being misreported as a rate-limit violation.
- DNS validation now rejects duplicate OPT pseudo-records, OPT records outside
  or not last in the additional section, and OPT records whose owner name is not
  the root.
- `keep-alive.txt` is a tracked file that the Keep-Alive workflow commits
  daily, yet it was also listed in `.gitignore`, which forced the workflow to
  use `git add -f`. A tracked file never appears as untracked clutter, so the
  ignore rule only contradicted the file's purpose and left a `-f` workaround
  in the workflow. The rule and the workaround are removed; `.dockerignore`
  still keeps the file out of the image build context.
