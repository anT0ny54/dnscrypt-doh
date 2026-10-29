# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not
use semantic versioning; the pinned Go and dnscrypt-proxy versions live in the
Dockerfile. Only the latest changes are listed.

## [Unreleased]

### Fixed

- Gateway: every upstream-rejection path (non-200 HTTP status, invalid
  content type, and advertised oversized response) now drains the bounded
  response body before replying. The non-200 path already did; the other two
  returned with an unread body, forcing net/http to close the loopback
  connection and defeating connection reuse during upstream error bursts.
- Gateway: a pre-epoch wall clock (negative Unix time) no longer wraps to
  ~2^64 when converted to `uint64` for rate-window bookkeeping in the limiter
  and its cleanup pass. Every request would have landed in a fresh window,
  silently disabling the per-client quota. The clock is pinned to the epoch,
  degrading to one long window instead of no limiting.
- Gateway: the GET oversized-query fast-fail no longer treats `;` as a
  tolerated parameter separator. `url.ParseQuery` rejects query settings
  containing a semicolon, so an oversized separator-free query that happened
  to contain `;` fell through to the parser and failed as a 400 after parsing
  work, instead of receiving the intended 414 before any parsing.
- Gateway: numeric environment variables with a leading `+` (for example
  `PORT=+8080`) fall back to their defaults again. `strconv.Atoi` accepted the
  sign, but `net.Listen` rejects a `+`-prefixed port, so such a value passed
  range validation and then died at bind time instead of falling back like the
  health check's port normalization.
- Gateway: the upstream HTTP status check no longer contains an unreachable
  `< 200` arm (`net/http` consumes interim 1xx responses before returning).
  The check is now a strict RFC 8484 `!= 200` test, so 2xx statuses other than
  200 from the upstream are rejected with 502 as well.
- Docs: the README configuration table and performance notes documented an
  image default of `16` for `MAX_CONCURRENCY`, but the Dockerfile has always
  shipped `16` for the 0.25 vCPU tier; the table now matches the image. The
  `.env.example` header comment likewise claimed "16 concurrent requests"
  above a `MAX_CONCURRENCY=16` value and now describes the value it sets.

### Changed

- Gateway: the bounded body-drain used by all upstream error responses is now
  a single shared helper (`drainBoundedBody`) instead of one inline
  `io.Copy`/`io.LimitReader` sequence per rejection path.
- Gateway: the raw-query fast-fail threshold is now a named compile-time
  constant (`maxGetQueryFastFail`) instead of being recomputed on every GET
  request.
- Gateway: the `POST` read-deadline handling in the DoH handler computes
  `isPost` once and reuses it for both deadline calls instead of re-testing
  `r.Method` at each site.
- Gateway: the `GET /` handler now serves its rate-limit description from a
  string computed once at startup instead of running `fmt.Sprintf` on every
  request.

- Gateway: `/health` no longer serializes concurrent checks behind an
  in-flight upstream probe. The probe mutex was held for the whole TCP+TLS
  handshake (up to 500 ms), so simultaneous health checks queued behind it.
  A check arriving mid-probe now returns the last cached result; sequential
  callers and the 2-second cache TTL are unchanged.

### Optimized

- Gateway: the `/health` and `/` handlers now build their fixed-key JSON
  response maps with a capacity hint (`make(map[string]any, 3)`) instead of
  map literals. A literal starts small and grows through reallocations on
  every request; the orchestrator polls `/health` on a fixed interval, so
  the hint removes that per-poll allocation churn. Response shape and field
  order are unchanged.
