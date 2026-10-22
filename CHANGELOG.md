# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not
use semantic versioning; the pinned Go and dnscrypt-proxy versions live in the
Dockerfile. Only the latest changes are listed.

## [Unreleased]

### Fixed

- Gateway: `readDNSQuery` referenced `s.maxEncoded` even though it is a free
  function with no `server` receiver, so the gateway source did not compile
  and the Docker build's `go test`/`go vet` stage would fail. The configured
  base64url ceiling is now passed in as an explicit parameter from `doh`
  (`readDNSQuery(r, s.maxBody, s.maxEncoded)`). Behavior is unchanged: the GET
  `dns` parameter is still capped at the smaller of
  `base64.RawURLEncoding.EncodedLen(MAX_DNS_MESSAGE_BYTES)` and the absolute
  12,288-character ceiling.

### Changed

- Gateway: GET DoH requests with a query string longer than the absolute
  encoded ceiling plus a `dns=` prefix are now rejected with 414 before
  `url.ParseQuery` runs, skipping parse work on requests that cannot succeed.
  No legitimate request is affected: a valid query string never exceeds that
  bound at any legal `MAX_DNS_MESSAGE_BYTES`.
- Gateway: the upstream health probe now closes the TLS connection object on
  handshake failure instead of closing the raw TCP connection directly,
  keeping the probe's close path in one layer.
- Tests: added coverage for the oversized-query-string fast-fail path.

### Notes

- Full-repository audit (all sources, tests, Docker assets, Compose file,
  entrypoint, and workflow): no dead or redundant code, no bugs, and no
  configuration conflicts found.
