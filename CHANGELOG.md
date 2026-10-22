# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not
use semantic versioning; the pinned Go and dnscrypt-proxy versions live in the
Dockerfile. Only the latest changes are listed.

## [Unreleased]

### Fixed

- Unknown paths now return a JSON 404 through `writeError` instead of
  `http.NotFound`'s plain-text body, matching every other error response.
- `dnscrypt-proxy.toml` no longer sets `log_file = '/dev/stdout'`. Reopening
  `/dev/stdout` as the unprivileged `doh` user can fail with "permission
  denied" when the runtime's stdout is a root-owned pipe; with `log_file`
  unset, dnscrypt-proxy logs to stderr, which the runtime captures the same way.

### Changed

- Extracted the catch-all mux closure in `main()` into `(*server).route`, so
  path dispatch (DoH path, `/`, 404) is unit-tested directly.

### Removed

- Dead error branch around `ip.Prefix(64)` in the rate limiter; the address is
  already validated, so the call cannot fail.
- `GOGC=100` from the image `ENV` (it is the Go default) and the unused
  `tzdata` package from the runtime image, shrinking it slightly.

### Added

- `TestRouteDispatchesPathsAndReturnsJSON404`.

### Notes

- Reviewed all files and intentionally left unchanged: `url.ParseQuery` (needed
  to reject duplicate `dns` parameters), the 2-second supervision poll in
  `entrypoint.sh`, and the redundant-looking range checks in `newRateLimiter`
  (they guard direct callers and tests).
- The Go toolchain was unavailable during this review, so the edits were
  verified by inspection only; the Docker build runs `go test` and `go vet`.
