# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not
use semantic versioning; the pinned Go and dnscrypt-proxy versions live in the
Dockerfile. Only the latest changes are listed.

## [Unreleased]

### Fixed

- Rate limiter: request admission and cleanup now share a non-decreasing logical
  clock projected from wall time and monotonic elapsed time. A backwards
  wall-clock correction, including one during a cleanup sweep, can no longer
  move the limiter into an earlier window or reopen an exhausted client's quota.

### Changed

- Gateway: a process-local monotonic projection keeps limiter time moving forward
  through backwards wall-clock corrections, so cleanup, admission and
  `Retry-After` countdowns use the same logical time.
- Gateway: known-oversized upstream error bodies are rejected without an
  unnecessary bounded read; small error bodies are still drained for connection
  reuse, and unknown-length bodies remain capped.
- Dependencies: pin dnscrypt-proxy 2.1.20 with its verified source-archive
  checksum.
- Docker: update both build and runtime base images from Alpine 3.24.2 to 3.24.4
  for the latest stable security fixes; the `mkdir -p /out` step remains folded
  into the `apk` layer.
- README: documents the non-decreasing limiter clock and accurate retry timing;
  it also states that the remote resolver list is off because
  `dnscrypt-proxy.toml` has no `[sources]` table, lists `go.mod` in the build
  context, and describes bounded upstream-error draining and dnscrypt-proxy 2.1.20.

### Tests

- Added regression coverage for forward-then-backward clock corrections
  around cleanup and admission, monotonic retry countdowns, and concurrent
  same-client requests respecting the configured quota.
- Retained coverage ensuring known-oversized upstream bodies are not read.
- `TestValidDNSMessages` now states which byte mutation triggers the rejection.
