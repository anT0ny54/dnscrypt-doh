# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not
use semantic versioning; the pinned Go and dnscrypt-proxy versions live in the
Dockerfile.

## [Unreleased]

### Added

- `.gitignore` covering `.env`, `*.zip`, and the generated `keep-alive.txt`.

### Changed

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

### Removed

- Dead code: `dnsQuestionSection` and its `TestDNSQuestionSection` test. It
  became unreachable when question-section comparison switched to the
  `qEnd` offsets returned by `parseDNSMessage`; `parseDNSMessage` already
  covers the same validation.

### Fixed

- Populated this changelog; it was previously an empty file despite the
  README linking to it.
- The Keep-Alive workflow force-adds `keep-alive.txt`, which is now listed in
  `.gitignore` so it no longer clutters local working trees.
