# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not
use semantic versioning; the pinned Go and dnscrypt-proxy versions live in the
Dockerfile. Only the latest changes are listed.

## [Unreleased]

### Removed

- Gateway: dropped bounds guards in `dnsNameEnd`, `dnsNameEndUncompressed` and
  `validEDNSOptions` that could never trigger, because the parsing loops
  already check `offset >= len(msg)` and the callers guarantee valid EDNS
  RDATA ranges.
- Gateway: removed an unreachable root-label length check in
  `dnsNameEndUncompressed`. The label branch already rejects names whose labels
  total 255 bytes, so the root label can never push the name past the limit.

### Changed

- Gateway: the concurrency-limit rejection reuses `unavailableRetryAfter1`, so
  every 503 with `Retry-After: 1` (concurrency, client-table capacity, invalid
  client IP) comes from one helper. Response status, header and body are
  unchanged.
- Deployment: `docker-compose.yml` comments now sit beside the settings they
  describe. The `TRUST_PROXY_HEADERS` rationale was previously placed above the
  unrelated `env_file` block, and the `env_file` note referred to
  `required: true` although the file uses `required: false`.
- Documentation: the `.dockerignore` description now matches what the file
  excludes, and the README notes the shared 503 response and the 255/256-byte
  name boundary coverage.

### Tests

- Added `TestValidDNSMessageNameLengthBoundary`, asserting that a 255-byte
  wire-format question name is accepted and a 256-byte name is rejected.
