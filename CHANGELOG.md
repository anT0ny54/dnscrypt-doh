# Changelog

This project does not use semantic versioning; the pinned Go and dnscrypt-proxy
versions live in the Dockerfile. Only the latest modification log is retained.

## 2026-11-16 — Sixth review pass

### Updated

- README now states the exact 100-consecutive-empty-read threshold used by
  `readLimited` before it returns `io.ErrNoProgress`.

### Reviewed, no further production changes needed

- Merged `dnscrypt-doh-main.zip` with `dnscrypt-doh-modified-files.zip`; the
  patch archive replaces exactly `main.go`, `main_test.go`, `README.md`, and
  `CHANGELOG.md`. No duplicate paths, unexpected files, or merge conflicts were
  present.
- Read all 15 regular files in the merged project in full, including the
  complete Go implementation and test suite, README, changelog, container
  files, shell entrypoint, workflow, environment template, ignore files,
  resolver configuration, module file, and license.
- Rechecked the prior `readLimited` and rate-limiter cleanup changes. Their
  bounds, lock ownership, global entry accounting, and regression tests remain
  consistent. The separate DNS-name parsers intentionally validate different
  wire-format contexts. No additional dead or redundant production code,
  conflicting configuration, or actionable correctness/performance issue was
  found, so no runtime source change was warranted.
- `gofmt`, `go test ./...`, `go test -race ./...`, five shuffled test runs,
  `go vet ./...`, `sh -n entrypoint.sh`, and a 5-second
  `FuzzParseDNSMessage` run passed using the installed Go 1.23.2 compiler in a
  temporary copy with only the `go.mod` directive lowered for compatibility.
  The supplied project `go.mod` was not changed. The pinned Go 1.27.4 toolchain
  and Docker image build were not verified in this environment.
- ShellCheck and the `dnscrypt-proxy -check` binary were unavailable, so those
  checks were not run.
