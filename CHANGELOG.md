# Changelog

This project does not use semantic versioning. Pinned component versions are
recorded in the Dockerfile. Only the latest modification log is retained.

## Latest modification — 2026-11-23

### Changed

- `README.md`: corrected the shutdown-race explanation. Tini's default mode
  forwards signals to its direct child; container teardown, not Tini itself,
  removes any process left behind if a signal lands between a child fork and
  PID registration.
- `CHANGELOG.md`: replaced the prior entry with this latest review log.

### Review

- Reassembled `dnscrypt-doh-main.zip` with the Pass 4 and Pass 6 overlays and
  read all 15 files in full (4,426 newline-terminated lines).
- No confirmed dead production code, unused helpers, redundant test helpers,
  Go gateway defects, or conflicting settings were found. No Go source changes
  or code removals were justified.
- No further runtime optimization was justified without representative load
  measurements and benchmarks.
- Rechecked the Pass 4 keep-alive workflow. A shallow-clone simulation forced
  a competing commit to change `keep-alive.txt` immediately before the first
  push; the first push was rejected, and the retry fetched the new tip, retained
  the competing commit in history, and successfully pushed a fresh timestamp.
- Verified that all three DNS stamps decode to the IP/hostname pairs listed in
  the README. The Dockerfile's combined PEM output was also tested locally and
  contains both a parseable private key and certificate.

### Verified

- `go test -count=1 ./...` passed on a temporary Go 1.23-compatible copy.
- `go test -race -count=1 ./...` passed on that copy.
- `go test -cover -count=1 ./...` passed with 86.1% statement coverage.
- `go vet ./...` passed; `gofmt` reported no changes.
- `FuzzParseDNSMessage` passed a 5-second run with 66,471 executions.
- The workflow script passed `bash -n`; `entrypoint.sh` passed `sh -n`.
- Workflow and Compose YAML parsed; `dnscrypt-proxy.toml` parsed successfully.
- The keep-alive same-file concurrent-push simulation passed with a depth-1
  clone and a local bare remote.
- Official release pages were checked for Go 1.27.4, Alpine 3.24.4,
  dnscrypt-proxy 2.1.20, and actions/checkout v7.0.1. The two Go archive
  checksums in the Dockerfile match the official Go download listing.

### Not verified in this environment

- The project declares Go 1.27, but only Go 1.23.2 is installed. Tests,
  coverage, race detection, vet, formatting, and fuzzing ran in a disposable
  copy with only its `go.mod` directive lowered to `go 1.23`; the submitted
  module declaration remains `go 1.27`.
- Docker, ShellCheck, and actionlint are unavailable. The Docker image build,
  the dnscrypt-proxy `-check` against the built image, and hosted GitHub Actions
  execution were not run. Repository branch-protection and ruleset behavior
  cannot be established from the supplied archives.
