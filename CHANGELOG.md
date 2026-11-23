# Changelog

This project does not use semantic versioning; the pinned Go and dnscrypt-proxy
versions live in the Dockerfile. Only the latest modification log is retained.

### Retained fixes

- The one-shot `-healthcheck` client caps response headers at 16 KiB, matching
the gateway and upstream client.
- The `GET` `dns` parameter uses `base64.RawURLEncoding.Strict()` so non-canonical
base64url spellings are rejected rather than aliasing the same DNS message.
- DNS compression-pointer parsing bounds backward offsets and rejects nested
pointer jumps; the existing parser and regression tests cover malformed and
boundary cases.
- Request bodies, response bodies, and HTTP header blocks remain bounded, and
health-check / upstream requests keep their explicit deadlines.
- The shell entrypoint's startup, signal handling, and peer-process cleanup
behavior remain covered by the existing supervision logic and tests.

### Reviewed, no further code change needed

- The full gateway and test sources were reviewed for dead or redundant code,
conflicts, correctness defects, DNS parser edge cases, concurrency, resource
limits, and safe optimization opportunities. No additional unreferenced
production declarations, reproducible production bugs, or justified production
code optimizations were found, so no speculative source changes were made.
- The README test commands now use `-count=1` so the documented test runs bypass
the Go test cache. The project module directive remains `go 1.27`.
- The TOML/YAML configuration parses cleanly, and the three DNS stamps decode
to the addresses, hostnames, and `/dns-query` paths documented in the README.
- A BusyBox `ash` supervision smoke test with stub child processes verified
startup, gateway-before-DNS shutdown ordering, and cleanup after an unexpected
gateway exit. This is a shell-level smoke test, not a full container test.

### Verified

- `gofmt -l`, `go vet ./...`, `go test -count=1 ./...`,
`go test -race -count=1 ./...`, and `go test -cover -count=1 ./...` pass;
statement coverage is 84.8%.
- An 8-second `FuzzParseDNSMessage` run completed without failures (119,317
executions).
- Native `linux/amd64` and cross-compiled `linux/arm64` builds pass with
`CGO_ENABLED=0`.
- `sh -n entrypoint.sh` and `busybox ash -n entrypoint.sh` pass. The TOML and
both YAML configuration files parse successfully.
- The pinned Go 1.27.4 archive hashes match the checksums published by go.dev;
the pinned Alpine and dnscrypt-proxy release metadata were checked against
upstream sources.

### Not verified in this environment

- Go tests/builds with the pinned Go 1.27.4 toolchain; the available local
compiler is Go 1.23.2. Go checks were run on a disposable verification copy
whose `go` directive alone was lowered to 1.23; the project's `go.mod` was not
changed.
- Docker image build or full container execution, validation with the actual
pinned `dnscrypt-proxy -check` binary, and ShellCheck. Docker and ShellCheck are
not installed in this environment.
