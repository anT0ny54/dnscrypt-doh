# Changelog

This project does not use semantic versioning; the pinned Go and dnscrypt-proxy
versions live in the Dockerfile. Only the latest modification log is retained.

## [Unreleased]

### Security

- Cap loopback-upstream HTTP response headers at the same 16 KiB limit used for
  incoming request headers, preventing unexpectedly large resolver headers from
  consuming excessive memory.

- Harden DNS resource-record owner-name parsing to allow only a single backward
  compression-pointer jump to a prior non-root label sequence that terminates
  before the pointer itself. Reject pointers to root terminators, nested pointer
  chains, and target labels whose data overlaps the pointer, reducing malformed-
  packet parser ambiguity and following the defensive guidance in RFC 9267 Section 2.

### Tests

- Verify that the production upstream transport rejects response headers above
  the 16 KiB limit and retains its configured connection-concurrency bounds.

- Cover the valid labels-then-pointer compression form as well as rejection of
  pointers targeting a prior root terminator, a previously compressed owner
  name, and label data that overlaps the pointer; include the valid form as a
  DNS parser fuzz seed.

### Documentation

- Clarify that the 16 KiB inbound and upstream header limits apply to complete
  header blocks, and document the race-detector and DNS parser fuzz commands.
