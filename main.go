package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultPort            = 8080
	defaultDoHPath         = "/dns-query"
	fixedUpstreamHost      = "127.0.0.1:8053"
	fixedUpstreamURL       = "https://" + fixedUpstreamHost + "/dns-query"
	defaultRateLimit       = 99
	defaultRateWindowSec   = 60
	defaultMaxBodyBytes    = 8192
	defaultConcurrency     = 8
	defaultClientEntries   = 8192
	defaultMaxHeaderBytes  = 16 << 10
	defaultMaxGetQuerySize = 12 << 10
	minMaxBodyBytes        = 512
	maxMaxBodyBytes        = 65535
	maxRateLimit           = 1000000
	maxRateWindowSec       = 86400
	maxConcurrency         = 16
	maxClientEntries       = 32768
	maxDNSNameBytes        = 255
	maxDNSRecords          = 4096
	dnsTypeOPT             = 41
	dnsOpcodeMask          = 0x7800
	shardCount             = 64
	upstreamTimeout        = 6 * time.Second
	requestReadTimeout     = 7 * time.Second
	bodyReadTimeout        = 2 * time.Second
	responseWriteTimeout   = requestReadTimeout + upstreamTimeout
	upstreamProbeTimeout   = 500 * time.Millisecond
	upstreamProbeCacheTTL  = 2 * time.Second
	shutdownGrace          = 5 * time.Second
	maxCleanupIntervalSec  = 30
)

// serviceName is reported by the / and /health endpoints.
const serviceName = "minimal-hagezi-doh"

type rateEntry struct {
	window uint64
	count  uint32
}

type rateLimitResult uint8

const (
	rateAllowed rateLimitResult = iota
	rateExceeded
	rateCapacityReached
	rateInvalidAddress
)

type rateShard struct {
	mu sync.Mutex
	m  map[netip.Addr]rateEntry
}

type rateLimiter struct {
	shards     [shardCount]rateShard
	limit      uint32
	windowSec  uint64
	maxEntries int64
	entries    atomic.Int64
}

func newRateLimiter(limit, windowSec, maxEntries int) *rateLimiter {
	if limit < 1 || limit > maxRateLimit {
		limit = defaultRateLimit
	}
	if windowSec < 1 || windowSec > maxRateWindowSec {
		windowSec = defaultRateWindowSec
	}
	if maxEntries < shardCount || maxEntries > maxClientEntries {
		maxEntries = defaultClientEntries
	}
	// Shard maps are allocated lazily. A large MAX_CLIENT_IPS value should not
	// reserve map buckets for every shard before the first client arrives.
	return &rateLimiter{
		limit:      uint32(limit),
		windowSec:  uint64(windowSec),
		maxEntries: int64(maxEntries),
	}
}

func addrHash(a netip.Addr) uint64 {
	b := a.As16()
	var x uint64 = 0x9e3779b97f4a7c15
	for i := 0; i < 16; i += 8 {
		v := binary.LittleEndian.Uint64(b[i:])
		x ^= v + 0x9e3779b97f4a7c15 + (x << 6) + (x >> 2)
		x ^= x >> 30
		x *= 0xbf58476d1ce4e5b9
		x ^= x >> 27
	}
	return x ^ (x >> 31)
}

// secondsUntilWindowReset returns the number of whole seconds (1 through
// windowSec) until the next fixed-window boundary. Keeping this tied to the
// same timestamp used for the quota decision avoids telling clients to wait a
// full extra window when only a small part of the current window remains.
// windowSec is always >= 1 because newRateLimiter validates it.
func secondsUntilWindowReset(unixSeconds, windowSec uint64) uint64 {
	return windowSec - unixSeconds%windowSec
}

func (r *rateLimiter) allowWithRetryAfter(ip netip.Addr) (rateLimitResult, uint64) {
	if !ip.IsValid() {
		return rateInvalidAddress, 0
	}
	// Rate-limit IPv6 clients per /64: a single subscriber normally controls
	// a whole /64, so per-address keys would let one host mint unlimited
	// identities and bypass the per-client quota.
	// ip is valid here, so Prefix(64) cannot fail.
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		ip = p.Addr()
	}
	idx := int(addrHash(ip) % shardCount)
	sh := &r.shards[idx]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	// Read the clock after acquiring the shard lock so contention across a
	// window boundary cannot make this decision use an already-expired window.
	nowUnix := uint64(time.Now().Unix())
	nowWindow := nowUnix / r.windowSec
	if sh.m == nil {
		sh.m = make(map[netip.Addr]rateEntry)
	}
	entry, ok := sh.m[ip]
	if !ok {
		// The global entry counter is the hard capacity guard. A previous
		// per-shard-only cap could reject a client merely because its hash
		// bucket filled early, even when other shards still had capacity.
		if !r.reserveEntry() {
			return rateCapacityReached, 0
		}
		entry = rateEntry{window: nowWindow}
	}

	if entry.window != nowWindow {
		entry.window = nowWindow
		entry.count = 0
	}
	if entry.count >= r.limit {
		return rateExceeded, secondsUntilWindowReset(nowUnix, r.windowSec)
	}
	entry.count++
	sh.m[ip] = entry
	return rateAllowed, 0
}

func (r *rateLimiter) reserveEntry() bool {
	for {
		current := r.entries.Load()
		if current >= r.maxEntries {
			return false
		}
		if r.entries.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// cleanupInterval bounds how long expired entries can occupy limiter slots.
// Ticking only once per RATE_WINDOW_SECONDS let expired entries linger for up
// to a whole extra window (a day at the 86,400 maximum), so stale entries could
// otherwise occupy global client capacity longer than necessary.
func cleanupInterval(windowSec int) time.Duration {
	if windowSec > maxCleanupIntervalSec {
		windowSec = maxCleanupIntervalSec
	}
	return time.Duration(windowSec) * time.Second
}

func (r *rateLimiter) cleanup() {
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		// Read the current window while holding each shard lock. Capturing it
		// once before the loop could let a window rollover cause cleanup to
		// delete newly-created entries from the next window.
		nowWindow := uint64(time.Now().Unix()) / r.windowSec
		for k, v := range sh.m {
			// Only expired windows may be reclaimed. A window ahead of
			// nowWindow means the clock moved backwards after the entry was
			// stored; evicting it would free a slot that the client's next
			// request immediately re-creates anyway.
			if v.window < nowWindow {
				delete(sh.m, k)
				r.entries.Add(-1)
			}
		}
		sh.mu.Unlock()
	}
}

// loopbackTLSConfig is shared by the gateway's upstream HTTP transport and
// the health probe. crypto/tls forbids modifying a Config once it is in use,
// but sharing a read-only Config across goroutines is safe and avoids
// re-allocating one for every 2-second probe.
var loopbackTLSConfig = &tls.Config{
	// dnscrypt-proxy's local DoH service uses its bundled localhost
	// self-signed certificate. It is only ever used for the fixed loopback
	// upstream, never for public destinations.
	InsecureSkipVerify: true, //nolint:gosec // loopback-only fixed upstream
	MinVersion:         tls.VersionTLS12,
}

// probeDialer is shared by all upstream health probes. A net.Dialer is safe
// for concurrent use, so probes do not need to allocate their own copy.
var probeDialer = &net.Dialer{Timeout: upstreamProbeTimeout}

type server struct {
	client *http.Client
	// upstreamURL is the full DoH URL requests are POSTed to; upstreamHost is
	// its host:port, used by the health probe. Both are stored as strings so
	// the hot path does not re-serialize a *url.URL for every request.
	upstreamURL  string
	upstreamHost string
	dohPath      string
	rate         *rateLimiter
	sem          chan struct{}
	maxBody      int64
	maxEncoded   int
	trustProxy   bool
	started      time.Time

	// Cached upstream probe result so health checks do not perform a fresh
	// TCP+TLS handshake on every call.
	probeMu sync.Mutex
	probeAt time.Time
	probeOK bool
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback, lo, hi int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || v < lo || v > hi {
		return fallback
	}
	return v
}

func getenvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch v {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

// parseClientIPValue parses a single header or RemoteAddr value into a
// canonical client IP. IPv6 zone identifiers are stripped so they cannot be
// used to mint additional rate-limit identities for the same address. It is a
// package-level function (not a per-request closure) because it captures
// nothing.
func parseClientIPValue(value string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap().WithZone(""), true
}

func parseClientIP(r *http.Request, trustProxy bool) netip.Addr {
	if trustProxy {
		if ip, ok := parseClientIPValue(r.Header.Get("CF-Connecting-IP")); ok {
			return ip
		}
		if h := r.Header.Get("X-Forwarded-For"); h != "" {
			first, _, _ := strings.Cut(h, ",")
			if ip, ok := parseClientIPValue(first); ok {
				return ip
			}
		}
	}

	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		if ip, ok := parseClientIPValue(host); ok {
			return ip
		}
	}
	ip, _ := parseClientIPValue(r.RemoteAddr)
	return ip
}

// validateDoHPath rejects paths that cannot be reached by http.ServeMux and
// paths that would shadow the reserved /health and / endpoints.
func validateDoHPath(dohPath string) error {
	if !strings.HasPrefix(dohPath, "/") {
		return fmt.Errorf("DOH_PATH must start with '/': %q", dohPath)
	}
	if strings.ContainsAny(dohPath, "?#%") {
		// '%' is rejected because the mux matches the decoded URL path, so a
		// configured percent-escape could never match a normal request.
		return fmt.Errorf("DOH_PATH must not contain '?', '#' or '%%': %q", dohPath)
	}
	if canonicalHTTPPath(dohPath) != dohPath {
		return fmt.Errorf("DOH_PATH must be canonical; repeated slashes and dot segments are redirected before matching: %q", dohPath)
	}
	switch dohPath {
	case "/", "/health":
		return fmt.Errorf("DOH_PATH %q conflicts with a reserved endpoint", dohPath)
	}
	return nil
}

// canonicalHTTPPath mirrors net/http's ServeMux path cleaning, including its
// preservation of one trailing slash. A configured path that differs from the
// cleaned form is unreachable because ServeMux redirects the request first.
//
// The caller (validateDoHPath) has already verified that p starts with "/".
func canonicalHTTPPath(p string) string {
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		if len(p) == len(cleaned)+1 && strings.HasPrefix(p, cleaned) {
			return p
		}
		cleaned += "/"
	}
	return cleaned
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func isDNSMessageContentType(v string) bool {
	mediaType, _, _ := strings.Cut(v, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/dns-message")
}

// dnsNameEnd validates a DNS name, including compression pointers, and returns
// the number of bytes consumed at the containing offset.
func dnsNameEnd(msg []byte, offset int) (int, bool) {
	if offset < 0 || offset >= len(msg) {
		return 0, false
	}

	next := offset
	jumped := false
	jumps := 0
	nameLen := 0
	for {
		if offset >= len(msg) {
			return 0, false
		}
		labelLen := msg[offset]
		switch {
		case labelLen == 0:
			nameLen++ // terminating root label
			if nameLen > maxDNSNameBytes {
				return 0, false
			}
			if jumped {
				return next, true
			}
			return offset + 1, true
		case labelLen&0xc0 == 0xc0:
			if offset+1 >= len(msg) {
				return 0, false
			}
			pointer := int(labelLen&0x3f)<<8 | int(msg[offset+1])
			// DNS compression pointers must point backwards to an earlier
			// label occurrence. A forward pointer is not a valid DNS name.
			if pointer < 12 || pointer >= offset {
				return 0, false
			}
			if !jumped {
				next = offset + 2
			}
			jumped = true
			offset = pointer
			jumps++
			if jumps > 128 {
				return 0, false
			}
		case labelLen&0xc0 != 0:
			return 0, false
		default:
			if offset+1+int(labelLen) > len(msg) {
				return 0, false
			}
			nameLen += 1 + int(labelLen)
			if nameLen > maxDNSNameBytes {
				return 0, false
			}
			offset += 1 + int(labelLen)
		}
	}
}

// parseDNSMessage validates a DNS message and also returns qEnd, the offset
// just past the question section (QNAME + QTYPE + QCLASS). Callers that have
// validated a message can slice msg[12:qEnd] to compare question sections
// without re-parsing them. On failure qEnd is 0.
func parseDNSMessage(msg []byte, wantResponse bool) (qEnd int, ok bool) {
	if len(msg) < 12 {
		return 0, false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if (flags&0x8000 != 0) != wantResponse {
		return 0, false
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))
	if qdCount != 1 {
		return 0, false
	}
	// A query carries no answer or authority records. Additional records are
	// only allowed for EDNS(0), whose resource type is OPT (41).
	if !wantResponse && (anCount != 0 || nsCount != 0) {
		return 0, false
	}

	recordCount := anCount + nsCount + arCount
	if recordCount > maxDNSRecords {
		return 0, false
	}

	// qdCount was required to be exactly one above, so parse the single
	// question directly instead of looping over a count that cannot repeat.
	offset, nameOK := dnsNameEnd(msg, 12)
	if !nameOK || offset+4 > len(msg) {
		return 0, false
	}
	// The question name must be uncompressed: compression pointers are only
	// valid inside resource records. Today any pointer here would still be
	// rejected indirectly (a question pointer can only target bytes inside
	// the name being parsed, which the jump cap above rejects as a loop), but
	// enforcing it explicitly documents the invariant dnsQuestionEqual relies
	// on and avoids that 128-step loop. A 0xc0 byte inside this span is
	// necessarily a pointer: dnsNameEnd already rejected 0x40/0x80 label
	// lengths, and a pointer that starts the jump still lies in this span
	// because dnsNameEnd returns the offset just past it.
	for i := 12; i < offset; i++ {
		if msg[i]&0xc0 == 0xc0 {
			return 0, false
		}
	}
	offset += 4 // QTYPE + QCLASS
	qEnd = offset

	sections := [...]int{anCount, nsCount, arCount}
	for section, sectionCount := range sections {
		for i := 0; i < sectionCount; i++ {
			recordStart := offset
			if offset, nameOK = dnsNameEnd(msg, offset); !nameOK || offset+10 > len(msg) {
				return 0, false
			}
			ownerEnd := offset
			rtype := binary.BigEndian.Uint16(msg[offset : offset+2])
			rdataLen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
			offset += 10
			if offset+rdataLen > len(msg) {
				return 0, false
			}
			offset += rdataLen

			if !wantResponse && rtype != dnsTypeOPT {
				return 0, false
			}
			if rtype == dnsTypeOPT {
				// EDNS permits a root-owned OPT pseudo-record only as the final
				// record in the additional section. This also rejects duplicates:
				// an earlier OPT cannot be final when another record follows.
				// A validated owner name of exactly one byte is necessarily the
				// root label (0x00): regular labels and compression pointers
				// each need at least two bytes, so an explicit zero-byte test
				// would be unreachable.
				if section != 2 || i != sectionCount-1 || ownerEnd != recordStart+1 {
					return 0, false
				}
			}
		}
	}

	// Trailing bytes after the last record are invalid; keep the documented
	// contract that qEnd is 0 on every failure path.
	if offset != len(msg) {
		return 0, false
	}
	return qEnd, true
}

// dnsQuestionEqual compares validated question sections. DNS names are
// case-insensitive ASCII labels, while QTYPE and QCLASS must match exactly.
// The parser guarantees that the question names are valid and uncompressed,
// and both end offsets come from parseDNSMessage, which already ensures
// aEnd >= 17 and that each offset is within its message; only the equality
// of the two ends needs to be checked here.
func dnsQuestionEqual(a []byte, aEnd int, b []byte, bEnd int) bool {
	if aEnd != bEnd {
		return false
	}
	// aEnd == bEnd was verified above, so both name sections share one end
	// offset; a single index serves both messages. The overwhelmingly common
	// case is a byte-identical echo; skip the fold-compare loop when it
	// already matches.
	if bytes.Equal(a[12:aEnd], b[12:bEnd]) {
		return true
	}
	nameEnd := aEnd - 4
	for i := 12; i < nameEnd; i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return bytes.Equal(a[nameEnd:aEnd], b[nameEnd:bEnd])
}

// readDNSQuery extracts and validates the DNS wire message from a DoH
// request, returning the message along with qEnd, the offset just past its
// question section, so the caller can compare question sections without a
// second parse. maxEncoded is the base64url-encoded ceiling derived from
// MAX_DNS_MESSAGE_BYTES; the absolute defaultMaxGetQuerySize ceiling is
// applied independently. The status return is a non-zero HTTP status code on
// failure.
func readDNSQuery(r *http.Request, maxBody int64, maxEncoded int) ([]byte, int, int) {
	var msg []byte
	if r.Method == http.MethodPost {
		if !isDNSMessageContentType(r.Header.Get("Content-Type")) {
			return nil, 0, http.StatusUnsupportedMediaType
		}
		if r.ContentLength > maxBody {
			return nil, 0, http.StatusRequestEntityTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			return nil, 0, http.StatusBadRequest
		}
		if int64(len(body)) > maxBody {
			return nil, 0, http.StatusRequestEntityTooLarge
		}
		msg = body
	} else {
		// Fail fast: a query string longer than the absolute encoded ceiling
		// plus the shortest possible "dns=" prefix cannot yield an acceptable
		// dns parameter, so reject it before parsing. (The request line is
		// already bounded by the server's MaxHeaderBytes; this only skips
		// parse work on requests that cannot succeed.)
		if len(r.URL.RawQuery) > defaultMaxGetQuerySize+len("dns=") {
			return nil, 0, http.StatusRequestURITooLong
		}
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return nil, 0, http.StatusBadRequest
		}
		dnsValues, ok := values["dns"]
		if !ok || len(dnsValues) != 1 || dnsValues[0] == "" {
			return nil, 0, http.StatusBadRequest
		}
		encoded := dnsValues[0]
		if len(encoded) > maxEncoded || len(encoded) > defaultMaxGetQuerySize {
			return nil, 0, http.StatusRequestURITooLong
		}
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, 0, http.StatusBadRequest
		}
		if int64(len(decoded)) > maxBody {
			return nil, 0, http.StatusRequestEntityTooLarge
		}
		msg = decoded
	}

	qEnd, ok := parseDNSMessage(msg, false)
	if !ok {
		return nil, 0, http.StatusBadRequest
	}
	return msg, qEnd, 0
}

// upstreamReady reports whether the fixed loopback DoH upstream accepts TLS
// connections, caching the result briefly so health checks do not perform a
// fresh TCP+TLS handshake on every call. It intentionally avoids doing a full
// DoH exchange so the health endpoint stays cheap.
//
// The probe must complete a real TLS handshake before closing. A bare TCP
// dial-and-close makes dnscrypt-proxy's local DoH server log a spurious
// "http: TLS handshake error ... EOF" on every /health check, because Go's
// net/http logs any connection that closes before the handshake finishes.
func (s *server) upstreamReady() bool {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if time.Since(s.probeAt) < upstreamProbeCacheTTL {
		return s.probeOK
	}
	ok := s.probeUpstream()
	s.probeAt = time.Now()
	s.probeOK = ok
	return ok
}

func (s *server) probeUpstream() bool {
	// The probe shares the transport's read-only loopbackTLSConfig and the
	// package-level probeDialer instead of allocating a fresh tls.Config and
	// net.Dialer for every probe. tls.DialWithDialer is deliberately NOT used:
	// it would give the TCP dial and TLS handshake separate timeout windows.
	// One deadline is fixed before dialing and carried through the handshake,
	// matching the documented total 500 ms probe budget.
	deadline := time.Now().Add(upstreamProbeTimeout)
	rawConn, err := probeDialer.Dial("tcp", s.upstreamHost)
	if err != nil {
		return false
	}
	if err := rawConn.SetDeadline(deadline); err != nil {
		_ = rawConn.Close()
		return false
	}
	conn := tls.Client(rawConn, loopbackTLSConfig)
	if err := conn.Handshake(); err != nil {
		// Close the TLS connection itself, not the raw conn: tls.Conn.Close
		// closes the underlying connection too and keeps the close path in
		// one layer.
		_ = conn.Close()
		return false
	}
	_ = conn.Close()
	return true
}

// allowGetOrHead reports whether the request method is GET or HEAD. For any
// other method it writes a 405 response with an Allow header and returns
// false, so the read-only /health and / handlers share one guard.
func allowGetOrHead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if !allowGetOrHead(w, r) {
		return
	}
	status, state := http.StatusOK, "ok"
	if !s.upstreamReady() {
		status, state = http.StatusServiceUnavailable, "starting"
	}
	writeJSON(w, status, map[string]any{
		"status":  state,
		"service": serviceName,
		"uptime":  time.Since(s.started).Round(time.Second).String(),
	})
}

func (s *server) root(w http.ResponseWriter, r *http.Request) {
	if !allowGetOrHead(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   serviceName,
		"endpoint":  s.dohPath,
		"rateLimit": fmt.Sprintf("%d requests/%ds per client IP", s.rate.limit, s.rate.windowSec),
	})
}

// unavailableRetryAfter1 answers 503 with a one-second Retry-After hint. The
// client-table-capacity and invalid-client-IP paths share this response.
func unavailableRetryAfter1(w http.ResponseWriter, msg string) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusServiceUnavailable, msg)
}

// doh handles requests for the configured DoH path only; the root mux wrapper
// dispatches matching paths here, and validateDoHPath keeps the reserved
// /health and / paths free, so no additional path check is needed inside the
// handler.
func (s *server) doh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Acquire the concurrency slot before reading or decoding request data.
	// This keeps body parsing and base64 work bounded under a burst of unique
	// client IPs, which is important on the 0.25-vCPU tier.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "server concurrency limit reached")
		return
	}

	ip := parseClientIP(r, s.trustProxy)
	rateDecision, retryAfter := s.rate.allowWithRetryAfter(ip)
	switch rateDecision {
	case rateAllowed:
		// Continue with request validation and forwarding.
	case rateExceeded:
		w.Header().Set("Retry-After", strconv.FormatUint(retryAfter, 10))
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	case rateCapacityReached:
		unavailableRetryAfter1(w, "client tracking capacity reached")
		return
	case rateInvalidAddress:
		unavailableRetryAfter1(w, "client IP address unavailable")
		return
	}

	if r.Method == http.MethodPost {
		// The concurrency slot is already held, so a client trickling its body
		// would pin it for the full ReadTimeout. A DNS message is at most a few
		// KiB; bound the body read tightly. Best effort: the error is ignored
		// for ResponseWriters that do not support read deadlines.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadTimeout))
	}

	query, qEnd, status := readDNSQuery(r, s.maxBody, s.maxEncoded)
	if status != 0 {
		msg := "invalid DNS query"
		switch status {
		case http.StatusUnsupportedMediaType:
			msg = "Content-Type must be application/dns-message"
		case http.StatusRequestEntityTooLarge:
			msg = "DNS message exceeds configured size limit"
		case http.StatusRequestURITooLong:
			msg = "dns query parameter too large"
		}
		writeError(w, status, msg)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()

	uReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.upstreamURL, bytes.NewReader(query))
	if err != nil {
		writeError(w, http.StatusBadGateway, "dns upstream unavailable")
		return
	}
	uReq.Header.Set("Accept", "application/dns-message")
	uReq.Header.Set("Content-Type", "application/dns-message")

	resp, err := s.client.Do(uReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "dns upstream timeout")
			return
		}
		writeError(w, http.StatusBadGateway, "dns upstream unavailable")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s.maxBody+1))
		writeError(w, http.StatusBadGateway, "dns upstream returned an invalid HTTP status")
		return
	}
	if !isDNSMessageContentType(resp.Header.Get("Content-Type")) {
		writeError(w, http.StatusBadGateway, "dns upstream returned an invalid content type")
		return
	}
	if resp.ContentLength > s.maxBody {
		writeError(w, http.StatusBadGateway, "dns upstream response exceeds configured size limit")
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBody+1))
	if err != nil {
		// The per-request deadline also covers the body read.
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "dns upstream timeout")
			return
		}
		writeError(w, http.StatusBadGateway, "invalid DNS response from upstream")
		return
	}
	if int64(len(body)) > s.maxBody {
		writeError(w, http.StatusBadGateway, "invalid DNS response from upstream")
		return
	}
	// parseDNSMessage validates the response and returns the offset just past
	// its question section, so the question comparison below needs no second
	// parse of either message.
	respQEnd, ok := parseDNSMessage(body, true)
	if !ok {
		writeError(w, http.StatusBadGateway, "invalid DNS response from upstream")
		return
	}
	// Both messages passed parseDNSMessage, so each is at least 12 bytes and
	// qEnd/respQEnd mark the end of each question section.
	if !bytes.Equal(body[:2], query[:2]) {
		writeError(w, http.StatusBadGateway, "DNS response ID mismatch")
		return
	}
	queryFlags := binary.BigEndian.Uint16(query[2:4])
	responseFlags := binary.BigEndian.Uint16(body[2:4])
	if queryFlags&dnsOpcodeMask != responseFlags&dnsOpcodeMask {
		writeError(w, http.StatusBadGateway, "DNS response opcode mismatch")
		return
	}
	if !dnsQuestionEqual(query, qEnd, body, respQEnd) {
		writeError(w, http.StatusBadGateway, "DNS response question mismatch")
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// route dispatches the catch-all "/" mux pattern: the configured DoH path, the
// service-info root, or a JSON 404 (consistent with every other error body).
func (s *server) route(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case s.dohPath:
		s.doh(w, r)
	case "/":
		s.root(w, r)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func main() {
	port := strconv.Itoa(getenvInt("PORT", defaultPort, 1, 65535))
	dohPath := getenv("DOH_PATH", defaultDoHPath)
	rateLimit := getenvInt("RATE_LIMIT", defaultRateLimit, 1, maxRateLimit)
	rateWindow := getenvInt("RATE_WINDOW_SECONDS", defaultRateWindowSec, 1, maxRateWindowSec)
	maxBody := getenvInt("MAX_DNS_MESSAGE_BYTES", defaultMaxBodyBytes, minMaxBodyBytes, maxMaxBodyBytes)
	// concLimit, not maxConcurrency: the package-level const maxConcurrency is
	// the env-var validation bound; shadowing it with the parsed local value
	// was legal but made the two meanings easy to confuse.
	concLimit := getenvInt("MAX_CONCURRENCY", defaultConcurrency, 1, maxConcurrency)
	maxClients := getenvInt("MAX_CLIENT_IPS", defaultClientEntries, shardCount, maxClientEntries)
	trustProxy := getenvBool("TRUST_PROXY_HEADERS", false)

	if err := validateDoHPath(dohPath); err != nil {
		log.Fatalf("invalid DOH_PATH: %v", err)
	}

	// The upstream deadline is owned by the per-request context created in
	// doh (upstreamTimeout). Do not also set http.Client.Timeout or
	// ResponseHeaderTimeout here, or partial timeout behavior becomes hard to
	// reason about.
	transport := &http.Transport{
		// No Proxy: the loopback upstream must never go through an
		// environment-configured proxy.
		TLSClientConfig:     loopbackTLSConfig,
		MaxIdleConns:        concLimit,
		MaxIdleConnsPerHost: concLimit,
		MaxConnsPerHost:     concLimit,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}

	s := &server{
		client: &http.Client{
			Transport: transport,
			// Do not follow redirects: the gateway must validate the actual
			// upstream response status before forwarding anything to clients.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		upstreamURL:  fixedUpstreamURL,
		upstreamHost: fixedUpstreamHost,
		dohPath:      dohPath,
		rate:         newRateLimiter(rateLimit, rateWindow, maxClients),
		sem:          make(chan struct{}, concLimit),
		maxBody:      int64(maxBody),
		maxEncoded:   base64.RawURLEncoding.EncodedLen(maxBody),
		trustProxy:   trustProxy,
		started:      time.Now(),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		t := time.NewTicker(cleanupInterval(rateWindow))
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.rate.cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/", s.route)

	h := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       requestReadTimeout,
		// WriteTimeout is reset by net/http when a request's headers are
		// read, so it overlaps the 7s request-read window instead of
		// starting after it. 13s (7s read + 6s upstream) covers the worst
		// case where a slow body consumes the full read interval and the
		// upstream then uses its full deadline.
		WriteTimeout:   responseWriteTimeout,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: defaultMaxHeaderBytes,
	}

	// Bind before announcing startup so an invalid or occupied port is
	// reported here instead of racing with a signal in the goroutine below.
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen on :%s: %v", port, err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Serve(listener)
	}()
	log.Printf("DoH gateway listening on :%s path=%s upstream=%s rate=%d/%ds maxClients=%d maxConcurrency=%d maxBody=%d trustProxy=%t",
		port, dohPath, fixedUpstreamURL, rateLimit, rateWindow, maxClients, concLimit, maxBody, trustProxy)

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received; draining in-flight requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := h.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v; forcing close", err)
			_ = h.Close()
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
}
