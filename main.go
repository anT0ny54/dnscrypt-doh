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
	defaultConcurrency     = 16
	defaultClientEntries   = 8192
	defaultMaxHeaderBytes  = 16 << 10
	defaultMaxGetQuerySize = 12 << 10
	// maxGetQueryFastFail is the raw-query length above which a separator-less
	// GET query is rejected with 414 before parsing. "&" is the only separator
	// tolerated here: url.ParseQuery rejects query settings containing ";",
	// so a semicolon must not let an oversized query bypass the fast-fail.
	maxGetQueryFastFail    = defaultMaxGetQuerySize + len("dns=")
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
	// Normalize IPv4-mapped IPv6 addresses first; otherwise the /64 grouping
	// below would collapse every mapped IPv4 client into one shared quota.
	// parseClientIP already unmaps, so this protects other callers.
	ip = ip.Unmap()
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
	now := time.Now().Unix()
	if now < 0 {
		// A pre-epoch wall clock wraps to ~2^64 as uint64, so every request
		// would land in a fresh window and per-client rate limiting would
		// silently switch off. Pin to the epoch so behavior degrades to one
		// long window instead of no limiting.
		now = 0
	}
	nowUnix := uint64(now)
	nowWindow := nowUnix / r.windowSec
	var entry rateEntry
	var ok bool
	if sh.m != nil {
		entry, ok = sh.m[ip]
	}
	if !ok {
		// The global entry counter is the hard capacity guard. A previous
		// per-shard-only cap could reject a client merely because its hash
		// bucket filled early, even when other shards still had capacity.
		if !r.reserveEntry() {
			return rateCapacityReached, 0
		}
		// Do not allocate an otherwise-unused shard map for a client that
		// cannot be tracked because the global table is already full.
		if sh.m == nil {
			sh.m = make(map[netip.Addr]rateEntry)
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
		nowUnix := time.Now().Unix()
		if nowUnix < 0 {
			nowUnix = 0
		}
		nowWindow := uint64(nowUnix) / r.windowSec
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
// for concurrent use. It has no Timeout of its own: the probe's context
// carries the single deadline for the dial and the TLS handshake together.
var probeDialer net.Dialer

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
	// rateDesc is the root endpoint's rate-limit line, formatted once at
	// startup so GET / does not run fmt.Sprintf on every request.
	rateDesc     string
	started      time.Time

	// Cached upstream probe result so health checks do not perform a fresh
	// TCP+TLS handshake on every call.
	probeMu sync.Mutex
	probeAt time.Time
	probeOK bool
	// probeRunning marks an in-flight probe so concurrent health checks use
	// the last cached result instead of serializing behind the handshake.
	probeRunning bool
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback, lo, hi int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	// strconv.Atoi accepts a leading "+", but net.Listen does not: a value
	// like "+8080" passed range validation and then died at bind time with
	// "listen tcp: lookup +8080: ..." instead of falling back. Reject it so
	// numeric env vars behave like the health check's port normalization.
	if strings.HasPrefix(raw, "+") {
		return fallback
	}
	v, err := strconv.Atoi(raw)
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

// validateDoHPath rejects non-canonical public paths and paths that would
// shadow the reserved /health and / endpoints.
func validateDoHPath(dohPath string) error {
	if !strings.HasPrefix(dohPath, "/") {
		return fmt.Errorf("DOH_PATH must start with '/': %q", dohPath)
	}
	if strings.ContainsAny(dohPath, "?#%") {
		// Query/fragment delimiters and percent signs are forbidden to keep the
		// configured decoded path unambiguous with its escaped URL spelling.
		return fmt.Errorf("DOH_PATH must not contain '?', '#' or '%%': %q", dohPath)
	}
	if canonicalHTTPPath(dohPath) != dohPath {
		return fmt.Errorf("DOH_PATH must be canonical; repeated slashes and dot segments are not allowed: %q", dohPath)
	}
	switch dohPath {
	case "/", "/health":
		return fmt.Errorf("DOH_PATH %q conflicts with a reserved endpoint", dohPath)
	}
	return nil
}

// canonicalHTTPPath applies slash/dot-segment normalization while preserving
// one trailing slash. Requiring the configured path to already be canonical
// avoids endpoint ambiguity across clients and intermediaries.
//
// The caller (validateDoHPath) has already verified that p starts with "/".
func canonicalHTTPPath(p string) string {
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
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

// drainBoundedBody discards up to limit bytes from an upstream error response
// so the loopback HTTP connection can be reused. Reading beyond the configured
// size cap is unnecessary because the response is being rejected anyway; one
// byte past the cap is enough to prove the body is fully consumed when it is
// small. All upstream-rejection paths must drain: returning with an unread
// body forces net/http to close the connection, defeating MaxIdleConns reuse
// during upstream error bursts.
func drainBoundedBody(r io.Reader, limit int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r, limit+1))
}

// dnsNameEnd validates a DNS name, including compression pointers, and returns
// the number of bytes consumed at the containing offset.
func dnsNameEnd(msg []byte, offset int) (int, bool) {
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

// dnsNameEndUncompressed validates an uncompressed DNS name and returns the
// offset just after it. It inspects label-length octets only, so arbitrary
// bytes inside a label (including 0xc0-0xff) are not mistaken for pointers.
func dnsNameEndUncompressed(msg []byte, offset int) (int, bool) {
	nameLen := 0
	for {
		if offset >= len(msg) {
			return 0, false
		}
		labelLen := msg[offset]
		if labelLen == 0 {
			// The label branch below rejects any name whose labels already
			// total 255 bytes, so nameLen+1 (the root label) is at most 255
			// here and needs no further length check.
			return offset + 1, true
		}
		// Question names must be uncompressed. The 0x40 and 0x80 label forms
		// are reserved, and 0xc0 begins a compression pointer.
		if labelLen&0xc0 != 0 {
			return 0, false
		}
		labelSize := int(labelLen)
		if offset+1+labelSize > len(msg) {
			return 0, false
		}
		nameLen += 1 + labelSize
		if nameLen >= maxDNSNameBytes {
			// A terminating root label must also fit within the 255-byte limit.
			return 0, false
		}
		offset += 1 + labelSize
	}
}

// validEDNSOptions checks the TLV framing of an EDNS(0) OPT record's RDATA.
// Each option contains a 2-byte code, a 2-byte length, and exactly that many
// option-data bytes. Unknown option codes remain valid and are kept opaque.
// The caller guarantees start <= end <= len(msg).
func validEDNSOptions(msg []byte, start, end int) bool {
	for start < end {
		if end-start < 4 {
			return false
		}
		optionLen := int(binary.BigEndian.Uint16(msg[start+2 : start+4]))
		start += 4
		if optionLen > end-start {
			return false
		}
		start += optionLen
	}
	return true
}

// parseDNSMessage validates the DNS message structure and also returns qEnd,
// the offset just past the question section (QNAME + QTYPE + QCLASS). Callers
// can slice msg[12:qEnd] to compare validated question sections without
// re-parsing them. On failure qEnd is 0.
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
	// uncompressed question directly instead of looping over a count that
	// cannot repeat. Only label-length octets determine name encoding; bytes
	// inside a label are arbitrary and must not be scanned for pointer markers.
	offset, nameOK := dnsNameEndUncompressed(msg, 12)
	if !nameOK || offset+4 > len(msg) {
		return 0, false
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
			rdataStart := offset + 10
			if rdataStart+rdataLen > len(msg) {
				return 0, false
			}
			rdataEnd := rdataStart + rdataLen
			offset = rdataEnd

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
				if !validEDNSOptions(msg, rdataStart, rdataEnd) {
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

// readLimited reads at most limit bytes from r and reports whether the source
// held more than that. sizeHint (a Content-Length, or <= 0 when unknown)
// pre-sizes the buffer so a typical DNS message is read without repeated
// io.ReadAll growth.
func readLimited(r io.Reader, limit, sizeHint int64) (data []byte, tooLarge bool, err error) {
	capacity := int64(512)
	if sizeHint > 0 && sizeHint <= limit {
		capacity = sizeHint + 1
	}
	buf := bytes.NewBuffer(make([]byte, 0, capacity))
	if _, err = buf.ReadFrom(io.LimitReader(r, limit+1)); err != nil {
		return nil, false, err
	}
	if int64(buf.Len()) > limit {
		return nil, true, nil
	}
	return buf.Bytes(), false, nil
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
		body, tooLarge, err := readLimited(r.Body, maxBody, r.ContentLength)
		if err != nil {
			return nil, 0, http.StatusBadRequest
		}
		if tooLarge {
			return nil, 0, http.StatusRequestEntityTooLarge
		}
		msg = body
	} else {
		// Fail fast only when a long raw query has no "&" separator. Extra
		// parameters are tolerated, so the total query may exceed the DNS
		// encoding ceiling while its dns value remains valid. MaxHeaderBytes
		// bounds the amount of query data parsed when multiple parameters exist.
		rawQuery := r.URL.RawQuery
		if len(rawQuery) > maxGetQueryFastFail && !strings.Contains(rawQuery, "&") {
			return nil, 0, http.StatusRequestURITooLong
		}
		values, err := url.ParseQuery(rawQuery)
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
		// Go's base64 decoder ignores CR and LF, but raw base64url values in
		// RFC 8484 query parameters must not contain line breaks. Reject them
		// before decoding so malformed input cannot be silently normalized.
		if strings.ContainsAny(encoded, "\r\n") {
			return nil, 0, http.StatusBadRequest
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
	if time.Since(s.probeAt) < upstreamProbeCacheTTL {
		ok := s.probeOK
		s.probeMu.Unlock()
		return ok
	}
	if s.probeRunning {
		// Another health check is already performing the handshake. Return
		// the last cached result rather than blocking this caller for up to
		// upstreamProbeTimeout; the next check after the probe completes sees
		// the fresh result.
		ok := s.probeOK
		s.probeMu.Unlock()
		return ok
	}
	s.probeRunning = true
	s.probeMu.Unlock()

	ok := s.probeUpstream()

	s.probeMu.Lock()
	s.probeRunning = false
	s.probeAt = time.Now()
	s.probeOK = ok
	s.probeMu.Unlock()
	return ok
}

func (s *server) probeUpstream() bool {
	// One context deadline covers both the TCP dial and the TLS handshake, so
	// the probe really is bounded by upstreamProbeTimeout in total. A
	// Dialer.Timeout plus a separate post-dial deadline would allow up to
	// twice that. HandshakeContext closes the connection when the deadline
	// expires, and the probe shares the transport's read-only
	// loopbackTLSConfig instead of allocating a new one.
	ctx, cancel := context.WithTimeout(context.Background(), upstreamProbeTimeout)
	defer cancel()
	rawConn, err := probeDialer.DialContext(ctx, "tcp", s.upstreamHost)
	if err != nil {
		return false
	}
	// tls.Conn.Close also closes the underlying connection.
	conn := tls.Client(rawConn, loopbackTLSConfig)
	defer conn.Close()
	return conn.HandshakeContext(ctx) == nil
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
	// Pre-size the response map: the orchestrator polls /health on a fixed
	// interval, and a literal map would grow through reallocations on every
	// single call.
	body := make(map[string]any, 3)
	body["status"] = state
	body["service"] = serviceName
	body["uptime"] = time.Since(s.started).Round(time.Second).String()
	writeJSON(w, status, body)
}

func (s *server) root(w http.ResponseWriter, r *http.Request) {
	if !allowGetOrHead(w, r) {
		return
	}
	// Pre-size the map like in health: these keys are fixed, so the capacity
	// hint avoids the literal-map growth reallocations on every request.
	body := make(map[string]any, 3)
	body["service"] = serviceName
	body["endpoint"] = s.dohPath
	body["rateLimit"] = s.rateDesc
	writeJSON(w, http.StatusOK, body)
}

// unavailableRetryAfter1 answers 503 with a one-second Retry-After hint. The
// concurrency-gate, client-table-capacity and invalid-client-IP paths share
// this response.
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
		unavailableRetryAfter1(w, "server concurrency limit reached")
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

	isPost := r.Method == http.MethodPost
	if isPost {
		// The concurrency slot is already held, so a client trickling its body
		// would pin it for the full ReadTimeout. A DNS message is at most a few
		// KiB; bound the body read tightly. Best effort: the error is ignored
		// for ResponseWriters that do not support read deadlines.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadTimeout))
	}

	query, qEnd, status := readDNSQuery(r, s.maxBody, s.maxEncoded)
	if isPost {
		// Clear the short body deadline now that the body has been read. Once
		// the body hits EOF, net/http starts a background read on the
		// connection to detect client disconnects; if the 2-second deadline
		// were still armed, that read would time out while the request waits
		// for the upstream and net/http would cancel the request context,
		// aborting valid slow lookups with a 502. The upstream exchange is
		// bounded by its own context (upstreamTimeout) instead.
		_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
	}
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

	// net/http consumes interim 1xx responses, so the final status here is
	// always >= 200; the old < 200 arm was unreachable. RFC 8484 mandates
	// exactly 200 for a successful DoH response, so reject anything else.
	if resp.StatusCode != http.StatusOK {
		drainBoundedBody(resp.Body, s.maxBody)
		writeError(w, http.StatusBadGateway, "dns upstream returned an invalid HTTP status")
		return
	}
	if !isDNSMessageContentType(resp.Header.Get("Content-Type")) {
		drainBoundedBody(resp.Body, s.maxBody)
		writeError(w, http.StatusBadGateway, "dns upstream returned an invalid content type")
		return
	}
	if resp.ContentLength > s.maxBody {
		drainBoundedBody(resp.Body, s.maxBody)
		writeError(w, http.StatusBadGateway, "dns upstream response exceeds configured size limit")
		return
	}

	body, tooLarge, err := readLimited(resp.Body, s.maxBody, resp.ContentLength)
	if err != nil {
		// The per-request deadline also covers the body read.
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "dns upstream timeout")
			return
		}
		writeError(w, http.StatusBadGateway, "invalid DNS response from upstream")
		return
	}
	if tooLarge {
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

// ServeHTTP dispatches on the decoded request path without ServeMux's automatic
// dot-segment/repeated-slash redirects. This keeps unknown paths consistently
// JSON 404s and avoids turning malformed POST paths into redirected requests.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// URL.Path is decoded by net/http. Without this guard, an alternate escaped
	// spelling such as "/%68ealth" or "/dns%2Dquery" would dispatch to the same
	// endpoint as its canonical spelling. RawPath is set when the request's
	// escaped path differs from Go's canonical escaping of Path; reject those
	// aliases rather than silently normalizing them.
	if r.URL.RawPath != "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	switch r.URL.Path {
	case "/health":
		s.health(w, r)
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
		rateDesc:     fmt.Sprintf("%d requests/%ds per client IP", rateLimit, rateWindow),
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

	h := &http.Server{
		Handler:           s,
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
