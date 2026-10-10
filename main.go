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
	defaultPort            = "8080"
	defaultDoHPath         = "/dns-query"
	fixedUpstreamURL       = "https://127.0.0.1:8053/dns-query"
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
	shardCount             = 64
	upstreamTimeout        = 6 * time.Second
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
	r := &rateLimiter{
		limit:      uint32(limit),
		windowSec:  uint64(windowSec),
		maxEntries: int64(maxEntries),
	}
	// Allocate shard maps lazily. A large MAX_CLIENT_IPS value should not
	// reserve map buckets for every shard before the first client arrives.
	return r
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

func (r *rateLimiter) allow(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	// Rate-limit IPv6 clients per /64: a single subscriber normally controls
	// a whole /64, so per-address keys would let one host mint unlimited
	// identities and bypass the per-client quota.
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			ip = p.Addr()
		}
	}
	nowWindow := uint64(time.Now().Unix()) / r.windowSec
	idx := int(addrHash(ip) % shardCount)
	sh := &r.shards[idx]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	entry, ok := sh.m[ip]
	if !ok {
		// The global entry counter is the hard capacity guard. A previous
		// per-shard-only cap could reject a client merely because its hash
		// bucket filled early, even when other shards still had capacity.
		if !r.reserveEntry() {
			return false
		}
		entry = rateEntry{window: nowWindow}
	}
	if sh.m == nil {
		sh.m = make(map[netip.Addr]rateEntry)
	}

	if entry.window != nowWindow {
		entry.window = nowWindow
		entry.count = 0
	}
	if entry.count >= r.limit {
		return false
	}
	entry.count++
	sh.m[ip] = entry
	return true
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
	nowWindow := uint64(time.Now().Unix()) / r.windowSec
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, v := range sh.m {
			if v.window != nowWindow {
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

type server struct {
	client     *http.Client
	upstream   *url.URL
	dohPath    string
	rate       *rateLimiter
	sem        chan struct{}
	maxBody    int64
	trustProxy bool
	started    time.Time

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

func getenvInt(key string, fallback, min, max int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || v < min || v > max {
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

func parseClientIP(r *http.Request, trustProxy bool) netip.Addr {
	parse := func(value string) netip.Addr {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return netip.Addr{}
		}
		// Strip IPv6 zone identifiers so they cannot be used to mint
		// additional rate-limit identities for the same address.
		return ip.Unmap().WithZone("")
	}

	if trustProxy {
		if h := r.Header.Get("CF-Connecting-IP"); h != "" {
			if ip := parse(h); ip.IsValid() {
				return ip
			}
		}
		if h := r.Header.Get("X-Forwarded-For"); h != "" {
			if first := strings.TrimSpace(strings.SplitN(h, ",", 2)[0]); first != "" {
				if ip := parse(first); ip.IsValid() {
					return ip
				}
			}
		}
	}

	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		if ip := parse(host); ip.IsValid() {
			return ip
		}
	}
	return parse(r.RemoteAddr)
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

func isDNSMessageContentType(v string) bool {
	return strings.EqualFold(strings.TrimSpace(strings.Split(v, ";")[0]), "application/dns-message")
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
			if pointer < 12 || pointer >= offset || pointer >= len(msg) {
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
			if labelLen > 63 || offset+1+int(labelLen) > len(msg) {
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

// dnsQuestionSection returns the question section (QNAME + QTYPE + QCLASS)
// of a DNS message that contains exactly one question.
func dnsQuestionSection(msg []byte) ([]byte, bool) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return nil, false
	}
	end, ok := dnsNameEnd(msg, 12)
	if !ok || end+4 > len(msg) {
		return nil, false
	}
	return msg[12 : end+4], true
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
	offset := 12
	{
		var nameOK bool
		if offset, nameOK = dnsNameEnd(msg, offset); !nameOK || offset+4 > len(msg) {
			return 0, false
		}
		offset += 4 // QTYPE + QCLASS
	}
	qEnd = offset

	for i := 0; i < recordCount; i++ {
		var nameOK bool
		if offset, nameOK = dnsNameEnd(msg, offset); !nameOK || offset+10 > len(msg) {
			return 0, false
		}
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
	}

	return qEnd, offset == len(msg)
}

func validDNSMessage(msg []byte, wantResponse bool) bool {
	_, ok := parseDNSMessage(msg, wantResponse)
	return ok
}

// readDNSQuery extracts and validates the DNS wire message from a DoH
// request, returning the message along with qEnd, the offset just past its
// question section, so the caller can compare question sections without a
// second parse. The status return is a non-zero HTTP status code on failure.
func readDNSQuery(r *http.Request, maxBody int64) (msg []byte, qEnd int, status int) {
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
		qEnd, ok := parseDNSMessage(body, false)
		if !ok {
			return nil, 0, http.StatusBadRequest
		}
		return body, qEnd, 0
	}

	encoded := r.URL.Query().Get("dns")
	if encoded == "" {
		return nil, 0, http.StatusBadRequest
	}
	maxEncoded := base64.RawURLEncoding.EncodedLen(int(maxBody))
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
	qEnd, ok := parseDNSMessage(decoded, false)
	if !ok {
		return nil, 0, http.StatusBadRequest
	}
	return decoded, qEnd, 0
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
	d := &net.Dialer{Timeout: upstreamProbeTimeout}
	// The probe shares the transport's read-only loopbackTLSConfig instead
	// of allocating a fresh tls.Config for every probe.
	conn, err := tls.DialWithDialer(d, "tcp", s.upstream.Host, loopbackTLSConfig)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
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
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   serviceName,
		"endpoint":  s.dohPath,
		"rateLimit": fmt.Sprintf("%d requests/%ds per client IP", s.rate.limit, s.rate.windowSec),
	})
}

// doh handles requests for the configured DoH path only; the mux dispatches
// exactly matching paths here and validateDoHPath keeps reserved paths free,
// so no additional path check is needed inside the handler.
func (s *server) doh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
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
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "server concurrency limit reached"})
		return
	}

	ip := parseClientIP(r, s.trustProxy)
	if !s.rate.allow(ip) {
		w.Header().Set("Retry-After", strconv.FormatUint(s.rate.windowSec, 10))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}

	query, qEnd, status := readDNSQuery(r, s.maxBody)
	if status != 0 {
		switch status {
		case http.StatusUnsupportedMediaType:
			writeJSON(w, status, map[string]string{"error": "Content-Type must be application/dns-message"})
		case http.StatusRequestEntityTooLarge:
			writeJSON(w, status, map[string]string{"error": "DNS message exceeds configured size limit"})
		case http.StatusRequestURITooLong:
			writeJSON(w, status, map[string]string{"error": "dns query parameter too large"})
		default:
			writeJSON(w, status, map[string]string{"error": "invalid DNS query"})
		}
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()

	uReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.upstream.String(), bytes.NewReader(query))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "dns upstream unavailable"})
		return
	}
	uReq.Header.Set("Accept", "application/dns-message")
	uReq.Header.Set("Content-Type", "application/dns-message")

	resp, err := s.client.Do(uReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "dns upstream timeout"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "dns upstream unavailable"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s.maxBody+1))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "dns upstream returned an invalid HTTP status"})
		return
	}
	if !isDNSMessageContentType(resp.Header.Get("Content-Type")) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "dns upstream returned an invalid content type"})
		return
	}
	if resp.ContentLength > s.maxBody {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "dns upstream response exceeds configured size limit"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBody+1))
	if err != nil {
		// The per-request deadline also covers the body read.
		if errors.Is(err, context.DeadlineExceeded) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "dns upstream timeout"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid DNS response from upstream"})
		return
	}
	if int64(len(body)) > s.maxBody {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid DNS response from upstream"})
		return
	}
	// parseDNSMessage validates the response and returns the offset just past
	// its question section, so the question comparison below needs no second
	// parse of either message.
	respQEnd, ok := parseDNSMessage(body, true)
	if !ok {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid DNS response from upstream"})
		return
	}
	// Both messages passed parseDNSMessage, so each is at least 12 bytes and
	// qEnd/respQEnd mark the end of each question section.
	if binary.BigEndian.Uint16(body[:2]) != binary.BigEndian.Uint16(query[:2]) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "DNS response ID mismatch"})
		return
	}
	if !bytes.Equal(query[12:qEnd], body[12:respQEnd]) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "DNS response question mismatch"})
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func main() {
	port := getenv("PORT", defaultPort)
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

	upstream, err := url.Parse(fixedUpstreamURL)
	if err != nil {
		log.Fatalf("invalid fixed DoH upstream: %v", err)
	}

	// The upstream deadline is owned by the per-request context created in
	// doh (upstreamTimeout). Do not also set http.Client.Timeout or
	// ResponseHeaderTimeout here, or partial timeout behavior becomes hard to
	// reason about.
	transport := &http.Transport{
		Proxy:               nil,
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
		upstream:   upstream,
		dohPath:    dohPath,
		rate:       newRateLimiter(rateLimit, rateWindow, maxClients),
		sem:        make(chan struct{}, concLimit),
		maxBody:    int64(maxBody),
		trustProxy: trustProxy,
		started:    time.Now(),
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == s.dohPath {
			s.doh(w, r)
			return
		}
		if r.URL.Path == "/" {
			s.root(w, r)
			return
		}
		http.NotFound(w, r)
	})

	h := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       7 * time.Second,
		WriteTimeout:      7 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}

	// Bind before announcing startup so an invalid or occupied port is
	// reported here instead of racing with a signal in the goroutine below.
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen on 0.0.0.0:%s: %v", port, err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Serve(listener)
	}()
	log.Printf("DoH gateway listening on 0.0.0.0:%s path=%s upstream=%s rate=%d/%ds maxClients=%d maxConcurrency=%d maxBody=%d trustProxy=%t",
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
