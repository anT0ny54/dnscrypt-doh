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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultPort            = "8080"
	defaultDoHPath         = "/dns-query"
	fixedUpstreamURL       = "https://127.0.0.1:8053/dns-query"
	defaultRateLimit       = 99
	defaultRateWindowSec   = 60
	defaultMaxBodyBytes    = 4096
	defaultConcurrency     = 8
	defaultClientEntries   = 10000
	defaultMaxHeaderBytes  = 16 << 10
	defaultMaxGetQuerySize = 12 << 10
	minMaxBodyBytes        = 512
	maxMaxBodyBytes        = 65535
	maxRateLimit           = 1000000
	maxRateWindowSec       = 86400
	maxConcurrency         = 512
	maxClientEntries       = 1000000
	maxDNSNameBytes        = 255
	maxDNSRecords          = 4096
	dnsTypeOPT             = 41
	shardCount             = 64
	upstreamTimeout        = 6 * time.Second
	upstreamProbeTimeout   = 500 * time.Millisecond
	upstreamProbeCacheTTL  = 2 * time.Second
	shutdownGrace          = 5 * time.Second
)

type rateEntry struct {
	window uint64
	count  uint32
}

type rateShard struct {
	mu sync.Mutex
	m  map[netip.Addr]rateEntry
}

type rateLimiter struct {
	shards             [shardCount]rateShard
	limit              uint32
	windowSec          uint64
	maxEntriesPerShard int
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
		limit:     uint32(limit),
		windowSec: uint64(windowSec),
		// Round up so the configured client-entry limit is fully usable.
		// Aggregate capacity can exceed the configured value by at most
		// shardCount-1 entries.
		maxEntriesPerShard: (maxEntries + shardCount - 1) / shardCount,
	}
	// Allocate shard maps lazily. A large MAX_CLIENT_IPS value should not
	// reserve map buckets for every shard before the first client arrives.
	return r
}

func addrHash(a netip.Addr) uint64 {
	b := a.As16()
	var x uint64 = 0x9e3779b97f4a7c15
	for i := 0; i < 16; i += 8 {
		v := uint64(b[i]) | uint64(b[i+1])<<8 | uint64(b[i+2])<<16 | uint64(b[i+3])<<24 |
			uint64(b[i+4])<<32 | uint64(b[i+5])<<40 | uint64(b[i+6])<<48 | uint64(b[i+7])<<56
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
	nowWindow := uint64(time.Now().Unix()) / r.windowSec
	idx := int(addrHash(ip) % shardCount)
	sh := &r.shards[idx]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	entry, ok := sh.m[ip]
	if !ok {
		if len(sh.m) >= r.maxEntriesPerShard {
			// Periodic cleanup owns expiration. Do not scan a full shard on the
			// request path, or a client churn burst could turn this into O(n)
			// work per rejected identity.
			return false
		}
		entry = rateEntry{window: nowWindow}
	}
	if sh.m == nil {
		sh.m = make(map[netip.Addr]rateEntry, r.maxEntriesPerShard)
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

func (r *rateLimiter) cleanup() {
	nowWindow := uint64(time.Now().Unix()) / r.windowSec
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for k, v := range sh.m {
			if v.window != nowWindow {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
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
		return ip.Unmap()
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

// doHPath reports whether path is the configured DoH endpoint. dohPath is
// guaranteed non-empty and non-reserved by getenv + validateDoHPath in main,
// so no empty-configured fallback is needed here.
func doHPath(path, configured string) bool {
	return path == configured
}

// validateDoHPath rejects paths that would shadow the reserved /health and /
// endpoints in the mux.
func validateDoHPath(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("DOH_PATH must start with '/': %q", path)
	}
	switch path {
	case "/", "/health":
		return fmt.Errorf("DOH_PATH %q conflicts with a reserved endpoint", path)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func isDNSMessageContentType(v string) bool {
	if v == "" {
		return false
	}
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

func validDNSMessage(msg []byte, wantResponse bool) bool {
	if len(msg) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if (flags&0x8000 != 0) != wantResponse {
		return false
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))
	if qdCount != 1 {
		return false
	}
	// A query carries no answer or authority records. Additional records are
	// only allowed for EDNS(0), whose resource type is OPT (41).
	if !wantResponse && (anCount != 0 || nsCount != 0) {
		return false
	}

	recordCount := anCount + nsCount + arCount
	if recordCount > maxDNSRecords {
		return false
	}

	offset := 12
	for i := 0; i < qdCount; i++ {
		var ok bool
		if offset, ok = dnsNameEnd(msg, offset); !ok || offset+4 > len(msg) {
			return false
		}
		offset += 4 // QTYPE + QCLASS
	}

	for i := 0; i < recordCount; i++ {
		var ok bool
		if offset, ok = dnsNameEnd(msg, offset); !ok || offset+10 > len(msg) {
			return false
		}
		rtype := binary.BigEndian.Uint16(msg[offset : offset+2])
		rdataLen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
		offset += 10
		if offset+rdataLen > len(msg) {
			return false
		}
		offset += rdataLen
		if !wantResponse && rtype != dnsTypeOPT {
			return false
		}
	}

	return offset == len(msg)
}

func readDNSQuery(r *http.Request, maxBody int64) ([]byte, int) {
	if r.Method == http.MethodPost {
		if !isDNSMessageContentType(r.Header.Get("Content-Type")) {
			return nil, http.StatusUnsupportedMediaType
		}
		if r.ContentLength > maxBody {
			return nil, http.StatusRequestEntityTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			return nil, http.StatusBadRequest
		}
		if int64(len(body)) > maxBody {
			return nil, http.StatusRequestEntityTooLarge
		}
		if !validDNSMessage(body, false) {
			return nil, http.StatusBadRequest
		}
		return body, 0
	}

	encoded := r.URL.Query().Get("dns")
	if encoded == "" {
		return nil, http.StatusBadRequest
	}
	if len(encoded) > defaultMaxGetQuerySize {
		return nil, http.StatusRequestURITooLong
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, http.StatusBadRequest
	}
	if int64(len(decoded)) > maxBody {
		return nil, http.StatusRequestEntityTooLarge
	}
	if !validDNSMessage(decoded, false) {
		return nil, http.StatusBadRequest
	}
	return decoded, 0
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
	conn, err := tls.DialWithDialer(d, "tcp", s.upstream.Host, &tls.Config{
		// Loopback-only probe of the dnscrypt-proxy local_doh listener, which
		// uses the container's bundled self-signed localhost certificate.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	})
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
	if !s.upstreamReady() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":  "starting",
			"service": "minimal-hagezi-doh",
			"uptime":  time.Since(s.started).Round(time.Second).String(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "minimal-hagezi-doh",
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
		"service":   "minimal-hagezi-doh",
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

	ip := parseClientIP(r, s.trustProxy)
	if !s.rate.allow(ip) {
		w.Header().Set("Retry-After", strconv.FormatUint(s.rate.windowSec, 10))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}

	query, status := readDNSQuery(r, s.maxBody)
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

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "server concurrency limit reached"})
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
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
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
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid DNS response from upstream"})
		return
	}
	if int64(len(body)) > s.maxBody || !validDNSMessage(body, true) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid DNS response from upstream"})
		return
	}
	if len(body) < 2 || len(query) < 2 || binary.BigEndian.Uint16(body[:2]) != binary.BigEndian.Uint16(query[:2]) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "DNS response ID mismatch"})
		return
	}
	queryQuestion, ok := dnsQuestionSection(query)
	if !ok {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid DNS query"})
		return
	}
	responseQuestion, ok := dnsQuestionSection(body)
	if !ok || !bytes.Equal(queryQuestion, responseQuestion) {
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
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			// dnscrypt-proxy's local DoH service uses its bundled localhost
			// self-signed certificate. This transport is used only for the
			// fixed loopback upstream, never for public destinations.
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // loopback-only fixed upstream
		},
		MaxIdleConns:          concLimit,
		MaxIdleConnsPerHost:   concLimit,
		MaxConnsPerHost:       concLimit,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		ExpectContinueTimeout: 1 * time.Second,
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
		t := time.NewTicker(time.Duration(rateWindow) * time.Second)
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
		if doHPath(r.URL.Path, s.dohPath) {
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
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       7 * time.Second,
		WriteTimeout:      7 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("DoH gateway listening on 0.0.0.0:%s path=%s upstream=%s rate=%d/%ds maxClients=%d maxConcurrency=%d maxBody=%d trustProxy=%t",
			port, dohPath, fixedUpstreamURL, rateLimit, rateWindow, maxClients, concLimit, maxBody, trustProxy)
		errCh <- h.ListenAndServe()
	}()

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
