package main

import (
	"context"
	"encoding/base64"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort          = "8080"
	defaultDoHPath       = "/dns-query"
	defaultUpstream      = "http://127.0.0.1:8053/dns-query"
	defaultRateLimit     = 99
	defaultRateWindowSec = 60
	defaultMaxBodyBytes  = 65535
	defaultConcurrency   = 128
	defaultClientEntries = 250000
	shardCount           = 64
	upstreamTimeout      = 6 * time.Second
)

type rateEntry struct {
	window uint64
	count  uint16
}

type rateShard struct {
	mu sync.Mutex
	m  map[netip.Addr]*rateEntry
}

type rateLimiter struct {
	shards             [shardCount]rateShard
	limit              uint16
	windowSec          uint64
	maxEntriesPerShard int
}

func newRateLimiter(limit int, windowSec int, maxEntries int) *rateLimiter {
	if limit < 1 {
		limit = defaultRateLimit
	}
	if windowSec < 1 {
		windowSec = defaultRateWindowSec
	}
	if maxEntries < shardCount {
		maxEntries = defaultClientEntries
	}
	r := &rateLimiter{
		limit:              uint16(limit),
		windowSec:          uint64(windowSec),
		maxEntriesPerShard: (maxEntries + shardCount - 1) / shardCount,
	}
	for i := range r.shards {
		r.shards[i].m = make(map[netip.Addr]*rateEntry, r.maxEntriesPerShard)
	}
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
			// Only scan when a shard is full. Remove one expired identity if possible.
			for k, v := range sh.m {
				if v.window != nowWindow {
					delete(sh.m, k)
					break
				}
			}
			if len(sh.m) >= r.maxEntriesPerShard {
				return false
			}
		}
		entry = &rateEntry{window: nowWindow}
		sh.m[ip] = entry
	}

	if entry.window != nowWindow {
		entry.window = nowWindow
		entry.count = 0
	}
	if entry.count >= r.limit {
		return false
	}
	entry.count++
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
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func getenvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func parseClientIP(r *http.Request, trustProxy bool) netip.Addr {
	if trustProxy {
		if h := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); h != "" {
			if ip, err := netip.ParseAddr(h); err == nil {
				return ip
			}
		}
		if h := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); h != "" {
			if first := strings.TrimSpace(strings.Split(h, ",")[0]); first != "" {
				if ip, err := netip.ParseAddr(first); err == nil {
					return ip
				}
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip, e := netip.ParseAddr(host); e == nil {
			return ip
		}
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}
	return netip.Addr{}
}

func doHPath(path, configured string) bool {
	if configured == "" {
		return path == defaultDoHPath
	}
	return path == configured
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

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
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

func (s *server) doh(w http.ResponseWriter, r *http.Request) {
	if !doHPath(r.URL.Path, s.dohPath) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := parseClientIP(r, s.trustProxy)
	if !s.rate.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
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

	if r.Method == http.MethodPost {
		if !isDNSMessageContentType(r.Header.Get("Content-Type")) {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/dns-message"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	} else {
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing dns query parameter"})
			return
		}
		if len(encoded) > 90000 {
			writeJSON(w, http.StatusRequestURITooLong, map[string]string{"error": "dns query parameter too large"})
			return
		}
		if _, err := base64.RawURLEncoding.DecodeString(encoded); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid base64url dns query"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()

	uReq := r.Clone(ctx)
	uReq.URL.Scheme = s.upstream.Scheme
	uReq.URL.Host = s.upstream.Host
	uReq.URL.Path = s.upstream.Path
	if s.upstream.RawQuery != "" {
		uReq.URL.RawQuery = s.upstream.RawQuery
	}
	uReq.Host = s.upstream.Host
	uReq.RequestURI = ""

	// Do not forward client/proxy identity to the local dnscrypt-proxy instance.
	for _, h := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "CF-Connecting-IP", "CF-Ray",
	} {
		uReq.Header.Del(h)
	}
	uReq.Header.Set("Accept", "application/dns-message")

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

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, s.maxBody))
}

func main() {
	port := getenv("PORT", defaultPort)
	dohPath := getenv("DOH_PATH", defaultDoHPath)
	upstreamRaw := getenv("DOH_UPSTREAM", defaultUpstream)
	rateLimit := getenvInt("RATE_LIMIT", defaultRateLimit)
	rateWindow := getenvInt("RATE_WINDOW_SECONDS", defaultRateWindowSec)
	maxBody := getenvInt("MAX_DNS_MESSAGE_BYTES", defaultMaxBodyBytes)
	maxConcurrency := getenvInt("MAX_CONCURRENCY", defaultConcurrency)
	maxClients := getenvInt("MAX_CLIENT_IPS", defaultClientEntries)
	trustProxy := getenvBool("TRUST_PROXY_HEADERS", true)

	upstream, err := url.Parse(upstreamRaw)
	if err != nil || upstream.Scheme == "" || upstream.Host == "" || upstream.Path == "" {
		log.Fatalf("invalid DOH_UPSTREAM: %q", upstreamRaw)
	}

	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: upstreamTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	s := &server{
		client:     &http.Client{Transport: transport, Timeout: upstreamTimeout},
		upstream:   upstream,
		dohPath:    dohPath,
		rate:       newRateLimiter(rateLimit, rateWindow, maxClients),
		sem:        make(chan struct{}, maxConcurrency),
		maxBody:    int64(maxBody),
		trustProxy: trustProxy,
		started:    time.Now(),
	}

	go func() {
		t := time.NewTicker(time.Duration(rateWindow) * time.Second)
		defer t.Stop()
		for range t.C {
			s.rate.cleanup()
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
		MaxHeaderBytes:    16 << 10,
	}

	log.Printf("DoH gateway listening on 0.0.0.0:%s path=%s upstream=%s rate=%d/%ds maxClients=%d maxConcurrency=%d trustProxy=%t",
		port, dohPath, upstream.String(), rateLimit, rateWindow, maxClients, maxConcurrency, trustProxy)

	err = h.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
