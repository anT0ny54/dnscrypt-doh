package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testQuery(id byte) []byte {
	return []byte{
		0x12, id, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
}

func testResponse(query []byte) []byte {
	body := append([]byte(nil), query...)
	body[2] = 0x81
	body[3] = 0x80
	body[6] = 0x00
	body[7] = 0x01
	body = append(body,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		93, 184, 216, 34,
	)
	return body
}

func queryWithQName(id byte, qname []byte) []byte {
	body := []byte{
		0x12, id, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	body = append(body, qname...)
	body = append(body, 0x00, 0x01, 0x00, 0x01)
	return body
}

// queryWithAdditional builds a one-question query whose additional section
// holds a single record of the given type (OPT/41 is the only valid choice).
func queryWithAdditional(id byte, rtype uint16) []byte {
	body := []byte{
		0x12, id, 0x01, 0x00, // ID, standard query flags
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x01, // ARCOUNT = 1
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
		// Additional record: root owner name, given type, class 4096 (UDP
		// payload size for OPT), zero TTL, empty RDATA.
		0x00,
		byte(rtype >> 8), byte(rtype),
		0x10, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	return body
}

type trackingBody struct {
	read bool
}

func (b *trackingBody) Read(_ []byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func (b *trackingBody) Close() error {
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newTestGateway(upstream string) *server {
	u, _ := url.Parse(upstream)
	return &server{
		client: &http.Client{
			Transport: http.DefaultTransport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		upstream:   u,
		dohPath:    defaultDoHPath,
		rate:       newRateLimiter(99, 60, 256),
		sem:        make(chan struct{}, 2),
		maxBody:    defaultMaxBodyBytes,
		trustProxy: false,
		started:    time.Now(),
	}
}

func TestValidDNSMessages(t *testing.T) {
	query := testQuery(1)
	response := testResponse(query)
	if !validDNSMessage(query, false) {
		t.Fatal("expected query to validate")
	}
	if !validDNSMessage(response, true) {
		t.Fatal("expected response to validate")
	}
	bad := append([]byte(nil), response...)
	bad[len(bad)-1] = 0
	bad[30] = 0x40
	if validDNSMessage(bad, true) {
		t.Fatal("expected malformed DNS name to be rejected")
	}
}

func TestValidDNSMessageRejectsForwardCompressionPointer(t *testing.T) {
	qname := []byte{0xc0, 0x10, 0x00, 0x01, 0x00, 0x01}
	query := queryWithQName(10, qname)
	if validDNSMessage(query, false) {
		t.Fatal("expected forward compression pointer to be rejected")
	}
}

func TestValidDNSMessageRejectsMultipleQuestions(t *testing.T) {
	query := testQuery(12)
	query[5] = 0x02
	if validDNSMessage(query, false) {
		t.Fatal("expected multiple questions to be rejected")
	}
}

func TestValidDNSMessageRejectsAnswerRecordsInQuery(t *testing.T) {
	query := testQuery(20)
	query[6] = 0x00
	query[7] = 0x01 // ANCOUNT = 1 must never appear in a query
	if validDNSMessage(query, false) {
		t.Fatal("expected query with answer records to be rejected")
	}
}

func TestValidDNSMessageRejectsAuthorityRecordsInQuery(t *testing.T) {
	query := testQuery(21)
	query[8] = 0x00
	query[9] = 0x01 // NSCOUNT = 1 must never appear in a query
	if validDNSMessage(query, false) {
		t.Fatal("expected query with authority records to be rejected")
	}
}

func TestValidDNSMessageAcceptsOPTAdditionalInQuery(t *testing.T) {
	query := queryWithAdditional(22, dnsTypeOPT)
	if !validDNSMessage(query, false) {
		t.Fatal("expected query with EDNS OPT additional record to validate")
	}
}

func TestValidDNSMessageRejectsNonOPTAdditionalInQuery(t *testing.T) {
	query := queryWithAdditional(23, 1) // A record in the additional section
	if validDNSMessage(query, false) {
		t.Fatal("expected query with non-OPT additional record to be rejected")
	}
}

func TestValidateDoHPath(t *testing.T) {
	for _, ok := range []string{"/dns-query", "/doh", "/a/b"} {
		if err := validateDoHPath(ok); err != nil {
			t.Fatalf("validateDoHPath(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "dns-query", "/", "/health"} {
		if err := validateDoHPath(bad); err == nil {
			t.Fatalf("validateDoHPath(%q) = nil, want error", bad)
		}
	}
}

func TestValidDNSMessageAcceptsMaximumRecordCount(t *testing.T) {
	response := testResponse(testQuery(13))
	count := uint16(maxDNSRecords)
	response[6] = byte(count >> 8)
	response[7] = byte(count)
	record := []byte{
		0x00,       // root owner name
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00, 0x00, 0x00, 0x3c, // TTL
		0x00, 0x00, // zero-length RDATA
	}
	for i := 1; i < maxDNSRecords; i++ {
		response = append(response, record...)
	}
	if !validDNSMessage(response, true) {
		t.Fatal("expected exactly 4096 records to validate")
	}
}

func TestValidDNSMessageRejectsExcessiveRecordCount(t *testing.T) {
	response := testResponse(testQuery(13))
	count := uint16(maxDNSRecords + 1)
	response[6] = byte(count >> 8)
	response[7] = byte(count)
	if validDNSMessage(response, true) {
		t.Fatal("expected excessive record count to be rejected")
	}
}

func TestDoHRejectsAdvertisedOversizedPOST(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	s.maxBody = 64
	body := &trackingBody{}
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, nil)
	req.Body = body
	req.Header.Set("Content-Type", "application/dns-message")
	req.ContentLength = 65
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if body.read {
		t.Fatal("oversized request body was read despite Content-Length")
	}
}

func TestRateLimiterAllocatesShardMapsLazily(t *testing.T) {
	r := newRateLimiter(1, 60, 256)
	for i := range r.shards {
		if r.shards[i].m != nil {
			t.Fatalf("shard %d map allocated before first request", i)
		}
	}

	ip := netip.MustParseAddr("192.0.2.11")
	if !r.allow(ip) {
		t.Fatal("first request should be allowed")
	}
	used := 0
	for i := range r.shards {
		if r.shards[i].m != nil {
			used++
		}
	}
	if used != 1 {
		t.Fatalf("allocated shard maps = %d, want 1", used)
	}
}

func TestRateLimiterRoundsUpShardCapacity(t *testing.T) {
	r := newRateLimiter(1, 60, 65)
	if got, want := r.maxEntriesPerShard, 2; got != want {
		t.Fatalf("maxEntriesPerShard = %d, want %d (65 entries across 64 shards rounds up)", got, want)
	}
	if got, want := r.maxEntriesPerShard*shardCount, 128; got != want {
		t.Fatalf("aggregate capacity = %d, want %d", got, want)
	}
}

func TestGetenvBoolUsesFallbackForInvalidValue(t *testing.T) {
	t.Setenv("BOOL_TEST", "invalid")
	if got := getenvBool("BOOL_TEST", true); !got {
		t.Fatal("invalid boolean value should use true fallback")
	}

	for _, value := range []string{"0", "false", "no", "off"} {
		t.Setenv("BOOL_TEST", value)
		if got := getenvBool("BOOL_TEST", true); got {
			t.Fatalf("%q should parse as false", value)
		}
	}

	for _, value := range []string{"1", "true", "yes", "on"} {
		t.Setenv("BOOL_TEST", value)
		if got := getenvBool("BOOL_TEST", false); !got {
			t.Fatalf("%q should parse as true", value)
		}
	}
}

func TestValidDNSMessageRejectsOversizedDNSName(t *testing.T) {
	qname := make([]byte, 0, 257)
	for i := 0; i < 4; i++ {
		qname = append(qname, 63)
		qname = append(qname, bytes.Repeat([]byte{'a'}, 63)...)
	}
	qname = append(qname, 0)
	query := queryWithQName(11, qname)
	if validDNSMessage(query, false) {
		t.Fatal("expected DNS name over 255 bytes to be rejected")
	}
}

func TestParseClientIPCanonicalizesMappedIPv4(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "127.0.0.1:8080"
	r.Header.Set("CF-Connecting-IP", "::ffff:192.0.2.1")
	got := parseClientIP(r, true)
	want := netip.MustParseAddr("192.0.2.1")
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRateLimiterFullShardFailsClosed(t *testing.T) {
	r := newRateLimiter(99, 60, 64)
	var first, second netip.Addr
	seen := make(map[uint64]netip.Addr)
	for i := 1; i < 256; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		idx := addrHash(ip) % shardCount
		if prior, ok := seen[idx]; ok {
			first, second = prior, ip
			break
		}
		seen[idx] = ip
	}
	if !first.IsValid() || !second.IsValid() {
		t.Fatal("failed to find two client IPs sharing a rate-limit shard")
	}
	if !r.allow(first) {
		t.Fatal("first client should be allowed")
	}
	if r.allow(second) {
		t.Fatal("new client should fail closed when its shard is full")
	}
	idx := int(addrHash(first) % shardCount)
	if got := len(r.shards[idx].m); got != 1 {
		t.Fatalf("full shard size = %d, want 1", got)
	}
}

func TestRateLimiterUsesValueEntriesAndEnforcesLimit(t *testing.T) {
	r := newRateLimiter(2, 60, 64)
	ip := netip.MustParseAddr("192.0.2.10")
	if !r.allow(ip) || !r.allow(ip) {
		t.Fatal("first two requests should be allowed")
	}
	if r.allow(ip) {
		t.Fatal("third request should be rejected")
	}
}

func TestDoHPostNormalizesUpstreamToPOST(t *testing.T) {
	query := testQuery(2)
	response := testResponse(query)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("upstream method = %s, want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(query) {
			t.Errorf("upstream body does not match query")
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/dns-message" {
		t.Fatalf("content type = %q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "45" {
		t.Fatalf("content length = %q, want 45", got)
	}
	if string(rec.Body.Bytes()) != string(response) {
		t.Fatalf("response body mismatch")
	}
}

func TestDoHGetIsDecodedAndForwardedAsPOST(t *testing.T) {
	query := testQuery(3)
	response := testResponse(query)
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("upstream method = %s, want POST", r.Method)
		}
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(response)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	encoded := base64.RawURLEncoding.EncodeToString(query)
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?dns="+url.QueryEscape(encoded), nil)
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if string(gotBody) != string(query) {
		t.Fatal("GET query was not forwarded as decoded DNS wire data")
	}
}

func TestDoHRejectsInvalidInputBeforeConcurrencyAcquire(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader("not-dns"))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := len(s.sem); got != 0 {
		t.Fatalf("semaphore occupancy = %d, want 0", got)
	}
}

func TestDoHRejectsOversizedPOST(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	s.maxBody = 16
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader("0123456789abcdefghijklmnop"))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestDoHRejectsInvalidUpstreamContentType(t *testing.T) {
	query := testQuery(14)
	response := testResponse(query)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestDoHRejectsUpstreamResponseLargerThanConfiguredLimit(t *testing.T) {
	query := testQuery(15)
	body := &trackingBody{}
	u, _ := url.Parse("http://127.0.0.1:8053/dns-query")
	s := newTestGateway(u.String())
	s.maxBody = 64
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": []string{"application/dns-message"}},
			ContentLength: 65,
			Body:          body,
			Request:       r,
		}, nil
	})
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if body.read {
		t.Fatal("oversized upstream response body was read despite Content-Length")
	}
}

func TestDoHRejectsInvalidUpstreamResponse(t *testing.T) {
	query := testQuery(4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-a-dns-response"))
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestDoHRejectsMismatchedResponseID(t *testing.T) {
	query := testQuery(5)
	response := testResponse(query)
	response[1] = 0x99
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestDoHRejectsMismatchedResponseQuestion(t *testing.T) {
	query := testQuery(16)
	response := testResponse(query)
	// Corrupt the response question: flip a byte inside the QNAME. The message
	// is still well-formed DNS, but it no longer answers the asked question.
	response[17] = 'x'
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestDoHRejectsUnsupportedMethod(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodPut, defaultDoHPath, strings.NewReader("ignored"))
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, POST" {
		t.Fatalf("Allow = %q, want GET, POST", got)
	}
}

func TestDoHRejectsInvalidGETQuery(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?dns=not-valid-dns", nil)
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestDoHRateLimitUsesConfiguredRetryAfter(t *testing.T) {
	query := testQuery(6)
	response := testResponse(query)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	s.rate = newRateLimiter(1, 37, 64)

	req1 := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req1.Header.Set("Content-Type", "application/dns-message")
	req1.RemoteAddr = "192.0.2.20:1234"
	rec1 := httptest.NewRecorder()
	s.doh(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req2.Header.Set("Content-Type", "application/dns-message")
	req2.RemoteAddr = "192.0.2.20:5678"
	rec2 := httptest.NewRecorder()
	s.doh(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", rec2.Code)
	}
	if got := rec2.Header().Get("Retry-After"); got != "37" {
		t.Fatalf("Retry-After = %q, want 37", got)
	}
}

func TestDoHRejectsNonSuccessUpstreamStatus(t *testing.T) {
	query := testQuery(7)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestDoHRejectsOversizedUpstreamResponse(t *testing.T) {
	query := testQuery(8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oversized := append([]byte(nil), testResponse(query)...)
		oversized = append(oversized, bytes.Repeat([]byte{0}, defaultMaxBodyBytes)...)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(oversized)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestDoHRejectsUpstreamRedirect(t *testing.T) {
	query := testQuery(9)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("redirect target should never receive the DNS request")
	}))
	defer target.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer upstream.Close()

	s := newTestGateway(upstream.URL)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestHealthReportsUpstreamReadiness(t *testing.T) {
	// Upstream accepting connections: health is OK.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	s := newTestGateway("https://" + ln.Addr().String() + "/dns-query")
	rec := httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Upstream refusing connections: health reports 503 starting state.
	s = newTestGateway("http://127.0.0.1:1/dns-query")
	rec = httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestDNSQuestionSection(t *testing.T) {
	query := testQuery(17)
	section, ok := dnsQuestionSection(query)
	if !ok {
		t.Fatal("expected question section from valid query")
	}
	// QNAME example.com + QTYPE A + QCLASS IN = 13 + 2 + 2 bytes.
	if want := 17; len(section) != want {
		t.Fatalf("question section length = %d, want %d", len(section), want)
	}
	if !bytes.Equal(section, query[12:]) {
		t.Fatal("question section should extend to the end of a bare query")
	}
	truncated := query[:len(query)-2]
	if _, ok := dnsQuestionSection(truncated); ok {
		t.Fatal("expected truncated question to be rejected")
	}
}
