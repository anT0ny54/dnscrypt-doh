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
	"strconv"
	"strings"
	"sync"
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

func testResponseWithPrefixedCompressedOwner(query []byte) []byte {
	body := append([]byte(nil), query...)
	body[2] = 0x81
	body[3] = 0x80
	body[6] = 0x00
	body[7] = 0x01
	// The owner name is "www" followed by a pointer to the prior question
	// name. This is the valid labels-then-pointer form of DNS compression.
	body = append(body,
		0x03, 'w', 'w', 'w', 0xc0, 0x0c,
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

func queryWithOPTOptions(id byte, options []byte) []byte {
	body := queryWithAdditional(id, dnsTypeOPT)
	body[38] = byte(len(options) >> 8)
	body[39] = byte(len(options))
	return append(body, options...)
}

func testResourceRecord(rtype uint16, rdata []byte) []byte {
	rr := []byte{
		0x00, // root owner name
		byte(rtype >> 8), byte(rtype),
		0x00, 0x01, // IN class
		0x00, 0x00, 0x00, 0x00, // zero TTL
		byte(len(rdata) >> 8), byte(len(rdata)),
	}
	return append(rr, rdata...)
}

type trackingBody struct {
	read bool
}

type readDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *readDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func (b *trackingBody) Read(_ []byte) (int, error) {
	b.read = true
	return 0, io.EOF
}

func (b *trackingBody) Close() error {
	return nil
}

type countingReader struct {
	remaining int
	read      int
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n := len(p)
	for i := range p {
		p[i] = 'x'
	}
	r.remaining -= n
	r.read += n
	return n, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newTestGateway(upstream string) *server {
	u, err := url.Parse(upstream)
	if err != nil {
		panic(err)
	}
	return &server{
		client: &http.Client{
			Transport: http.DefaultTransport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		upstreamURL:  upstream,
		upstreamHost: u.Host,
		dohPath:      defaultDoHPath,
		rate:         newRateLimiter(99, 60, 256),
		sem:          make(chan struct{}, 2),
		maxBody:      defaultMaxBodyBytes,
		maxEncoded:   base64.RawURLEncoding.EncodedLen(defaultMaxBodyBytes),
		trustProxy:   false,
		started:      time.Now(),
	}
}

// allow is a test-only convenience wrapper around allowWithRetryAfter; the
// production handler uses allowWithRetryAfter directly to also get the
// Retry-After value.
func (r *rateLimiter) allow(ip netip.Addr) rateLimitResult {
	result, _ := r.allowWithRetryAfter(ip)
	return result
}

// validDNSMessage is a test-only convenience wrapper around parseDNSMessage;
// the production handler uses parseDNSMessage directly to also get qEnd.
func validDNSMessage(msg []byte, wantResponse bool) bool {
	_, ok := parseDNSMessage(msg, wantResponse)
	return ok
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
	// Turn the answer's name pointer (bytes 29-30) into a forward pointer to
	// offset 64, which must be rejected.
	bad := append([]byte(nil), response...)
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

func TestValidDNSResponseAcceptsLabelPrefixBeforeCompressionPointer(t *testing.T) {
	response := testResponseWithPrefixedCompressedOwner(testQuery(55))
	if !validDNSMessage(response, true) {
		t.Fatal("expected an uncompressed label prefix followed by a backward pointer to validate")
	}
}

func TestValidDNSResponseRejectsCompressionPointerToRootTerminator(t *testing.T) {
	response := testResponse(testQuery(11))
	// Offset 24 is the question's root terminator. A pointer must target a
	// non-empty label-length octet, not the terminator itself.
	response[30] = 0x18
	if validDNSMessage(response, true) {
		t.Fatal("expected pointer to a root terminator to be rejected")
	}
}

func TestValidDNSResponseRejectsNestedCompressionPointer(t *testing.T) {
	response := testResponse(testQuery(12))
	response[7] = 2 // Add a second answer record.
	// The first answer owner starts at offset 29 and is itself a pointer to the
	// question name. The second answer must not point to that pointer.
	response = append(response, []byte{
		0xc0, 0x1d, // owner pointer to the first answer's pointer
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00, 0x00, 0x00, 0x3c, // TTL
		0x00, 0x00, // empty RDATA
	}...)
	if validDNSMessage(response, true) {
		t.Fatal("expected nested compression pointer to be rejected")
	}
}

func TestValidDNSResponseRejectsCompressionTargetOverlappingPointer(t *testing.T) {
	response := testResponse(testQuery(19))
	// The answer owner pointer begins at offset 29 and targets offset 27.
	// Make offset 27 look like a four-byte label whose payload crosses the
	// pointer itself; subsequent RR header bytes then look like a terminating
	// name. The target is earlier, but it is not a complete prior name.
	response[27] = 4
	response[28] = 'x'
	response[29] = 0xc0
	response[30] = 0x1b // pointer to offset 27
	if validDNSMessage(response, true) {
		t.Fatal("expected compression target overlapping its pointer to be rejected")
	}
}

func TestValidDNSMessageRejectsCompressedQuestionName(t *testing.T) {
	// A backward pointer inside the question section is invalid: compression
	// is only permitted inside resource records, so the question parser must
	// reject it even when the pointer targets an earlier label.
	qname := []byte{0x01, 'x', 0xc0, 0x0c}
	query := queryWithQName(17, qname)
	if validDNSMessage(query, false) {
		t.Fatal("expected compressed question name to be rejected")
	}
}

func TestValidDNSMessageAcceptsHighBytesInsideQuestionLabel(t *testing.T) {
	// Only label-length octets can introduce compression pointers. Bytes in
	// the label payload are arbitrary DNS name octets, even when >= 0xc0.
	qname := []byte{0x03, 'a', 0xc0, 0xff, 0x00}
	query := queryWithQName(18, qname)
	if !validDNSMessage(query, false) {
		t.Fatal("expected high bytes inside an uncompressed label to be accepted")
	}
}

func TestValidDNSMessageValidatesEDNSOptionFraming(t *testing.T) {
	for name, options := range map[string][]byte{
		"truncated option header": {0x00, 0x01, 0x00},
		"truncated option data":   {0x00, 0x01, 0x00, 0x02, 0xaa},
	} {
		t.Run(name, func(t *testing.T) {
			query := queryWithOPTOptions(42, options)
			if validDNSMessage(query, false) {
				t.Fatal("expected malformed EDNS option framing to be rejected")
			}
		})
	}

	validOptions := []byte{0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb}
	if !validDNSMessage(queryWithOPTOptions(43, validOptions), false) {
		t.Fatal("expected a well-formed EDNS option to be accepted")
	}
}

func TestValidDNSResponseRejectsMalformedEDNSOptionFraming(t *testing.T) {
	response := testResponse(testQuery(44))
	response[11] = 1 // ARCOUNT = 1; append a final OPT record.
	response = append(response, []byte{
		0x00,       // root owner name
		0x00, 0x29, // OPT (41)
		0x10, 0x00, // UDP payload size
		0x00, 0x00, 0x00, 0x00, // extended RCODE, version, flags
		0x00, 0x03, // RDLENGTH = 3, too short for an option header
		0x00, 0x01, 0x00,
	}...)
	if validDNSMessage(response, true) {
		t.Fatal("expected malformed upstream EDNS option framing to be rejected")
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

func TestValidDNSMessageRejectsTSIGAndSIG0ClientQueries(t *testing.T) {
	// These records have complete wire framing and the standard Additional
	// placement, but this gateway intentionally does not authenticate them.
	tsigRDATA := []byte{
		0x0b, 'h', 'm', 'a', 'c', '-', 's', 'h', 'a', '2', '5', '6', 0, // algorithm name
		0, 0, 0, 0, 0, 1, // 48-bit signing time
		0x01, 0x2c, // fudge = 300 seconds
		0, 1, 0xaa, // one-byte MAC
		0x12, 0x34, // original ID
		0, 0, // error
		0, 0, // other data length = 0
	}
	tsigRR := []byte{
		0x03, 'k', 'e', 'y', 0, // owner name
		0x00, 0xfa, // TSIG
		0x00, 0xff, // ANY class
		0, 0, 0, 0, // TTL = 0
		byte(len(tsigRDATA) >> 8), byte(len(tsigRDATA)),
	}
	tsigRR = append(tsigRR, tsigRDATA...)

	// SIG(0): Type Covered = 0, algorithm, labels, original TTL, expiration,
	// inception, key tag, signer name (root), and one signature octet.
	sig0RDATA := []byte{
		0, 0, // Type Covered = 0 identifies SIG(0)
		1, 0, // algorithm and labels
		0, 0, 0, 0, // original TTL
		0, 0, 0, 1, // expiration
		0, 0, 0, 1, // inception
		0, 1, // key tag
		0,    // signer name = root
		0xaa, // signature
	}
	sig0RR := []byte{
		0,          // owner name = root
		0x00, 0x18, // SIG
		0x00, 0xff, // ANY class
		0, 0, 0, 0, // TTL = 0
		byte(len(sig0RDATA) >> 8), byte(len(sig0RDATA)),
	}
	sig0RR = append(sig0RR, sig0RDATA...)

	for name, rr := range map[string][]byte{
		"TSIG":   tsigRR,
		"SIG(0)": sig0RR,
	} {
		t.Run(name, func(t *testing.T) {
			query := testQuery(52)
			query[11] = 1 // ARCOUNT = 1
			query = append(query, rr...)
			if validDNSMessage(query, false) {
				t.Fatalf("expected %s-signed client query to be rejected by the unsigned-query profile", name)
			}
		})
	}
}

func TestValidDNSMessageRejectsDuplicateOPTRecords(t *testing.T) {
	query := queryWithAdditional(24, dnsTypeOPT)
	query[10], query[11] = 0, 2 // ARCOUNT = 2
	query = append(query, []byte{
		0x00,       // root owner name
		0x00, 0x29, // OPT (41)
		0x10, 0x00, // UDP payload size
		0x00, 0x00, 0x00, 0x00, // extended RCODE, version, flags
		0x00, 0x00, // empty RDATA
	}...)
	if validDNSMessage(query, false) {
		t.Fatal("expected duplicate OPT records to be rejected")
	}
}

func TestValidDNSResponseRejectsOPTOutsideAdditionalSection(t *testing.T) {
	response := testResponse(testQuery(27))
	response[7] = 2 // ANCOUNT = 2, placing the appended OPT in the answer section.
	response = append(response, []byte{
		0x00,       // root owner name
		0x00, 0x29, // OPT (41)
		0x10, 0x00, // UDP payload size
		0x00, 0x00, 0x00, 0x00, // extended RCODE, version, flags
		0x00, 0x00, // empty RDATA
	}...)
	if validDNSMessage(response, true) {
		t.Fatal("expected OPT outside the additional section to be rejected")
	}
}

func TestValidDNSResponseAcceptsOPTBeforeOtherAdditionalRecord(t *testing.T) {
	response := testResponse(testQuery(28))
	response[10], response[11] = 0, 2 // ARCOUNT = 2: OPT followed by an A record.
	response = append(response, []byte{
		0x00,       // root owner name
		0x00, 0x29, // OPT (41)
		0x10, 0x00, // UDP payload size
		0x00, 0x00, 0x00, 0x00, // extended RCODE, version, flags
		0x00, 0x00, // empty RDATA
		0x00,       // root owner name
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00, 0x00, 0x00, 0x3c, // TTL
		0x00, 0x00, // empty RDATA
	}...)
	if !validDNSMessage(response, true) {
		t.Fatal("expected OPT before another additional record to be accepted")
	}
}

func TestValidDNSResponseRejectsDuplicateOPTRecords(t *testing.T) {
	response := testResponse(testQuery(29))
	response[10], response[11] = 0, 2 // ARCOUNT = 2: duplicate OPT records.
	opt := []byte{
		0x00,       // root owner name
		0x00, 0x29, // OPT (41)
		0x10, 0x00, // UDP payload size
		0x00, 0x00, 0x00, 0x00, // extended RCODE, version, flags
		0x00, 0x00, // empty RDATA
	}
	response = append(response, opt...)
	response = append(response, opt...)
	if validDNSMessage(response, true) {
		t.Fatal("expected duplicate OPT records to be rejected")
	}
}

func TestValidDNSResponseRequiresTSIGAndSIG0LastInAdditional(t *testing.T) {
	opt := testResourceRecord(dnsTypeOPT, nil)
	tsig := testResourceRecord(dnsTypeTSIG, nil)
	sig0 := testResourceRecord(dnsTypeSIG, []byte{0x00, 0x00})
	other := testResourceRecord(1, nil)

	tests := []struct {
		name       string
		records    [][]byte
		answerTSIG bool
		wantValid  bool
	}{
		{
			name:      "OPT may precede final TSIG",
			records:   [][]byte{opt, tsig},
			wantValid: true,
		},
		{
			name:      "TSIG may not precede another additional record",
			records:   [][]byte{tsig, opt},
			wantValid: false,
		},
		{
			name:       "TSIG may not appear in Answer",
			records:    [][]byte{tsig},
			answerTSIG: true,
			wantValid:  false,
		},
		{
			name:      "OPT may precede final SIG(0)",
			records:   [][]byte{opt, sig0},
			wantValid: true,
		},
		{
			name:      "SIG(0) may not precede another additional record",
			records:   [][]byte{sig0, opt},
			wantValid: false,
		},
		{
			name:      "ordinary SIG may precede another additional record",
			records:   [][]byte{testResourceRecord(dnsTypeSIG, []byte{0x00, 0x01}), other},
			wantValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			response := testResponse(testQuery(30))
			if tc.answerTSIG {
				response[7]++ // Add the TSIG record to the Answer section.
			} else {
				response[10] = byte(len(tc.records) >> 8)
				response[11] = byte(len(tc.records))
			}
			for _, rr := range tc.records {
				response = append(response, rr...)
			}
			if got := validDNSMessage(response, true); got != tc.wantValid {
				t.Fatalf("validDNSMessage = %t, want %t", got, tc.wantValid)
			}
		})
	}
}

func TestValidDNSMessageRejectsNonRootOPTName(t *testing.T) {
	query := testQuery(25)
	query[11] = 1 // ARCOUNT = 1
	query = append(query, []byte{
		0x01, 'x', 0x00, // non-root owner name
		0x00, 0x29, // OPT (41)
		0x10, 0x00, // UDP payload size
		0x00, 0x00, 0x00, 0x00, // extended RCODE, version, flags
		0x00, 0x00, // empty RDATA
	}...)
	if validDNSMessage(query, false) {
		t.Fatal("expected OPT with a non-root owner name to be rejected")
	}
}

func TestValidateDoHPath(t *testing.T) {
	for _, ok := range []string{"/dns-query", "/doh", "/a/b", "/doh/"} {
		if err := validateDoHPath(ok); err != nil {
			t.Fatalf("validateDoHPath(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"dns-query",
		"/",
		"/health",
		"/doh//",
		"/doh/./",
		"/doh/../doh",
		"/doh?dns=",
		"/doh#fragment",
		"//doh",
		"/doh%2Fx",
	} {
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

func TestHealthAndRootJSONBodies(t *testing.T) {
	// The key order is part of the wire format; these bodies must not change
	// shape when the responses are encoded from structs.
	s := newTestGateway("http://127.0.0.1:1/dns-query")
	s.rateDesc = "99 requests/60s per client IP"

	rec := httptest.NewRecorder()
	s.root(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got, want := rec.Body.String(), `{"endpoint":"/dns-query","rateLimit":"99 requests/60s per client IP","service":"minimal-hagezi-doh"}`+"\n"; got != want {
		t.Fatalf("root body = %q, want %q", got, want)
	}

	rec = httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status = %d, want 503 for an unreachable upstream", rec.Code)
	}
	if want, got := `{"service":"minimal-hagezi-doh","status":"starting","uptime":"`, rec.Body.String(); !strings.HasPrefix(got, want) {
		t.Fatalf("health body = %q, want prefix %q", got, want)
	}
}

func TestHealthcheckURLUsesGatewayPortFallback(t *testing.T) {
	for value, want := range map[string]string{
		"9090":   "9090",
		" 9091 ": "9091",
		"":       "8080",
	} {
		t.Setenv("PORT", value)
		if got, wantURL := healthcheckURL(), "http://127.0.0.1:"+want+"/health"; got != wantURL {
			t.Fatalf("PORT=%q: healthcheckURL() = %q, want %q", value, got, wantURL)
		}
	}
}

func TestRunHealthcheckDoesNotFollowRedirects(t *testing.T) {
	targetHits := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	if got := runHealthcheck(origin.URL); got != 1 {
		t.Fatalf("redirect response: runHealthcheck = %d, want 1", got)
	}
	select {
	case <-targetHits:
		t.Fatal("health check followed a redirect to another service")
	default:
	}
}

func TestRunHealthcheckExitCodes(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"service":"minimal-hagezi-doh","status":"ok","uptime":"1s"}`)
	}))
	defer ok.Close()
	if got := runHealthcheck(ok.URL + "/health"); got != 0 {
		t.Fatalf("healthy gateway: runHealthcheck = %d, want 0", got)
	}

	starting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer starting.Close()
	if got := runHealthcheck(starting.URL + "/health"); got != 1 {
		t.Fatalf("503 response: runHealthcheck = %d, want 1", got)
	}

	if got := runHealthcheck("http://127.0.0.1:1/health"); got != 1 {
		t.Fatalf("refused connection: runHealthcheck = %d, want 1", got)
	}
}

func TestRunHealthcheckRejectsUnrelatedOrInvalid200Responses(t *testing.T) {
	for name, body := range map[string]string{
		"plain text":       "ok",
		"wrong service":    `{"service":"other-service","status":"ok","uptime":"1s"}`,
		"starting service": `{"service":"minimal-hagezi-doh","status":"starting","uptime":"1s"}`,
		"malformed JSON":   `{"service":"minimal-hagezi-doh","status":"ok"`,
		"trailing JSON":    `{"service":"minimal-hagezi-doh","status":"ok","uptime":"1s"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			if got := runHealthcheck(server.URL); got != 1 {
				t.Fatalf("runHealthcheck = %d, want 1 for %s", got, name)
			}
		})
	}
}

func TestRunHealthcheckRejectsOversized200Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // force an unknown-length, chunked response
		}
		_, _ = io.WriteString(w, `{"service":"minimal-hagezi-doh","status":"ok","uptime":"1s"}`+strings.Repeat(" ", maxHealthcheckBodyBytes))
	}))
	defer server.Close()
	if got := runHealthcheck(server.URL); got != 1 {
		t.Fatalf("oversized response: runHealthcheck = %d, want 1", got)
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
	if r.allow(ip) != rateAllowed {
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

func TestRateLimiterTracksGlobalCapacityAcrossShards(t *testing.T) {
	r := newRateLimiter(1, 60, 65)
	if got, want := r.entries.Load(), int64(0); got != want {
		t.Fatalf("initial entries = %d, want %d", got, want)
	}
	for i := 1; i <= 65; i++ {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i / 256), byte(i % 256)})
		if r.allow(ip) != rateAllowed {
			t.Fatalf("client %d was rejected before global capacity was reached", i)
		}
	}
	if got := r.entries.Load(); got != 65 {
		t.Fatalf("entries = %d, want 65", got)
	}
	if r.allow(netip.MustParseAddr("203.0.113.254")) == rateAllowed {
		t.Fatal("client beyond global capacity should be rejected")
	}
}

func TestRateLimiterDoesNotAllocateShardMapAtCapacity(t *testing.T) {
	r := newRateLimiter(99, 60, 64)
	for i := 1; i <= 64; i++ {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i / 256), byte(i)})
		if got := r.allow(ip); got != rateAllowed {
			t.Fatalf("client %d decision = %v, want rateAllowed", i, got)
		}
	}

	// Select a candidate mapped to a shard that has not needed a map yet.
	// Since the global capacity is full, this identity must be rejected
	// without allocating that otherwise-unused map.
	var candidate netip.Addr
	for i := 1; i < 256; i++ {
		ip := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
		idx := int(addrHash(ip) % shardCount)
		if r.shards[idx].m == nil {
			candidate = ip
			break
		}
	}
	if !candidate.IsValid() {
		t.Fatal("failed to find an unused shard")
	}

	idx := int(addrHash(candidate) % shardCount)
	if got := r.allow(candidate); got != rateCapacityReached {
		t.Fatalf("decision = %v, want rateCapacityReached", got)
	}
	if r.shards[idx].m != nil {
		t.Fatalf("shard %d map allocated for a rejected client", idx)
	}
	if got := r.entries.Load(); got != 64 {
		t.Fatalf("entries = %d, want 64", got)
	}
}

func TestPortConfigurationFallsBackForInvalidValues(t *testing.T) {
	for _, value := range []string{"not-a-port", "0", "65536", "-1", "+8080", "+0"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PORT", value)
			if got := getenvInt("PORT", defaultPort, 1, 65535); got != defaultPort {
				t.Fatalf("PORT=%q resolved to %d, want default %d", value, got, defaultPort)
			}
		})
	}
	t.Setenv("PORT", "9090")
	if got := getenvInt("PORT", defaultPort, 1, 65535); got != 9090 {
		t.Fatalf("valid PORT resolved to %d, want 9090", got)
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

func TestRateLimiterSharedShardDoesNotReduceGlobalCapacity(t *testing.T) {
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
	if r.allow(first) != rateAllowed || r.allow(second) != rateAllowed {
		t.Fatal("clients sharing a shard should both be admitted while global capacity remains")
	}
	if got := r.entries.Load(); got != 2 {
		t.Fatalf("entries=%d; want 2", got)
	}
}

func TestRateLimiterLogicalClockClampsOutOfOrderSamples(t *testing.T) {
	r := newRateLimiter(2, 60, 64)
	startWall := r.clockStart.UnixNano()
	second := int64(time.Second)

	// Model a goroutine delayed after sampling an earlier monotonic timestamp:
	// a different shard observes the later sample first, then the stale sample
	// reaches logicalUnixSecondsAt.
	later := r.logicalUnixSecondsAt(startWall+11*second, 11*second)
	earlier := r.logicalUnixSecondsAt(startWall+10*second, 10*second)
	if earlier != later {
		t.Fatalf("stale sample moved logical time backward: earlier=%d later=%d", earlier, later)
	}
}

func TestRateLimiterLogicalClockNeverMovesBackwardAndAdvancesDuringRollback(t *testing.T) {
	r := newRateLimiter(2, 60, 64)
	startWall := r.clockStart.UnixNano()
	second := int64(time.Second)
	base := r.logicalUnixSecondsAt(startWall, 0)

	if got, want := r.logicalUnixSecondsAt(startWall+10*second, 10*second), base+10; got != want {
		t.Fatalf("normal clock progression = %d, want %d", got, want)
	}
	if got, want := r.logicalUnixSecondsAt(startWall+100*second, 10*second), base+100; got != want {
		t.Fatalf("forward clock step = %d, want %d", got, want)
	}
	// The wall clock is corrected backwards, but the logical clock keeps
	// advancing with monotonic elapsed time rather than freezing at the peak.
	if got, want := r.logicalUnixSecondsAt(startWall+15*second, 15*second), base+105; got != want {
		t.Fatalf("backwards clock projection = %d, want %d", got, want)
	}
	if got, want := r.logicalUnixSecondsAt(startWall+16*second, 16*second), base+106; got != want {
		t.Fatalf("logical clock stopped advancing after rollback: got %d, want %d", got, want)
	}
}

func TestRateLimiterConcurrentRequestsRespectPerClientQuota(t *testing.T) {
	const (
		limit    = 7
		requests = 128
	)
	r := newRateLimiter(limit, 60, 64)
	ip := netip.MustParseAddr("192.0.2.41")
	start := make(chan struct{})
	results := make(chan rateLimitResult, requests)
	var wg sync.WaitGroup

	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- r.allow(ip)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var allowed, exceeded int
	for result := range results {
		switch result {
		case rateAllowed:
			allowed++
		case rateExceeded:
			exceeded++
		default:
			t.Fatalf("unexpected rate-limit result: %v", result)
		}
	}
	if allowed != limit || exceeded != requests-limit {
		t.Fatalf("concurrent requests: allowed=%d exceeded=%d; want %d and %d", allowed, exceeded, limit, requests-limit)
	}
	if got := r.entries.Load(); got != 1 {
		t.Fatalf("tracked entries = %d, want exactly one client entry", got)
	}
}

func TestRateLimiterCleanupDoesNotReopenQuotaAfterClockStepBackward(t *testing.T) {
	r := newRateLimiter(1, 60, 64)
	ip := netip.MustParseAddr("192.0.2.40")
	sh := &r.shards[int(addrHash(ip)%shardCount)]
	now := time.Now()
	elapsed := now.Sub(r.clockStart).Nanoseconds()
	currentLogical := r.logicalUnixSecondsAt(now.UnixNano(), elapsed)
	oldWindow := currentLogical / r.windowSec
	sh.m = map[netip.Addr]rateEntry{ip: {window: oldWindow, count: 1}}
	r.entries.Store(1)

	// Simulate a forward wall-clock step that crosses two windows. Cleanup
	// must use that logical time; a backwards correction immediately after the
	// sweep must not reopen the exhausted client's quota.
	futureWindow := oldWindow + 2
	futureWall := int64(futureWindow*r.windowSec) * int64(time.Second)
	if got := r.logicalUnixSecondsAt(futureWall, elapsed); got/r.windowSec != futureWindow {
		t.Fatalf("logical window after forward step = %d, want %d", got/r.windowSec, futureWindow)
	}
	r.cleanup()
	if got := r.entries.Load(); got != 0 {
		t.Fatalf("entries after cleanup = %d, want expired entry reclaimed", got)
	}
	if got := r.logicalUnixSecondsAt(now.UnixNano(), elapsed); got/r.windowSec != futureWindow {
		t.Fatalf("logical window after backwards correction = %d, want %d", got/r.windowSec, futureWindow)
	}

	if got := r.allow(ip); got != rateAllowed {
		t.Fatalf("first request in the new logical window = %v, want rateAllowed", got)
	}
	if got := r.allow(ip); got != rateExceeded {
		t.Fatalf("second request after the backwards step = %v, want rateExceeded", got)
	}
}

func TestRateLimiterCleanupKeepsFutureWindowEntries(t *testing.T) {
	r := newRateLimiter(5, 60, 64)
	ip := netip.MustParseAddr("192.0.2.31")
	if r.allow(ip) != rateAllowed {
		t.Fatal("first request should be allowed")
	}
	sh := &r.shards[int(addrHash(ip)%shardCount)]
	entry := sh.m[ip]
	entry.window++ // pretend the clock jumped backwards after the entry was stored
	sh.m[ip] = entry
	r.cleanup()
	if got := len(sh.m); got != 1 {
		t.Fatalf("future-window entries removed by cleanup = %d, want 1", got)
	}
	if got := r.entries.Load(); got != 1 {
		t.Fatalf("entries after cleanup = %d, want 1", got)
	}
}

func TestRateLimiterCleanupReleasesGlobalCapacity(t *testing.T) {
	r := newRateLimiter(1, 60, 64)
	ip := netip.MustParseAddr("192.0.2.30")
	idx := int(addrHash(ip) % shardCount)
	r.shards[idx].m = map[netip.Addr]rateEntry{ip: {window: 0, count: 1}}
	r.entries.Store(1)
	r.cleanup()
	if got := r.entries.Load(); got != 0 {
		t.Fatalf("entries after cleanup=%d; want 0", got)
	}
	if r.allow(ip) != rateAllowed {
		t.Fatal("client should be admitted after stale capacity is reclaimed")
	}
}

func TestRateLimiterEnforcesPerClientLimit(t *testing.T) {
	r := newRateLimiter(2, 60, 64)
	ip := netip.MustParseAddr("192.0.2.10")
	if r.allow(ip) != rateAllowed || r.allow(ip) != rateAllowed {
		t.Fatal("first two requests should be allowed")
	}
	if r.allow(ip) == rateAllowed {
		t.Fatal("third request should be rejected")
	}
}

func TestRateLimiterGroupsIPv6By64(t *testing.T) {
	r := newRateLimiter(1, 60, 6400)
	a := netip.MustParseAddr("2001:db8:1:2::1")
	sameNet := netip.MustParseAddr("2001:db8:1:2:ffff::9")
	otherNet := netip.MustParseAddr("2001:db8:1:3::1")
	if r.allow(a) != rateAllowed {
		t.Fatal("first request should be allowed")
	}
	if r.allow(sameNet) == rateAllowed {
		t.Fatal("another address in the same /64 must share the quota")
	}
	if r.allow(otherNet) != rateAllowed {
		t.Fatal("an address in a different /64 must have its own quota")
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
	if rec.Body.String() != string(response) {
		t.Fatalf("response body mismatch")
	}
}

func TestDoHRejectsDuplicateGETDNSParameters(t *testing.T) {
	query := testQuery(30)
	encoded := base64.RawURLEncoding.EncodeToString(query)
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?dns="+encoded+"&dns="+encoded, nil)
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestDoHRejectsOversizedRawQueryBeforeParsing(t *testing.T) {
	// A long raw query without parameter separators is rejected with 414
	// before parsing. Without the fast-fail it would parse as one giant
	// valueless parameter and then fail as a 400 because it has no dns value.
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	long := strings.Repeat("a", defaultMaxGetQuerySize+len("dns=")+1)
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?"+long, nil)
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusRequestURITooLong {
		t.Fatalf("status = %d, want 414", rec.Code)
	}
}

func TestDoHOversizedSemicolonQueryUsesFastFail(t *testing.T) {
	// A semicolon is not a tolerated separator: url.ParseQuery rejects query
	// settings containing one, so an oversized separator-free query must hit
	// the 414 fast-fail instead of being parsed into a 400 first.
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	long := strings.Repeat("a", defaultMaxGetQuerySize+len("dns=")+1) + ";"
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?"+long, nil)
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusRequestURITooLong {
		t.Fatalf("status = %d, want 414", rec.Code)
	}
}

func TestReadDNSQueryAcceptsValidDNSWithExtraParametersPastFastFailThreshold(t *testing.T) {
	query := testQuery(36)
	encoded := base64.RawURLEncoding.EncodeToString(query)
	rawQuery := "dns=" + encoded + "&extra=" + strings.Repeat("x", defaultMaxGetQuerySize+1)
	if len(rawQuery) <= defaultMaxGetQuerySize+len("dns=") {
		t.Fatal("test query must exceed the oversized-query fast-fail threshold")
	}
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?"+rawQuery, nil)
	got, _, status, bodyConsumed := readDNSQuery(req, defaultMaxBodyBytes, base64.RawURLEncoding.EncodedLen(defaultMaxBodyBytes))
	if status != 0 {
		t.Fatalf("status = %d, want success for a valid dns parameter with an extra parameter", status)
	}
	if bodyConsumed {
		t.Fatal("GET parsing must not report a consumed POST body")
	}
	if !bytes.Equal(got, query) {
		t.Fatal("decoded DNS query does not match the original message")
	}
}

func TestDoHRejectsMalformedGETQueryString(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?dns=%zz", nil)
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestReadDNSQueryRejectsBase64URLLineBreaks(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(testQuery(35))
	mid := len(encoded) / 2
	req := httptest.NewRequest(http.MethodGet, defaultDoHPath+"?dns="+encoded[:mid]+"%0A"+encoded[mid:], nil)
	if _, _, status, _ := readDNSQuery(req, defaultMaxBodyBytes, base64.RawURLEncoding.EncodedLen(defaultMaxBodyBytes)); status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a line break inside the base64url value", status)
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

func TestDoHReleasesConcurrencySlotOnBadRequest(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader("not-dns"))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := len(s.sem); got != 0 {
		t.Fatalf("semaphore occupancy = %d, want 0 after request", got)
	}
}

func TestDoHConcurrencyGateRejectsBeforeReadingBody(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	for i := 0; i < cap(s.sem); i++ {
		s.sem <- struct{}{}
	}
	body := &trackingBody{}
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, nil)
	req.Body = body
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d; want 503", rec.Code)
	}
	if body.read {
		t.Fatal("request body was read while concurrency gate was full")
	}
}

func TestDoHPreAdmissionRejectionsKeepPOSTReadDeadline(t *testing.T) {
	tests := []struct {
		name   string
		status int
		setup  func(*server, *http.Request)
	}{
		{
			name:   "concurrency limit",
			status: http.StatusServiceUnavailable,
			setup: func(s *server, _ *http.Request) {
				for i := 0; i < cap(s.sem); i++ {
					s.sem <- struct{}{}
				}
			},
		},
		{
			name:   "rate limit",
			status: http.StatusTooManyRequests,
			setup: func(s *server, req *http.Request) {
				s.rate = newRateLimiter(1, 60, 64)
				ip := netip.MustParseAddr("192.0.2.90")
				if got := s.rate.allow(ip); got != rateAllowed {
					t.Fatalf("priming rate-limit decision = %v, want rateAllowed", got)
				}
				req.RemoteAddr = ip.String() + ":1234"
			},
		},
		{
			name:   "client table capacity",
			status: http.StatusServiceUnavailable,
			setup: func(s *server, req *http.Request) {
				s.rate = newRateLimiter(99, 60, 64)
				for i := 1; i <= 64; i++ {
					ip := netip.AddrFrom4([4]byte{198, 18, byte(i / 256), byte(i)})
					if got := s.rate.allow(ip); got != rateAllowed {
						t.Fatalf("priming client %d decision = %v, want rateAllowed", i, got)
					}
				}
				req.RemoteAddr = "203.0.113.201:1234"
			},
		},
		{
			name:   "invalid client address",
			status: http.StatusServiceUnavailable,
			setup: func(_ *server, req *http.Request) {
				req.RemoteAddr = "not-an-ip-address"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestGateway("http://127.0.0.1:9/dns-query")
			body := &trackingBody{}
			req := httptest.NewRequest(http.MethodPost, defaultDoHPath, nil)
			req.Body = body
			req.ContentLength = -1
			req.Header.Set("Content-Type", "application/dns-message")
			tc.setup(s, req)

			rec := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			s.doh(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
			if body.read {
				t.Fatal("POST body was read before admission rejection")
			}
			if len(rec.deadlines) != 1 || rec.deadlines[0].IsZero() {
				t.Fatalf("read deadlines = %v, want one active short deadline", rec.deadlines)
			}
		})
	}
}

func TestDoHPreAdmissionRejectionWithoutPOSTBodyDoesNotSetReadDeadline(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	s.rate = newRateLimiter(1, 60, 64)
	ip := netip.MustParseAddr("192.0.2.91")
	if got := s.rate.allow(ip); got != rateAllowed {
		t.Fatalf("priming rate-limit decision = %v, want rateAllowed", got)
	}

	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, nil)
	req.RemoteAddr = ip.String() + ":1234"
	req.Header.Set("Content-Type", "application/dns-message")
	rec := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	s.doh(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if len(rec.deadlines) != 0 {
		t.Fatalf("read deadlines = %v, want none for a bodyless POST", rec.deadlines)
	}
}

func TestHandlersBoundBodiesTheyLeaveUnread(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		status int
	}{
		{name: "unsupported DoH method", method: http.MethodPut, path: defaultDoHPath, status: http.StatusMethodNotAllowed},
		{name: "ignored DoH GET body", method: http.MethodGet, path: defaultDoHPath, status: http.StatusBadRequest},
		{name: "unsupported health method", method: http.MethodPost, path: "/health", status: http.StatusMethodNotAllowed},
		{name: "unsupported root method", method: http.MethodPost, path: "/", status: http.StatusMethodNotAllowed},
		{name: "ignored root body", method: http.MethodGet, path: "/", status: http.StatusOK},
		{name: "unknown path", method: http.MethodPost, path: "/unknown", status: http.StatusNotFound},
		{name: "non-canonical path", method: http.MethodPost, path: "/%68ealth", status: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestGateway("http://127.0.0.1:9/dns-query")
			body := &trackingBody{}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Body = body
			req.ContentLength = -1
			rec := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			s.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
			if body.read {
				t.Fatal("handler read a body that should have been left for bounded cleanup")
			}
			if len(rec.deadlines) != 1 || rec.deadlines[0].IsZero() {
				t.Fatalf("read deadlines = %v, want one active short deadline", rec.deadlines)
			}
		})
	}
}

func TestDoHRejectsOversizedPOST(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	s.maxBody = 16
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader("0123456789abcdefghijklmnop"))
	req.Header.Set("Content-Type", "application/dns-message")
	// Unknown length (chunked) forces the streaming limit in readLimited rather
	// than the Content-Length pre-check that TestDoHRejectsAdvertisedOversizedPOST
	// covers.
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestDoHKeepsPOSTReadDeadlineWhenBodyIsNotConsumed(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*server) *http.Request
		want  int
	}{
		{
			name: "unsupported content type",
			setup: func(_ *server) *http.Request {
				req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader("unread body"))
				req.Header.Set("Content-Type", "text/plain")
				return req
			},
			want: http.StatusUnsupportedMediaType,
		},
		{
			name: "advertised oversized body",
			setup: func(s *server) *http.Request {
				s.maxBody = 512
				req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader("unread body"))
				req.Header.Set("Content-Type", "application/dns-message")
				req.ContentLength = 513
				return req
			},
			want: http.StatusRequestEntityTooLarge,
		},
		{
			name: "streaming oversized body",
			setup: func(s *server) *http.Request {
				s.maxBody = 512
				req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(strings.Repeat("x", 600)))
				req.Header.Set("Content-Type", "application/dns-message")
				req.ContentLength = -1
				return req
			},
			want: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestGateway("http://127.0.0.1:9/dns-query")
			req := tc.setup(s)
			rec := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			s.doh(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if len(rec.deadlines) != 1 || rec.deadlines[0].IsZero() {
				t.Fatalf("read deadlines = %v, want only the active short deadline", rec.deadlines)
			}
		})
	}
}

func TestDoHClearsPOSTReadDeadlineAfterBodyEOF(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader("not a DNS message"))
	req.Header.Set("Content-Type", "application/dns-message")
	rec := &readDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}

	s.doh(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(rec.deadlines) != 2 || rec.deadlines[0].IsZero() || !rec.deadlines[1].IsZero() {
		t.Fatalf("read deadlines = %v, want set then clear after body EOF", rec.deadlines)
	}
}

func TestUpstreamTransportCapsResponseHeaders(t *testing.T) {
	const concurrency = 3
	transport := newUpstreamTransport(concurrency)
	defer transport.CloseIdleConnections()

	if transport.MaxResponseHeaderBytes != int64(defaultMaxHeaderBytes) {
		t.Fatalf("MaxResponseHeaderBytes = %d, want %d", transport.MaxResponseHeaderBytes, defaultMaxHeaderBytes)
	}
	if transport.MaxIdleConns != concurrency || transport.MaxIdleConnsPerHost != concurrency || transport.MaxConnsPerHost != concurrency {
		t.Fatalf("connection limits = (%d, %d, %d), want %d", transport.MaxIdleConns, transport.MaxIdleConnsPerHost, transport.MaxConnsPerHost, concurrency)
	}
	if transport.Proxy != nil {
		t.Fatal("upstream transport must not use environment-configured proxies")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("x", defaultMaxHeaderBytes))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := &http.Client{Transport: transport}
	resp, err := client.Get(upstream.URL)
	if err == nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		t.Fatal("request unexpectedly accepted an oversized upstream response header")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "header") {
		t.Fatalf("error = %v, want a response-header size error", err)
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
	s := newTestGateway("http://127.0.0.1:8053/dns-query")
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
	// Content-Length already proves this body exceeds the limit. Do not spend
	// another full body-read budget on a connection that must be discarded.
	if body.read {
		t.Fatal("known-oversized upstream response body should not be read")
	}
}

func TestDrainBoundedBodyStopsAtLimitPlusOne(t *testing.T) {
	body := &countingReader{remaining: 100}
	drainBoundedBody(body, 4)
	if body.read != 5 {
		t.Fatalf("drained %d bytes, want the 5-byte detection bound", body.read)
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

func TestDoHAcceptsCaseInsensitiveResponseQuestion(t *testing.T) {
	query := testQuery(31)
	response := testResponse(query)
	qEnd, ok := parseDNSMessage(response, true)
	if !ok {
		t.Fatal("test response should be valid")
	}
	for i := 13; i < qEnd-4; i++ {
		if response[i] >= 'a' && response[i] <= 'z' {
			response[i] -= 'a' - 'A'
		}
	}
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
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestDoHRejectsMismatchedResponseOpcode(t *testing.T) {
	query := testQuery(32)
	query[2] |= 0x10 // Opcode 2 (IQUERY) in the query.
	// testResponse always writes flags 0x81, which is opcode 0 (QUERY), so the
	// response opcode differs from the query's opcode 2 and the gateway's
	// opcode-mismatch branch is exercised.
	response := testResponse(query)
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

func TestDoHReturnsServiceUnavailableWhenClientTableIsFull(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	s.rate = newRateLimiter(99, 60, 64)
	for i := 1; i <= 64; i++ {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i / 256), byte(i)})
		if got := s.rate.allow(ip); got != rateAllowed {
			t.Fatalf("client %d decision = %v, want rateAllowed", i, got)
		}
	}

	query := testQuery(26)
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(query)))
	req.RemoteAddr = "203.0.113.201:1234"
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestDoHReturnsServiceUnavailableWhenClientAddressIsInvalid(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	req := httptest.NewRequest(http.MethodPost, defaultDoHPath, strings.NewReader(string(testQuery(29))))
	req.RemoteAddr = "not-an-ip-address"
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.doh(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want 1", got)
	}
}

func TestSecondsUntilWindowReset(t *testing.T) {
	for _, tc := range []struct {
		unixSeconds uint64
		windowSec   uint64
		want        uint64
	}{
		{unixSeconds: 0, windowSec: 37, want: 37},
		{unixSeconds: 1, windowSec: 37, want: 36},
		{unixSeconds: 36, windowSec: 37, want: 1},
		{unixSeconds: 37, windowSec: 37, want: 37},
		{unixSeconds: 74, windowSec: 37, want: 37},
	} {
		if got := secondsUntilWindowReset(tc.unixSeconds, tc.windowSec); got != tc.want {
			t.Errorf("secondsUntilWindowReset(%d, %d) = %d, want %d", tc.unixSeconds, tc.windowSec, got, tc.want)
		}
	}
}

func TestDoHRateLimitRetryAfterUntilWindowReset(t *testing.T) {
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
	retryAfter, err := strconv.ParseUint(rec2.Header().Get("Retry-After"), 10, 64)
	if err != nil || retryAfter == 0 || retryAfter > s.rate.windowSec {
		t.Fatalf("Retry-After = %q; want 1..%d seconds", rec2.Header().Get("Retry-After"), s.rate.windowSec)
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

func TestDoHRejectsNonOKUpstreamStatus(t *testing.T) {
	// This gateway's fixed local-upstream contract requires HTTP 200. A 204
	// has no response body and must be rejected like any other non-200 status.
	query := testQuery(41)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusNoContent)
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
		// t.Fatal must not be called from a non-test goroutine.
		t.Error("redirect target should never receive the DNS request")
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
	// Upstream accepting a real TLS handshake: health is OK.
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upstream.StartTLS()

	s := newTestGateway(upstream.URL + "/dns-query")
	rec := httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// A successful result is cached briefly, so a second health check does not
	// need another handshake even if the upstream disappears immediately.
	upstream.Close()
	rec = httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("cached status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Once the cache expires, the next check probes again and reports failure.
	s.probeAt = time.Now().Add(-upstreamProbeCacheTTL)
	rec = httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired-cache status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}

	// Upstream refusing connections: health reports 503 starting state.
	s = newTestGateway("http://127.0.0.1:1/dns-query")
	rec = httptest.NewRecorder()
	s.health(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestHealthAndRootAllowOnlyGetAndHead(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	handlers := map[string]http.HandlerFunc{"health": s.health, "root": s.root}
	for name, h := range handlers {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status = %d, want 405", name, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
			t.Fatalf("%s: Allow = %q, want %q", name, got, "GET, HEAD")
		}
	}

	rec := httptest.NewRecorder()
	s.root(rec, httptest.NewRequest(http.MethodHead, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD /: status = %d, want 200", rec.Code)
	}
}

func TestParseClientIPStripsIPv6Zone(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "[fe80::1%eth0]:8080"
	got := parseClientIP(r, false)
	want := netip.MustParseAddr("fe80::1")
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestCleanupIntervalIsCapped(t *testing.T) {
	if got, want := cleanupInterval(5), 5*time.Second; got != want {
		t.Fatalf("cleanupInterval(5) = %s, want %s", got, want)
	}
	if got, want := cleanupInterval(maxRateWindowSec), time.Duration(maxCleanupIntervalSec)*time.Second; got != want {
		t.Fatalf("cleanupInterval(%d) = %s, want %s", maxRateWindowSec, got, want)
	}
}

func TestRateLimiterCleanupRemovesExpiredEntries(t *testing.T) {
	r := newRateLimiter(5, 60, 64)
	ip := netip.MustParseAddr("192.0.2.30")
	if r.allow(ip) != rateAllowed {
		t.Fatal("first request should be allowed")
	}
	sh := &r.shards[int(addrHash(ip)%shardCount)]
	entry := sh.m[ip]
	entry.window-- // pretend the entry belongs to the previous window
	sh.m[ip] = entry
	r.cleanup()
	if got := len(sh.m); got != 0 {
		t.Fatalf("expired entries left after cleanup = %d, want 0", got)
	}
}

func TestParseDNSMessageReportsQuestionEnd(t *testing.T) {
	query := testQuery(40)
	qEnd, ok := parseDNSMessage(query, false)
	if !ok || qEnd != len(query) {
		t.Fatalf("parseDNSMessage = (%d, %t), want (%d, true)", qEnd, ok, len(query))
	}

	withTrailing := append(append([]byte(nil), query...), 0xff)
	if qEnd, ok := parseDNSMessage(withTrailing, false); ok || qEnd != 0 {
		t.Fatalf("message with trailing bytes = (%d, %t), want (0, false)", qEnd, ok)
	}
}

func TestParseClientIPUsesFirstForwardedAddressOnlyWhenTrusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "127.0.0.1:8080"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got, want := parseClientIP(r, true), netip.MustParseAddr("198.51.100.7"); got != want {
		t.Fatalf("trusted: got %s, want %s", got, want)
	}
	if got, want := parseClientIP(r, false), netip.MustParseAddr("127.0.0.1"); got != want {
		t.Fatalf("untrusted: got %s, want %s", got, want)
	}
}

func TestRouteDispatchesPathsAndReturnsJSON404(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("404 Content-Type = %q, want JSON", got)
	}

	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("root status = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, defaultDoHPath, nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("DoH path dispatch: status=%d Allow=%q, want 405 and %q", rec.Code, rec.Header().Get("Allow"), "GET, POST")
	}
}

func TestServeHTTPDoesNotRedirectNonCanonicalPaths(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	for _, requestPath := range []string{
		"/unknown//path",
		"/unknown/../dns-query",
		"/dns-query//",
		"/%68ealth",    // encoded spelling of a reserved endpoint
		"/dns%2Dquery", // encoded spelling of the configured DoH endpoint
	} {
		t.Run(requestPath, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, requestPath, strings.NewReader("ignored")))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != "" {
				t.Fatalf("unexpected redirect Location %q", got)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Fatalf("Content-Type = %q, want JSON", got)
			}
		})
	}
}

func TestServeHTTPAllowsCanonicalEscapingForConfiguredPath(t *testing.T) {
	s := newTestGateway("http://127.0.0.1:9/dns-query")
	s.dohPath = "/doh path"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/doh%20path", nil))
	// The configured path contains a space, so its canonical URL spelling is
	// percent-escaped. It should reach DoH validation, not become a 404.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("canonical escaped path status = %d, want 400 from missing dns parameter; body=%s", rec.Code, rec.Body.String())
	}
}

func TestProbeUpstreamBoundedByDeadline(t *testing.T) {
	// An endpoint that accepts TCP but never speaks TLS must fail the probe
	// within the probe timeout rather than waiting for the peer to close.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			// Keep the peer silent during the TLS handshake, then exit as soon
			// as the probe's deadline closes the client connection. A fixed
			// sleep would leave this goroutine and socket alive after the test.
			_, _ = io.Copy(io.Discard, c)
			_ = c.Close()
		}
	}()

	s := &server{upstreamHost: ln.Addr().String()}
	start := time.Now()
	if s.probeUpstream() {
		t.Fatal("probe should fail against a non-speaking TCP endpoint")
	}
	if elapsed := time.Since(start); elapsed > upstreamProbeTimeout+500*time.Millisecond {
		t.Fatalf("probe took %s, want it bounded by the %s probe timeout", elapsed, upstreamProbeTimeout)
	}
}

func TestValidDNSMessageNameLengthBoundary(t *testing.T) {
	// Three 63-byte labels (192 bytes) plus a final label plus the root label.
	build := func(lastLabel int) []byte {
		var qname []byte
		for i := 0; i < 3; i++ {
			qname = append(qname, 63)
			qname = append(qname, bytes.Repeat([]byte{'a'}, 63)...)
		}
		qname = append(qname, byte(lastLabel))
		qname = append(qname, bytes.Repeat([]byte{'a'}, lastLabel)...)
		return append(qname, 0)
	}
	if !validDNSMessage(queryWithQName(50, build(61)), false) {
		t.Fatal("expected a 255-byte wire-format name to be accepted")
	}
	if validDNSMessage(queryWithQName(51, build(62)), false) {
		t.Fatal("expected a 256-byte wire-format name to be rejected")
	}
}

func TestRateLimiterKeepsMappedIPv4ClientsSeparate(t *testing.T) {
	// IPv4-mapped IPv6 addresses must not collapse into a single /64 key.
	r := newRateLimiter(1, 60, 64)
	a := netip.MustParseAddr("::ffff:192.0.2.1")
	b := netip.MustParseAddr("::ffff:192.0.2.2")
	if r.allow(a) != rateAllowed || r.allow(b) != rateAllowed {
		t.Fatal("distinct mapped IPv4 clients must have independent quotas")
	}
	if r.allow(netip.MustParseAddr("192.0.2.1")) == rateAllowed {
		t.Fatal("mapped and plain spellings of one IPv4 client must share a quota")
	}
}

// readDNSQuery does not re-check the decoded size of GET queries because the
// encoded ceiling EncodedLen(maxBody) already implies it. This pins that
// implication across the configurable MAX_DNS_MESSAGE_BYTES range.
func TestEncodedCeilingImpliesDecodedLimit(t *testing.T) {
	for _, maxBody := range []int{512, 8192, 9216, 9217, 65535} {
		encoded := base64.RawURLEncoding.EncodedLen(maxBody)
		if decoded := base64.RawURLEncoding.DecodedLen(encoded); decoded > maxBody {
			t.Errorf("maxBody=%d: encoded ceiling %d decodes to %d bytes", maxBody, encoded, decoded)
		}
	}
}

func TestReadLimited(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       string
		limit    int64
		hint     int64
		want     string
		tooLarge bool
	}{
		{"within limit, no hint", "abcd", 4, -1, "abcd", false},
		{"within limit, exact hint", "abcd", 4, 4, "abcd", false},
		{"over limit", "abcde", 4, -1, "", true},
		{"hint larger than limit is ignored", "ab", 4, 1 << 40, "ab", false},
		{"lying small hint", "abcd", 4, 1, "abcd", false},
	} {
		got, tooLarge, err := readLimited(strings.NewReader(tc.in), tc.limit, tc.hint)
		if err != nil || tooLarge != tc.tooLarge || string(got) != tc.want {
			t.Errorf("%s: got (%q, %t, %v), want (%q, %t, nil)", tc.name, got, tooLarge, err, tc.want, tc.tooLarge)
		}
	}
}

func FuzzParseDNSMessage(f *testing.F) {
	f.Add(testQuery(1), false)
	f.Add(testResponse(testQuery(2)), true)
	f.Add(testResponseWithPrefixedCompressedOwner(testQuery(3)), true)
	f.Add([]byte{0xc0, 0x0c, 0x00, 0x01}, true)
	f.Add([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0xc0, 0x0c}, true)
	f.Fuzz(func(t *testing.T, msg []byte, wantResponse bool) {
		qEnd, ok := parseDNSMessage(msg, wantResponse)
		if !ok && qEnd != 0 {
			t.Fatalf("invalid DNS message returned non-zero question end %d", qEnd)
		}
		if ok && (qEnd < 12 || qEnd > len(msg)) {
			t.Fatalf("valid DNS message returned question end %d outside [12, %d]", qEnd, len(msg))
		}
	})
}
