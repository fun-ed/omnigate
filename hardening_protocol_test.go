package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const hardeningProtocolTimeout = 5 * time.Second
const hardeningClientIP = "198.51.100.42"
const hardeningSpoofedRequestID = "spoofed-client-request-id"

func TestHardeningProtocolWebSocketUpgradeHeadersAndFrames(t *testing.T) {
	logs := captureRequestLogs(t)
	backendRequests := make(chan hardeningProtocolRequest, 1)
	backendDone := make(chan struct{})
	backendErrors := make(chan error, 1)
	reportBackendError := func(err error) {
		select {
		case backendErrors <- err:
		default:
		}
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/socket" {
			http.NotFound(w, r)
			return
		}
		backendRequests <- captureHardeningProtocolRequest(r)
		serveHardeningWebSocket(w, r, backendDone, reportBackendError)
	}))
	t.Cleanup(upstream.Close)

	front, appDone := startHardeningProtocolApp(t, upstream)
	frontURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", frontURL.Host, hardeningProtocolTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(hardeningProtocolTimeout)); err != nil {
		t.Fatal(err)
	}

	authorization := base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password"))
	_, err = fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Basic %s\r\nX-Forwarded-Proto: https\r\nCF-Connecting-IP: %s\r\nX-Real-IP: 203.0.113.77\r\nX-Forwarded-For: 203.0.113.88\r\nX-Request-ID: %s\r\n\r\n", frontURL.Host, authorization, hardeningClientIP, hardeningSpoofedRequestID)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		t.Fatalf("WebSocket response status = %d, want 101", response.StatusCode)
	}
	if got, want := response.Header.Get("Sec-WebSocket-Accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; got != want {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, want)
	}
	assertHardeningResponsePolicy(t, response.Header)

	observation := receiveHardeningProtocolRequest(t, backendRequests)
	requestID := assertHardeningUpstreamRequest(t, observation)
	assertHardeningSingleHeader(t, response.Header, requestIDHeader, requestID)

	for _, message := range []string{"first masked frame", "second masked frame"} {
		if err := writeHardeningMaskedTextFrame(conn, message); err != nil {
			t.Fatalf("write WebSocket frame: %v", err)
		}
		if got := readHardeningTextFrame(t, reader); got != message {
			t.Fatalf("echoed WebSocket message = %q, want %q", got, message)
		}
	}

	if err := conn.Close(); err != nil {
		t.Errorf("close WebSocket connection: %v", err)
	}
	waitHardeningProtocolDone(t, "upstream WebSocket handler", backendDone)
	waitHardeningProtocolDone(t, "front-end request handler", appDone)
	select {
	case err := <-backendErrors:
		t.Fatalf("upstream WebSocket protocol: %v", err)
	default:
	}

	assertHardeningRequestLog(t, logs.String(), http.StatusSwitchingProtocols, requestID)
}

func TestHardeningProtocolEarlyHintsFinalResponseAndTrailer(t *testing.T) {
	logs := captureRequestLogs(t)
	backendRequests := make(chan hardeningProtocolRequest, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path != "/early-hints" {
			http.NotFound(w, r)
			return
		}
		backendRequests <- captureHardeningProtocolRequest(r)

		w.Header().Set("Link", "</early-style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		w.Header().Set("Strict-Transport-Security", "max-age=0")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("CDN-Cache-Control", "public, max-age=300")
		w.Header().Set("Cloudflare-CDN-Cache-Control", "public, max-age=300")
		w.Header().Set("Surrogate-Control", "max-age=300")
		w.Header().Set("Expires", "Wed, 21 Oct 2037 07:28:00 GMT")
		w.Header().Set("Age", "7")
		w.Header().Set("Trailer", "X-Protocol-Trailer")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "early-hints response body"); err != nil {
			return
		}
		w.Header().Set("X-Protocol-Trailer", "trailer-after-eof")
	}))
	t.Cleanup(upstream.Close)

	front, appDone := startHardeningProtocolApp(t, upstream)
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   hardeningProtocolTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), hardeningProtocolTimeout)
	defer cancel()

	var interimMu sync.Mutex
	var interim []hardeningInterimResponse
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
		interimMu.Lock()
		interim = append(interim, hardeningInterimResponse{code: code, header: http.Header(header).Clone()})
		interimMu.Unlock()
		return nil
	}}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, front.URL+"/early-hints", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("fixture-user", "fixture-password")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("CF-Connecting-IP", hardeningClientIP)
	request.Header.Set("X-Real-IP", "203.0.113.77")
	request.Header.Set("X-Forwarded-For", "203.0.113.88")
	request.Header.Set(requestIDHeader, hardeningSpoofedRequestID)

	response, err := client.Do(request)
	if err != nil {
		waitHardeningProtocolDone(t, "front-end request handler", appDone)
		t.Fatalf("HTTP request: %v", err)
	}
	body, bodyErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	waitHardeningProtocolDone(t, "front-end request handler", appDone)
	if bodyErr != nil {
		t.Fatalf("read final response body: %v", bodyErr)
	}
	if closeErr != nil {
		t.Fatalf("close final response body: %v", closeErr)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("final response status = %d, want 200", response.StatusCode)
	}
	if got, want := string(body), "early-hints response body"; got != want {
		t.Fatalf("final response body = %q, want %q", got, want)
	}
	interimMu.Lock()
	gotInterim := append([]hardeningInterimResponse(nil), interim...)
	interimMu.Unlock()
	if len(gotInterim) != 1 || gotInterim[0].code != http.StatusEarlyHints {
		t.Fatalf("interim responses = %#v, want one 103 Early Hints", gotInterim)
	}
	if got := hardeningHeaderValues(gotInterim[0].header, "Link"); len(got) != 1 || got[0] != "</early-style.css>; rel=preload" {
		t.Fatalf("103 Link values = %#v, want the announced preload link", got)
	}
	assertHardeningHeaderAbsent(t, response.Header, "Link")
	assertHardeningResponsePolicy(t, response.Header)
	if got := hardeningHeaderValues(response.Trailer, "X-Protocol-Trailer"); len(got) != 1 || got[0] != "trailer-after-eof" {
		t.Fatalf("final response trailer values = %#v, want [trailer-after-eof]", got)
	}

	observation := receiveHardeningProtocolRequest(t, backendRequests)
	requestID := assertHardeningUpstreamRequest(t, observation)
	assertHardeningRequestLog(t, logs.String(), http.StatusOK, requestID)
}

type hardeningProtocolRequest struct {
	host             string
	authorization    []string
	clientIPHeader   []string
	realIPHeader     []string
	forwardedFor     string
	forwardedProto   string
	requestIDHeaders []string
}

type hardeningInterimResponse struct {
	code   int
	header http.Header
}

func hardeningProtocolConfig(upstreamURL string) config {
	c := testConfig()
	c.upstreams = upstreamURL
	c.publicURL = "https://omni.curl.rs"
	c.httpsRedirect = true
	c.trustedProxies = "127.0.0.1/32"
	c.clientIPHeader = "CF-Connecting-IP"
	c.privateCache = true
	c.hstsMaxAge = 86400
	c.frameOptions = "SAMEORIGIN"
	c.referrerPolicy = "strict-origin-when-cross-origin"
	c.accessLog = true
	c.authUser = "fixture-user"
	c.authPassword = "fixture-password"
	return c
}

func startHardeningProtocolApp(t *testing.T, upstream *httptest.Server) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	app := testApp(t, hardeningProtocolConfig(upstream.URL))
	done := make(chan struct{})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		app.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	return front, done
}

func captureHardeningProtocolRequest(r *http.Request) hardeningProtocolRequest {
	return hardeningProtocolRequest{
		host:             r.Host,
		authorization:    append([]string(nil), r.Header.Values("Authorization")...),
		clientIPHeader:   append([]string(nil), r.Header.Values("CF-Connecting-IP")...),
		realIPHeader:     append([]string(nil), r.Header.Values("X-Real-IP")...),
		forwardedFor:     r.Header.Get("X-Forwarded-For"),
		forwardedProto:   r.Header.Get("X-Forwarded-Proto"),
		requestIDHeaders: append([]string(nil), r.Header.Values(requestIDHeader)...),
	}
}

func serveHardeningWebSocket(w http.ResponseWriter, r *http.Request, done chan<- struct{}, reportError func(error)) {
	defer close(done)
	if r.Header.Get("Upgrade") != "websocket" {
		reportError(errors.New("backend request did not ask for a WebSocket upgrade"))
		http.Error(w, "upgrade required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Strict-Transport-Security", "max-age=0")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "unsafe-url")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("CDN-Cache-Control", "public, max-age=300")
	w.Header().Set("Cloudflare-CDN-Cache-Control", "public, max-age=300")
	w.Header().Set("Surrogate-Control", "max-age=300")
	w.Header().Set("Expires", "Wed, 21 Oct 2037 07:28:00 GMT")
	w.Header().Set("Age", "7")
	w.Header().Set(requestIDHeader, "upstream-response-id")

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		reportError(errors.New("upstream ResponseWriter does not support hijacking"))
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		reportError(fmt.Errorf("upstream hijack: %w", err))
		return
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * hardeningProtocolTimeout)); err != nil {
		reportError(fmt.Errorf("set upstream WebSocket deadline: %w", err))
		return
	}

	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n", accept); err != nil {
		reportError(fmt.Errorf("write upstream WebSocket response: %w", err))
		return
	}
	for _, name := range []string{
		"Strict-Transport-Security", "X-Frame-Options", "Referrer-Policy", "Cache-Control",
		"CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control", "Expires", "Age", requestIDHeader,
	} {
		for _, value := range w.Header().Values(name) {
			if _, err := fmt.Fprintf(rw, "%s: %s\r\n", name, value); err != nil {
				reportError(fmt.Errorf("write upstream WebSocket header: %w", err))
				return
			}
		}
	}
	if _, err := rw.WriteString("\r\n"); err != nil {
		reportError(fmt.Errorf("finish upstream WebSocket response: %w", err))
		return
	}
	if err := rw.Flush(); err != nil {
		reportError(fmt.Errorf("flush upstream WebSocket response: %w", err))
		return
	}

	for range 2 {
		message, err := readHardeningMaskedTextFrame(rw.Reader)
		if err != nil {
			reportError(fmt.Errorf("read masked client WebSocket frame: %w", err))
			return
		}
		frame := append([]byte{0x81, byte(len(message))}, []byte(message)...)
		if _, err := rw.Write(frame); err != nil {
			reportError(fmt.Errorf("write WebSocket echo: %w", err))
			return
		}
		if err := rw.Flush(); err != nil {
			reportError(fmt.Errorf("flush WebSocket echo: %w", err))
			return
		}
	}
	_, _ = rw.ReadByte()
}

func readHardeningMaskedTextFrame(reader *bufio.Reader) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", err
	}
	length := int(header[1] & 0x7f)
	if header[0] != 0x81 || header[1]&0x80 == 0 || length > 125 {
		return "", errors.New("invalid masked text frame")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(reader, mask); err != nil {
		return "", err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return "", err
	}
	for i := range payload {
		payload[i] ^= mask[i%len(mask)]
	}
	return string(payload), nil
}

func writeHardeningMaskedTextFrame(conn net.Conn, message string) error {
	payload := []byte(message)
	if len(payload) > 125 {
		return fmt.Errorf("WebSocket test message length %d exceeds one-byte frame limit", len(payload))
	}
	mask := [4]byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | byte(len(payload)), mask[0], mask[1], mask[2], mask[3]}
	for i, value := range payload {
		frame = append(frame, value^mask[i%len(mask)])
	}
	for len(frame) > 0 {
		written, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}

func readHardeningTextFrame(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatalf("read echoed WebSocket frame header: %v", err)
	}
	if header[0] != 0x81 || header[1]&0x80 != 0 || header[1]&0x7f > 125 {
		t.Fatalf("invalid echoed WebSocket frame header: %v", header)
	}
	payload := make([]byte, int(header[1]&0x7f))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("read echoed WebSocket frame payload: %v", err)
	}
	return string(payload)
}

func receiveHardeningProtocolRequest(t *testing.T, requests <-chan hardeningProtocolRequest) hardeningProtocolRequest {
	t.Helper()
	timer := time.NewTimer(hardeningProtocolTimeout)
	defer timer.Stop()
	select {
	case request := <-requests:
		return request
	case <-timer.C:
		t.Fatal("timed out waiting for upstream application request")
		return hardeningProtocolRequest{}
	}
}

func assertHardeningUpstreamRequest(t *testing.T, request hardeningProtocolRequest) string {
	t.Helper()
	if request.host != "omni.curl.rs" {
		t.Errorf("upstream Host = %q, want omni.curl.rs", request.host)
	}
	if len(request.authorization) != 0 {
		t.Errorf("edge Authorization reached upstream: %q", request.authorization)
	}
	if len(request.clientIPHeader) != 0 || len(request.realIPHeader) != 0 {
		t.Errorf("raw client IP headers reached upstream: CF=%q X-Real-IP=%q", request.clientIPHeader, request.realIPHeader)
	}
	if request.forwardedFor != hardeningClientIP {
		t.Errorf("upstream X-Forwarded-For = %q, want verified client IP %q", request.forwardedFor, hardeningClientIP)
	}
	if request.forwardedProto != "https" {
		t.Errorf("upstream X-Forwarded-Proto = %q, want https", request.forwardedProto)
	}
	if len(request.requestIDHeaders) != 1 {
		t.Fatalf("upstream X-Request-ID values = %#v, want one generated ID", request.requestIDHeaders)
	}
	requestID := request.requestIDHeaders[0]
	decoded, err := hex.DecodeString(requestID)
	if err != nil || len(decoded) != 16 || requestID == hardeningSpoofedRequestID {
		t.Fatalf("upstream X-Request-ID = %q, want a fresh 128-bit hex ID", requestID)
	}
	return requestID
}

func assertHardeningResponsePolicy(t *testing.T, header http.Header) {
	t.Helper()
	for name, value := range map[string]string{
		"Strict-Transport-Security": "max-age=86400",
		"X-Frame-Options":           "SAMEORIGIN",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Cache-Control":             "private, no-store",
	} {
		assertHardeningSingleHeader(t, header, name, value)
	}
	for _, name := range []string{"CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control", "Expires", "Age"} {
		assertHardeningHeaderAbsent(t, header, name)
	}
}

func hardeningHeaderValues(header http.Header, name string) []string {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func assertHardeningSingleHeader(t *testing.T, header http.Header, name, want string) {
	t.Helper()
	values := hardeningHeaderValues(header, name)
	if len(values) != 1 || values[0] != want {
		t.Errorf("%s values = %#v, want exactly [%q]", name, values, want)
	}
}

func assertHardeningHeaderAbsent(t *testing.T, header http.Header, name string) {
	t.Helper()
	if values := hardeningHeaderValues(header, name); len(values) != 0 {
		t.Errorf("%s should be absent, got %#v", name, values)
	}
}

func assertHardeningRequestLog(t *testing.T, line string, status int, requestID string) {
	t.Helper()
	for _, want := range []string{
		"status=" + fmt.Sprint(status),
		"completed=true",
		"request_id=" + requestID,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("request log omitted %q: %s", want, line)
		}
	}
	for _, forbidden := range []string{"fixture-user", "fixture-password", hardeningSpoofedRequestID} {
		if strings.Contains(line, forbidden) {
			t.Errorf("request log contains forbidden value %q", forbidden)
		}
	}
}

func waitHardeningProtocolDone(t *testing.T, description string, done <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(hardeningProtocolTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", description)
	}
}
