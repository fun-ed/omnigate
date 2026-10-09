package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var requestLogDefaultMu sync.Mutex

func captureRequestLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	requestLogDefaultMu.Lock()
	previous := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
		requestLogDefaultMu.Unlock()
	})
	return &output
}

func TestObserveRequestsDisabledIsTransparent(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/path", nil)
	request.Header.Set(requestIDHeader, "incoming-secret-id")
	next := &requestLogPassthrough{request: request}
	wrapped := observeRequests(false, next)
	if wrapped != next {
		t.Fatal("disabled middleware did not return the exact next handler")
	}

	recorder := httptest.NewRecorder()
	wrapped.ServeHTTP(recorder, request)
	if next.gotRequest != request || next.gotWriter != recorder {
		t.Fatal("disabled middleware did not pass through the original request and writer")
	}
	if requestID(request) != "" || request.Header.Get(requestIDHeader) != "incoming-secret-id" {
		t.Fatal("disabled middleware changed request ID context or header")
	}
	if recorder.Header().Get(requestIDHeader) != "" {
		t.Fatal("disabled middleware added a response request ID")
	}
	if observeRequests(false, nil) != nil {
		t.Fatal("disabled middleware changed a nil handler")
	}
}

type requestLogPassthrough struct {
	request    *http.Request
	gotRequest *http.Request
	gotWriter  http.ResponseWriter
}

func (h *requestLogPassthrough) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.gotRequest = r
	h.gotWriter = w
}

func TestObserveRequestsUsesFreshIDAndDoesNotLogSecrets(t *testing.T) {
	logs := captureRequestLogs(t)
	incomingID := "incoming-id-secret"
	pathSecret := "private-path-secret"
	querySecret := "query-token-secret"
	authorizationSecret := "authorization-secret"
	cookieSecret := "cookie-secret"
	bodySecret := "body-secret"
	userAgentSecret := "user-agent-secret"

	var contextID, headerID string
	handler := observeRequests(true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = requestID(r)
		headerID = r.Header.Get(requestIDHeader)
		w.Header().Set(requestIDHeader, incomingID)
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "http://example.test/"+pathSecret+"?token="+querySecret, strings.NewReader(bodySecret))
	r.Header.Set(requestIDHeader, incomingID)
	r.Header.Set("Authorization", "Bearer "+authorizationSecret)
	r.Header.Set("Cookie", "session="+cookieSecret)
	r.Header.Set("User-Agent", userAgentSecret)
	originalContext := r.Context()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)

	if contextID == "" || contextID == incomingID || contextID != headerID {
		t.Fatalf("handler did not receive the generated request ID in both context and header: context=%q header=%q", contextID, headerID)
	}
	idBytes, err := hex.DecodeString(contextID)
	if err != nil || len(idBytes) != 16 || len(contextID) != 32 {
		t.Fatalf("request ID is not a bounded 128-bit hex value: %q", contextID)
	}
	if got := recorder.Header().Get(requestIDHeader); got != contextID {
		t.Fatalf("response request ID = %q, want %q", got, contextID)
	}
	if requestID(r) != "" || r.Context() != originalContext || r.Header.Get(requestIDHeader) != incomingID {
		t.Fatal("middleware mutated the caller's request")
	}

	line := logs.String()
	for _, forbidden := range []string{incomingID, pathSecret, querySecret, authorizationSecret, cookieSecret, bodySecret, userAgentSecret} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("request log contains sensitive value %q: %s", forbidden, line)
		}
	}
	if !strings.Contains(line, "method=POST") || !strings.Contains(line, "status=200") || !strings.Contains(line, "origin_scheme=http") || !strings.Contains(line, "completed=true") || !strings.Contains(line, "request_id="+contextID) {
		t.Fatalf("request log omitted expected safe fields: %s", line)
	}
}

func TestObserveRequestsGeneratesDistinctIDs(t *testing.T) {
	logs := captureRequestLogs(t)
	var ids []string
	handler := observeRequests(true, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ids = append(ids, requestID(r))
	}))
	for range 2 {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if len(ids) != 2 || ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
		t.Fatalf("generated request IDs are not distinct: %q", ids)
	}
	for _, id := range ids {
		if !strings.Contains(logs.String(), "request_id="+id) {
			t.Fatalf("request log missing generated ID %q: %s", id, logs.String())
		}
	}
}

func TestObserveRequestsLogsStatusCodes(t *testing.T) {
	logs := captureRequestLogs(t)
	cases := []struct {
		name    string
		status  int
		handler http.Handler
	}{
		{
			name:   "implicit 200",
			status: http.StatusOK,
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "ok")
			}),
		},
		{
			name:   "unauthorized",
			status: http.StatusUnauthorized,
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}),
		},
		{
			name:   "redirect",
			status: http.StatusMovedPermanently,
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://example.test/target", http.StatusMovedPermanently)
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := observeRequests(true, tc.handler)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
			if recorder.Code != tc.status {
				t.Fatalf("response status = %d, want %d", recorder.Code, tc.status)
			}
			if !strings.Contains(logs.String(), "status="+strconv.Itoa(tc.status)) {
				t.Fatalf("request log omitted status %d: %s", tc.status, logs.String())
			}
		})
	}
}

func TestObserveRequestsPanicIsIncompleteAndPropagates(t *testing.T) {
	logs := captureRequestLogs(t)
	handler := observeRequests(true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "partial")
		panic("handler panic")
	}))
	recorder := httptest.NewRecorder()
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	if recovered != "handler panic" {
		t.Fatalf("middleware swallowed or changed panic: recovered=%v", recovered)
	}
	line := logs.String()
	if !strings.Contains(line, "status=200") || !strings.Contains(line, "completed=false") {
		t.Fatalf("panic was logged as a normal successful response: %s", line)
	}
}

func TestObserveRequestsCanceledRequestIsIncomplete(t *testing.T) {
	logs := captureRequestLogs(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	handler := observeRequests(true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	handler.ServeHTTP(httptest.NewRecorder(), request)
	line := logs.String()
	if !strings.Contains(line, "status=200") || !strings.Contains(line, "completed=false") {
		t.Fatalf("canceled request was logged as a normal successful response: %s", line)
	}
}

func TestObserveRequestsPreservesFlushAndUnwrap(t *testing.T) {
	t.Run("direct flusher", func(t *testing.T) {
		logs := captureRequestLogs(t)
		recorder := httptest.NewRecorder()
		handler := observeRequests(true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("middleware hid the underlying Flusher interface")
			}
			flusher.Flush()
			_, _ = io.WriteString(w, "after flush")
		}))
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		if !recorder.Flushed || recorder.Code != http.StatusOK {
			t.Fatalf("flush was not forwarded: flushed=%t status=%d", recorder.Flushed, recorder.Code)
		}
		if !strings.Contains(logs.String(), "status=200") {
			t.Fatalf("flush's implicit 200 status was not logged: %s", logs.String())
		}
	})

	t.Run("response controller unwrap", func(t *testing.T) {
		logs := captureRequestLogs(t)
		recorder := httptest.NewRecorder()
		underlying := &unwrapResponseWriter{ResponseWriter: recorder}
		handler := observeRequests(true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, ok := w.(http.Flusher); ok {
				t.Fatal("middleware advertised Flush when the direct writer does not")
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Fatalf("ResponseController could not reach underlying flusher: %v", err)
			}
		}))
		handler.ServeHTTP(underlyingResponseRecorder{ResponseWriter: underlying}, httptest.NewRequest(http.MethodGet, "/", nil))
		if !recorder.Flushed || recorder.Code != http.StatusOK {
			t.Fatalf("ResponseController flush was not forwarded: flushed=%t status=%d", recorder.Flushed, recorder.Code)
		}
		if !strings.Contains(logs.String(), "status=200") {
			t.Fatalf("unwrapped flush's implicit 200 status was not logged: %s", logs.String())
		}
	})
}

type unwrapResponseWriter struct{ http.ResponseWriter }

func (w *unwrapResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type underlyingResponseRecorder struct{ http.ResponseWriter }

func (w underlyingResponseRecorder) Header() http.Header         { return w.ResponseWriter.Header() }
func (w underlyingResponseRecorder) Write(p []byte) (int, error) { return w.ResponseWriter.Write(p) }
func (w underlyingResponseRecorder) WriteHeader(status int)      { w.ResponseWriter.WriteHeader(status) }
func (w underlyingResponseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestObserveRequestsPreservesHijackAndLogs101(t *testing.T) {
	logs := captureRequestLogs(t)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = serverConn.Close(); _ = clientConn.Close() })
	underlying := &hijackResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             serverConn,
		buffered:         bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn)),
	}
	var gotConn net.Conn
	handler := observeRequests(true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("middleware hid the underlying Hijacker interface")
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatalf("Hijack failed: %v", err)
		}
		gotConn = conn
		if err := conn.Close(); err != nil {
			t.Fatalf("closing hijacked connection: %v", err)
		}
	}))
	handler.ServeHTTP(underlying, httptest.NewRequest(http.MethodGet, "/", nil))
	if gotConn != serverConn {
		t.Fatal("middleware replaced the hijacked connection and changed its concrete semantics")
	}
	line := logs.String()
	if !strings.Contains(line, "status=101") || !strings.Contains(line, "completed=true") {
		t.Fatalf("successful hijack was not logged as a completed 101: %s", line)
	}
}

type hijackResponseWriter struct {
	*httptest.ResponseRecorder
	conn     net.Conn
	buffered *bufio.ReadWriter
}

func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.buffered, nil
}
