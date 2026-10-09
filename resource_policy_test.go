package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

type resourcePolicyTestBody struct {
	r         io.Reader
	readBytes int64
	closes    int
}

func (b *resourcePolicyTestBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.readBytes += int64(n)
	return n, err
}

func (b *resourcePolicyTestBody) Close() error {
	b.closes++
	return nil
}

type endlessResourcePolicyReader struct{}

func (endlessResourcePolicyReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestLimitRequestBodyKnownLengthBoundaryAndPreReject(t *testing.T) {
	for _, tc := range []struct {
		name       string
		payload    string
		length     int64
		wantStatus int
		wantCalls  int
		wantRead   int64
	}{
		{name: "exact limit", payload: "1234", length: 4, wantStatus: http.StatusNoContent, wantCalls: 1, wantRead: 4},
		{name: "over limit", payload: "12345", length: 5, wantStatus: http.StatusRequestEntityTooLarge, wantCalls: 0, wantRead: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &resourcePolicyTestBody{r: strings.NewReader(tc.payload)}
			r := httptest.NewRequest(http.MethodPost, "http://example.test/upload", body)
			r.ContentLength = tc.length
			calls := 0
			h := limitRequestBody(4, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read request body: %v", err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if w.Code != tc.wantStatus || calls != tc.wantCalls {
				t.Fatalf("got status %d and %d handler calls; want status %d and %d calls", w.Code, calls, tc.wantStatus, tc.wantCalls)
			}
			if body.readBytes != tc.wantRead {
				t.Fatalf("read %d request bytes, want %d", body.readBytes, tc.wantRead)
			}
			if body.closes == 0 {
				t.Fatal("request body was not closed")
			}
		})
	}
}

func TestLimitRequestBodyZeroDisablesLimit(t *testing.T) {
	body := &resourcePolicyTestBody{r: strings.NewReader("more than any useful limit")}
	r := httptest.NewRequest(http.MethodPost, "http://example.test/upload", body)
	r.ContentLength = 1 << 20
	called := false
	h := limitRequestBody(0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		if string(data) != "more than any useful limit" {
			t.Errorf("got body %q", data)
		}
		_ = r.Body.Close()
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !called || w.Code != http.StatusNoContent {
		t.Fatalf("zero limit did not pass through: called=%v status=%d", called, w.Code)
	}
}

func TestLimitRequestBodyUnknownLengthStreamsAndReturnsMaxBytesError(t *testing.T) {
	const max = 8
	body := &resourcePolicyTestBody{r: endlessResourcePolicyReader{}}
	r := httptest.NewRequest(http.MethodPost, "http://example.test/upload", body)
	r.ContentLength = -1
	var got []byte
	var readErr error
	h := limitRequestBody(max, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	var maxBytesErr *http.MaxBytesError
	if !errors.As(readErr, &maxBytesErr) {
		t.Fatalf("read error %T %v is not a MaxBytesError", readErr, readErr)
	}
	if len(got) != max {
		t.Fatalf("handler received %d bytes, want exactly the %d-byte limit", len(got), max)
	}
	if body.readBytes > max+1 {
		t.Fatalf("limit read %d source bytes; want no more than %d", body.readBytes, max+1)
	}
	if body.closes == 0 {
		t.Fatal("streaming request body was not closed")
	}
	if status := proxyErrorStatus(readErr); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("proxyErrorStatus(MaxBytesError) = %d, want 413", status)
	}
}

func TestProxyErrorStatus(t *testing.T) {
	if got := proxyErrorStatus(fmt.Errorf("wrapped: %w", &http.MaxBytesError{Limit: 8})); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("wrapped MaxBytesError mapped to %d, want 413", got)
	}
	if got := proxyErrorStatus(fmt.Errorf("upstream unavailable")); got != http.StatusBadGateway {
		t.Fatalf("ordinary proxy error mapped to %d, want 502", got)
	}
}

func TestUnknownLengthLimitMapsThroughReverseProxyErrorPath(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Do not consume the body or send an early response. The proxy transport
		// streams the request body independently and must report its read error.
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
			// A server not reading a chunked body may not observe disconnect.
		}
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	mappedStatusCh := make(chan int, 1)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		status := proxyErrorStatus(err)
		mappedStatusCh <- status
		http.Error(w, http.StatusText(status), status)
	}
	front := httptest.NewServer(limitRequestBody(8, proxy))
	defer front.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, front.URL, strings.NewReader(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	res, err := front.Client().Do(req)
	if err != nil {
		t.Fatalf("POST with unknown-length body: %v", err)
	}
	defer res.Body.Close()

	var mappedStatus int
	select {
	case mappedStatus = <-mappedStatusCh:
	default:
		t.Fatal("ReverseProxy error handler was not called")
	}
	if mappedStatus != http.StatusRequestEntityTooLarge || res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("proxy mapped error to %d and returned %d; want 413 for both", mappedStatus, res.StatusCode)
	}
}
