package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Handler-only benchmarks exclude socket I/O, TLS, QUIC and the client. They
// measure allocations per operation, not process RSS or cross-server throughput.
type benchmarkResponse struct{ header http.Header }

func (w *benchmarkResponse) Header() http.Header       { return w.header }
func (*benchmarkResponse) WriteHeader(int)             {}
func (*benchmarkResponse) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkDefaultHTML(b *testing.B) {
	c := defaultConfig()
	c.rps = 0
	h, closeApp, err := newApp(context.Background(), c)
	if err != nil {
		b.Fatal(err)
	}
	defer closeApp()
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := &benchmarkResponse{header: make(http.Header)}
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, r)
	}
}
func BenchmarkBasicAuthHTML(b *testing.B) {
	c := defaultConfig()
	c.rps = 0
	c.authUser = "admin"
	c.authPassword = "benchmark-only"
	h, closeApp, err := newApp(context.Background(), c)
	if err != nil {
		b.Fatal(err)
	}
	defer closeApp()
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.SetBasicAuth(c.authUser, c.authPassword)
	w := &benchmarkResponse{header: make(http.Header)}
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, r)
	}
}
func BenchmarkRateLimiter(b *testing.B) {
	limiter := newIPLimiter(1e9, 1e9)
	h := limiter.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	w := &benchmarkResponse{header: make(http.Header)}
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, r)
	}
}
func BenchmarkRateLimiterParallel(b *testing.B) {
	limiter := newIPLimiter(1e9, 1e9)
	h := limiter.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := &benchmarkResponse{header: make(http.Header)}
		for pb.Next() {
			h.ServeHTTP(w, r)
		}
	})
}
