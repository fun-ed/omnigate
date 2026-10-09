package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig() config {
	return config{httpAddr: "127.0.0.1:0", httpsAddr: "127.0.0.1:0", healthPath: "/healthz", healthInterval: time.Hour, burst: 20, acmeDirectory: googleACME, rps: 10}
}
func testApp(t *testing.T, c config) http.Handler {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h, closeApp, err := newApp(ctx, c)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); closeApp() })
	return h
}
func request(h http.Handler, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
	r.RemoteAddr = "192.0.2.1:1234"
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestDefaultPageAndHealth(t *testing.T) {
	h := testApp(t, testConfig())
	for _, path := range []string{"/", "/healthz", "/readyz"} {
		w := request(h, path, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		if path == "/" && !strings.Contains(w.Body.String(), "<!doctype html>") {
			t.Fatal("missing default HTML")
		}
	}
	if w := request(h, "/missing", ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest(http.MethodHead, "http://example.com/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("HEAD must not return a body")
	}
	r = httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
func TestBasicAuth(t *testing.T) {
	c := testConfig()
	c.authUser = "admin"
	c.authPassword = "test-password"
	h := testApp(t, c)
	for _, auth := range []string{"", "Basic invalid", "Basic YWRtaW46d3Jvbmc="} {
		w := request(h, "/", auth)
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("expected auth challenge, got %d", w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.SetBasicAuth("admin", "test-password")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "/healthz", ""); w.Code != 200 {
		t.Fatal("health should bypass auth")
	}
}
func TestRateLimitAndSpoofing(t *testing.T) {
	c := testConfig()
	c.rps = 0.001
	c.burst = 2
	h := testApp(t, c)
	for i := range 3 {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+10))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 200
		if i == 2 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: %d", i, w.Code)
		}
		if i == 2 && w.Header().Get("Retry-After") == "" {
			t.Fatal("missing retry header")
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.RemoteAddr = "192.0.2.2:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("IP buckets not independent")
	}
	if w := request(h, "/healthz", ""); w.Code != 200 {
		t.Fatal("health must bypass limit")
	}
	l := newIPLimiter(10, 2)
	now := time.Now()
	if !l.allow("a", now) || !l.allow("a", now) || l.allow("a", now) || !l.allow("a", now.Add(time.Second)) {
		t.Fatal("token refill broken")
	}
	l.allow("b", now.Add(11*time.Minute))
	if _, ok := l.entries["a"]; ok {
		t.Fatal("stale IP bucket retained")
	}
	for i := range 10000 {
		l.entries[fmt.Sprint(i)] = &ipEntry{last: now.Add(11 * time.Minute)}
	}
	if l.allow("new", now.Add(11*time.Minute)) {
		t.Fatal("bucket capacity not bounded")
	}
}
func TestStaticFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	c := testConfig()
	c.root = root
	c.rps = 0
	h := testApp(t, c)
	for _, path := range []string{"/hello.txt", "/static/hello.txt"} {
		w := request(h, path, "")
		if w.Code != 200 || w.Body.String() != "hello" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/.env", "/static/.env", "/empty/", "/escape.txt", "/static/../outside.txt", "/%2e%2e/outside.txt"} {
		w := request(h, path, "")
		if w.Code == 200 || strings.Contains(w.Body.String(), "outside") || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("unsafe file exposed: %s (%d)", path, w.Code)
		}
	}
	if w := request(h, "/", ""); !strings.Contains(w.Body.String(), "Web server is running") {
		t.Fatal("no fallback homepage")
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("custom homepage"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "/", ""); w.Code != 200 || w.Body.String() != "custom homepage" {
		t.Fatalf("index: %d %s", w.Code, w.Body.String())
	}
}

func TestRoundRobinHealthAndForwarding(t *testing.T) {
	var healthyA atomic.Bool
	healthyA.Store(true)
	var leaked atomic.Bool
	backend := func(id string, healthy func() bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/base/healthz" {
				if !healthy() {
					w.WriteHeader(503)
				}
				return
			}
			if r.Header.Get("Authorization") != "" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "192.0.2.1" {
				leaked.Store(true)
			}
			fmt.Fprintf(w, "%s %s?%s", id, r.URL.Path, r.URL.RawQuery)
		}))
	}
	a := backend("a", healthyA.Load)
	defer a.Close()
	b := backend("b", func() bool { return true })
	defer b.Close()
	p, err := newPool(a.URL+"/base,"+b.URL+"/base", "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	p.check(context.Background())
	h := basicAuth(p, "admin", "password")
	for _, want := range []string{"a /base/api?q=1", "b /base/api?q=1", "a /base/api?q=1"} {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/api?q=1", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		r.SetBasicAuth("admin", "password")
		r.Header.Set("X-Forwarded-For", "evil")
		r.Header.Set("Forwarded", "for=evil")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.String() != want {
			t.Fatalf("got %d %q, want %q", w.Code, w.Body.String(), want)
		}
	}
	if leaked.Load() {
		t.Fatal("credentials or spoofed forwarding headers leaked")
	}
	healthyA.Store(false)
	p.check(context.Background())
	for range 3 {
		if got := p.pick(); got != p.backends[1] {
			t.Fatal("unhealthy backend selected")
		}
	}
	healthyA.Store(true)
	p.check(context.Background())
	if !p.backends[0].healthy.Load() {
		t.Fatal("backend did not recover")
	}
	a.Close()
	b.Close()
	p.check(context.Background())
	if p.ready() {
		t.Fatal("ready without healthy backend")
	}
	if w := request(p, "/", ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
}
func TestProxyErrorAndReadiness(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	p, err := newPool(s.URL, "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	p.check(context.Background())
	s.Close()
	if w := request(p, "/", ""); w.Code != 502 {
		t.Fatal(w.Code)
	}
	if p.ready() {
		t.Fatal("failed upstream remains healthy")
	}
	c := testConfig()
	c.upstreams = s.URL
	h := testApp(t, c)
	if w := request(h, "/readyz", ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if w := request(h, "/healthz", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, raw := range []string{"ftp://example.com", "http://user:pass@example.com", "http://example.com?q=1", "http://", "http://example.com,"} {
		if _, err := newPool(raw, "/healthz"); err == nil {
			t.Fatalf("accepted invalid upstream %s", raw)
		}
	}
}
func TestConcurrentRequests(t *testing.T) {
	c := testConfig()
	c.rps = 1e6
	c.burst = 1000
	h := testApp(t, c)
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := request(h, "/", ""); w.Code != 200 {
				t.Errorf("status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer s.Close()
	p, err := newPool(s.URL, "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	p.check(context.Background())
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.check(context.Background())
			if p.pick() == nil {
				t.Error("healthy backend not available")
			}
		}()
	}
	wg.Wait()
}
func TestConfigValidation(t *testing.T) {
	c := testConfig()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	cases := []func(*config){func(c *config) { c.rps = -1 }, func(c *config) { c.burst = 0 }, func(c *config) { c.authUser = "a" }, func(c *config) { c.authUser = "a:b"; c.authPassword = "p" }, func(c *config) { c.healthPath = "//evil" }, func(c *config) { c.domain = "example.com" }, func(c *config) { c.domain = "*.example.com"; c.email = "a@example.com"; c.acceptTOS = true }}
	for i, mutate := range cases {
		c := testConfig()
		mutate(&c)
		if c.validate() == nil {
			t.Errorf("accepted invalid config %d", i)
		}
	}
}
func TestHTTPServerLifecycle(t *testing.T) {
	// Exercise real listener startup and graceful cancellation through run.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := testConfig()
	c.httpAddr = "127.0.0.1:0"
	done := make(chan error, 1)
	go func() { done <- run(ctx, c) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server shutdown hung")
	}
}
func TestActualHTTP(t *testing.T) {
	s := httptest.NewServer(testApp(t, testConfig()))
	defer s.Close()
	res, err := s.Client().Get(s.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !strings.Contains(string(data), "<!doctype html>") {
		t.Fatal("HTTP homepage failed")
	}
}
