package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHardeningWebfileAndCLI(t *testing.T) {
	t.Setenv("WEB_HTTP_AUTH_PASSWORD", "hardening-fixture-password")
	data, err := os.ReadFile("config/cloudflared-example.Webfile")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "Webfile")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig([]string{"-config", path})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if !c.httpsRedirect || !c.privateCache || !c.accessLog || c.hstsMaxAge != 86400 || c.frameOptions != "SAMEORIGIN" || c.referrerPolicy != "strict-origin-when-cross-origin" || c.maxBodyBytes != 0 {
		t.Fatal("production hardening settings were not parsed")
	}
	c, err = parseConfig([]string{"-config", path, "-https-redirect=false", "-private-cache=false", "-access-log=false", "-trusted-proxies=", "-client-ip-header=", "-hsts-max-age=0", "-frame-options=off", "-referrer-policy=off", "-max-body-bytes=4"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.httpsRedirect || c.privateCache || c.accessLog || c.trustedProxies != "" || c.clientIPHeader != "" || c.hstsMaxAge != 0 || c.maxBodyBytes != 4 {
		t.Fatal("explicit CLI flags did not override the Webfile")
	}
	for _, directive := range []string{
		"https_redirect maybe", "https_redirect on", "public_url http://example.com",
		"public_url https://example.com/path", "trusted_proxies localhost",
		"client_ip_header CF-Connecting-IP", "max_body_bytes -1", "hsts_max_age -1",
		"frame_options ALLOWALL", "referrer_policy unsafe-url", "private_cache perhaps", "access_log maybe",
	} {
		t.Run(directive, func(t *testing.T) {
			c, err := parseWebfile(strings.NewReader(":8080 {\n" + directive + "\n}\n"))
			if err == nil {
				err = c.validate()
			}
			if err == nil {
				t.Fatal("invalid hardening directive was accepted")
			}
		})
	}
}

func TestTrustedTunnelForwardingAndClientBuckets(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000")
		w.Header().Set("CDN-Cache-Control", "public, s-maxage=999")
		w.Header().Set("Cloudflare-CDN-Cache-Control", "public, max-age=999")
		w.Header().Set("Surrogate-Control", "max-age=999")
		w.Header().Set("Age", "123")
		w.Header().Set("X-Frame-Options", "ALLOWALL")
		w.Header().Set("Referrer-Policy", "unsafe-url")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ip": r.Header.Get("X-Forwarded-For"), "scheme": r.Header.Get("X-Forwarded-Proto"),
			"host": r.Host, "forwarded_host": r.Header.Get("X-Forwarded-Host"),
			"auth": r.Header.Get("Authorization"), "raw_cf": r.Header.Get("CF-Connecting-IP"),
			"raw_real": r.Header.Get("X-Real-IP"), "request_id": r.Header.Get("X-Request-ID"),
		})
	}))
	t.Cleanup(upstream.Close)
	c := defaultConfig()
	c.upstreams = upstream.URL
	c.publicURL = "https://omni.curl.rs"
	c.httpsRedirect = true
	c.trustedProxies = "127.0.0.1/32"
	c.clientIPHeader = "CF-Connecting-IP"
	c.privateCache = true
	c.hstsMaxAge = 86400
	c.frameOptions = "SAMEORIGIN"
	c.referrerPolicy = "strict-origin-when-cross-origin"
	c.authUser, c.authPassword = "admin", "hardening-fixture-password"
	c.rps, c.burst = 0.001, 1
	h := testApp(t, c)
	send := func(ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://forged-host.invalid/", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("CF-Connecting-IP", ip)
		r.Header.Set("X-Forwarded-For", "203.0.113.77")
		r.Header.Set("X-Real-IP", "203.0.113.78")
		r.Header.Set("X-Request-ID", "untrusted-request-id")
		r.SetBasicAuth(c.authUser, c.authPassword)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		w := send(ip)
		if w.Code != 200 {
			t.Fatalf("independent client bucket returned %d", w.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["ip"] != ip || body["scheme"] != "https" || body["host"] != "omni.curl.rs" || body["forwarded_host"] != "omni.curl.rs" || body["auth"] != "" || body["raw_cf"] != "" || body["raw_real"] != "" || body["request_id"] != "" {
			t.Fatal("verified metadata was lost or untrusted headers leaked")
		}
		if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("CDN-Cache-Control") != "" || w.Header().Get("Cloudflare-CDN-Cache-Control") != "" || w.Header().Get("Surrogate-Control") != "" || w.Header().Get("Age") != "" || w.Header().Get("X-Frame-Options") != "SAMEORIGIN" || w.Header().Get("Referrer-Policy") != c.referrerPolicy || w.Header().Get("Strict-Transport-Security") != "max-age=86400" {
			t.Fatal("upstream headers overrode the private response policy")
		}
	}
	if w := send("192.0.2.1"); w.Code != 429 {
		t.Fatal("same client bucket was not rate limited")
	}
}

func TestBodyRejectionDoesNotDisableBackend(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			return
		}
		if r.Method == http.MethodPost {
			t.Error("known oversized body reached upstream")
		}
		_, _ = io.WriteString(w, "healthy")
	}))
	t.Cleanup(upstream.Close)
	c := defaultConfig()
	c.upstreams = upstream.URL
	c.maxBodyBytes = 4
	c.authUser, c.authPassword = "admin", "hardening-fixture-password"
	h := testApp(t, c)
	r := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader("too-large-body"))
	r.SetBasicAuth(c.authUser, c.authPassword)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("oversized body returned %d", w.Code)
	}
	if w := request(h, "/readyz", ""); w.Code != 200 {
		t.Fatal("client upload rejection made backend unhealthy")
	}
}
