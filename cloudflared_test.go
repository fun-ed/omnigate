package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCloudflaredWebfile(t *testing.T) {
	t.Setenv("WEB_HTTP_AUTH_PASSWORD", "tunnel-fixture-password")
	data, err := os.ReadFile("config/cloudflared-example.Webfile")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseWebfile(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if c.httpAddr != "127.0.0.1:8081" || c.domain != "" || c.http3Addr != "" || c.googleSetup {
		t.Fatal("Go tunnel origin must be loopback HTTP-only on 8081 without Google setup")
	}
	if c.upstreams != "http://127.0.0.1:6767" || c.healthPath != "/healthz" {
		t.Fatal("Omnigent must remain the upstream on 6767, separate from the Go listener")
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if !c.httpsRedirect || !c.privateCache || !c.accessLog || c.publicURL != "https://example.com" || c.clientIPHeader != "CF-Connecting-IP" {
		t.Fatal("tunnel profile must explicitly enable private trusted-edge hardening")
	}
	c.accessLog = false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("edge credentials reached the upstream")
		}
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte("omni-origin-fixture"))
	}))
	t.Cleanup(upstream.Close)
	// Use an isolated upstream; unit tests must never contact the user's Omnigent.
	c.upstreams = upstream.URL
	h := testApp(t, c)
	send := func(path, authorization string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("CF-Connecting-IP", "192.0.2.1")
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if w := send(path, ""); w.Code != 200 || w.Header().Get("Location") != "" {
			t.Fatal("tunnel health endpoint was rejected or redirected")
		}
	}
	if w := send("/", ""); w.Code != 401 || w.Header().Get("Location") != "" {
		t.Fatal("tunnel origin must authenticate without an HTTPS redirect")
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:tunnel-fixture-password"))
	if w := send("/", auth); w.Code != 200 || w.Header().Get("Location") != "" || w.Body.String() != "omni-origin-fixture" {
		t.Fatal("authenticated tunnel request did not reach the isolated upstream without redirect")
	}
	if w := request(h, "/", ""); w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "https://example.com/" || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("HTTP application request must redirect before challenging for credentials")
	}
}
