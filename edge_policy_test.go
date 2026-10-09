package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewEdgePolicyValidation(t *testing.T) {
	valid := config{
		publicURL:      "HTTPS://Public.Example:8443/",
		httpsRedirect:  true,
		trustedProxies: "192.0.2.0/24, 2001:db8::/32",
		clientIPHeader: "cf-connecting-ip",
		hstsMaxAge:     maxHSTSMaxAge,
		frameOptions:   "sameorigin",
		referrerPolicy: "NO-REFERRER",
	}
	if _, err := newEdgePolicy(valid); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}

	invalid := []struct {
		name   string
		change func(*config)
	}{
		{"redirect requires public URL", func(c *config) { c.httpsRedirect = true }},
		{"non-HTTPS URL", func(c *config) { c.publicURL = "http://public.example" }},
		{"userinfo", func(c *config) { c.publicURL = "https://user@public.example" }},
		{"query", func(c *config) { c.publicURL = "https://public.example?" }},
		{"fragment", func(c *config) { c.publicURL = "https://public.example#" }},
		{"non-root path", func(c *config) { c.publicURL = "https://public.example/app" }},
		{"invalid host", func(c *config) { c.publicURL = "https://bad..example" }},
		{"invalid port", func(c *config) { c.publicURL = "https://public.example:65536" }},
		{"nonnumeric port", func(c *config) { c.publicURL = "https://public.example:abc" }},
		{"malformed CIDR", func(c *config) { c.trustedProxies = "192.0.2.1" }},
		{"invalid client IP header", func(c *config) { c.clientIPHeader = "X-Forwarded-For" }},
		{"client IP header needs proxy ranges", func(c *config) { c.clientIPHeader = "X-Real-IP"; c.trustedProxies = "" }},
		{"negative HSTS", func(c *config) { c.hstsMaxAge = -1 }},
		{"excessive HSTS", func(c *config) { c.hstsMaxAge = maxHSTSMaxAge + 1 }},
		{"invalid frame policy", func(c *config) { c.frameOptions = "ALLOWALL" }},
		{"invalid referrer policy", func(c *config) { c.referrerPolicy = "unsafe-url" }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			c := config{}
			if test.name != "redirect requires public URL" {
				c = valid
			}
			test.change(&c)
			if _, err := newEdgePolicy(c); err == nil {
				t.Fatal("expected invalid edge policy to be rejected")
			}
		})
	}
}

func TestEdgePolicyTrustedRequestMetadata(t *testing.T) {
	policy, err := newEdgePolicy(config{
		publicURL:      "https://public.example:8443",
		trustedProxies: "192.0.2.0/24",
		clientIPHeader: "CF-Connecting-IP",
	})
	if err != nil {
		t.Fatal(err)
	}
	observe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s|%s|%s", requestClientIP(r), requestScheme(r), requestPublicHost(r))
	})

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  []string
		proto      []string
		xff        string
		want       string
	}{
		{
			name:       "trusted metadata accepted",
			remoteAddr: "192.0.2.7:1234",
			forwarded:  []string{"198.51.100.8"},
			proto:      []string{"https"},
			want:       "198.51.100.8|https|public.example:8443",
		},
		{
			name:       "untrusted metadata ignored",
			remoteAddr: "198.51.100.9:1234",
			forwarded:  []string{"203.0.113.4"},
			proto:      []string{"https"},
			want:       "198.51.100.9|http|public.example:8443",
		},
		{
			name:       "malformed and repeated metadata ignored",
			remoteAddr: "192.0.2.10:1234",
			forwarded:  []string{"198.51.100.1", "198.51.100.2"},
			proto:      []string{"http,https"},
			want:       "192.0.2.10|http|public.example:8443",
		},
		{
			name:       "X-Forwarded-For is not a client IP source",
			remoteAddr: "192.0.2.12:1234",
			proto:      []string{"http"},
			xff:        "203.0.113.19, 198.51.100.20",
			want:       "192.0.2.12|http|public.example:8443",
		},
		{
			name:       "invalid single IP ignored",
			remoteAddr: "192.0.2.11:1234",
			forwarded:  []string{"not-an-ip"},
			proto:      []string{"ftp"},
			want:       "192.0.2.11|http|public.example:8443",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://incoming.example/", nil)
			r.RemoteAddr = test.remoteAddr
			for _, value := range test.forwarded {
				r.Header.Add("CF-Connecting-IP", value)
			}
			for _, value := range test.proto {
				r.Header.Add("X-Forwarded-Proto", value)
			}
			if test.xff != "" {
				r.Header.Set("X-Forwarded-For", test.xff)
			}
			w := httptest.NewRecorder()
			policy.wrap(observe).ServeHTTP(w, r)
			if got := w.Body.String(); got != test.want {
				t.Fatalf("metadata = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEdgePolicyTLSPriorityAndRedirect(t *testing.T) {
	policy, err := newEdgePolicy(config{publicURL: "https://public.example", httpsRedirect: true, trustedProxies: "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h := policy.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(requestScheme(r)))
	}))

	tlsRequest := httptest.NewRequest(http.MethodGet, "http://attacker.example/secure", nil)
	tlsRequest.RemoteAddr = "192.0.2.3:80"
	tlsRequest.TLS = &tls.ConnectionState{}
	tlsRequest.Header.Set("X-Forwarded-Proto", "http")
	tlsResponse := httptest.NewRecorder()
	h.ServeHTTP(tlsResponse, tlsRequest)
	if tlsResponse.Code != http.StatusOK || tlsResponse.Body.String() != "https" || tlsResponse.Header().Get("Location") != "" {
		t.Fatalf("TLS request was downgraded or redirected: status=%d body=%q location=%q", tlsResponse.Code, tlsResponse.Body.String(), tlsResponse.Header().Get("Location"))
	}

	trustedHTTPS := httptest.NewRequest(http.MethodGet, "http://attacker.example/already-secure", nil)
	trustedHTTPS.RemoteAddr = "192.0.2.3:80"
	trustedHTTPS.Header.Set("X-Forwarded-Proto", "https")
	trustedResponse := httptest.NewRecorder()
	h.ServeHTTP(trustedResponse, trustedHTTPS)
	if trustedResponse.Code != http.StatusOK || trustedResponse.Body.String() != "https" || trustedResponse.Header().Get("Location") != "" {
		t.Fatalf("trusted HTTPS request was redirected: status=%d body=%q", trustedResponse.Code, trustedResponse.Body.String())
	}
}

func TestEdgePolicyRedirectUsesCanonicalOriginAndPreservesTarget(t *testing.T) {
	policy, err := newEdgePolicy(config{publicURL: "HTTPS://Public.Example:8443/", httpsRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	h := policy.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequest(http.MethodGet, "http://attacker.example/a/%2f/b/?x=%2F&next=https%3A%2F%2Fevil.example", nil)
	r.Host = "attacker.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	want := "https://public.example:8443/a/%2f/b/?x=%2F&next=https%3A%2F%2Fevil.example"
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != want {
		t.Fatalf("redirect = %d %q, want 301 %q", w.Code, w.Header().Get("Location"), want)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("redirect cache control = %q, want no-store", got)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Host != "public.example:8443" {
		t.Fatalf("redirect host escaped canonical origin: %q (%v)", w.Header().Get("Location"), err)
	}

	maliciousPath := httptest.NewRequest(http.MethodGet, "http://attacker.example//evil.example/path", nil)
	maliciousResponse := httptest.NewRecorder()
	h.ServeHTTP(maliciousResponse, maliciousPath)
	maliciousLocation, err := url.Parse(maliciousResponse.Header().Get("Location"))
	if err != nil || maliciousLocation.Host != "public.example:8443" {
		t.Fatalf("path-controlled redirect escaped canonical origin: %q (%v)", maliciousResponse.Header().Get("Location"), err)
	}
}

func TestEdgePolicyHealthExceptionAndNoStore(t *testing.T) {
	policy, err := newEdgePolicy(config{publicURL: "https://public.example", httpsRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	h := policy.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Header().Set("CDN-Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
	}))
	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://incoming.example"+path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
				t.Fatalf("health endpoint redirected: status=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			if got := w.Header().Get("Cache-Control"); got != "private, no-store" || w.Header().Get("CDN-Cache-Control") != "" {
				t.Fatalf("health cache policy = %q, CDN=%q", got, w.Header().Get("CDN-Cache-Control"))
			}
		})
	}
}

func TestEdgePolicyAuthoritativeHeadersOnResponses(t *testing.T) {
	policy, err := newEdgePolicy(config{
		privateCache:   true,
		hstsMaxAge:     86400,
		frameOptions:   "DENY",
		referrerPolicy: "no-referrer",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		method     string
		statusCode int
	}{
		{name: "HEAD without body", method: http.MethodHead, statusCode: http.StatusOK},
		{name: "304", method: http.MethodGet, statusCode: http.StatusNotModified},
		{name: "error", method: http.MethodGet, statusCode: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := policy.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=600")
				w.Header().Set("CDN-Cache-Control", "public, s-maxage=600")
				w.Header().Set("Cloudflare-CDN-Cache-Control", "public, s-maxage=600")
				w.Header().Set("Surrogate-Control", "max-age=600")
				w.Header().Set("Expires", "Wed, 21 Oct 2030 07:28:00 GMT")
				w.Header().Set("Strict-Transport-Security", "max-age=999999; includeSubDomains; preload")
				w.Header().Set("X-Frame-Options", "SAMEORIGIN")
				w.Header().Set("Referrer-Policy", "unsafe-url")
				w.WriteHeader(test.statusCode)
			}))
			r := httptest.NewRequest(test.method, "https://public.example/resource", nil)
			r.TLS = &tls.ConnectionState{}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.statusCode {
				t.Fatalf("status = %d, want %d", w.Code, test.statusCode)
			}
			if test.method == http.MethodHead && w.Body.Len() != 0 {
				t.Fatalf("HEAD returned a body: %q", w.Body.String())
			}
			if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
				t.Errorf("Cache-Control = %q", got)
			}
			for _, name := range []string{"CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control", "Expires"} {
				if got := w.Header().Get(name); got != "" {
					t.Errorf("%s survived private cache policy: %q", name, got)
				}
			}
			if got := w.Header().Get("Strict-Transport-Security"); got != "max-age=86400" {
				t.Errorf("HSTS = %q", got)
			}
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q", got)
			}
			if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q", got)
			}
		})
	}
}

func TestEdgePolicyHSTSOnlyOnHTTPSAndOffPoliciesRemoveUpstreamValues(t *testing.T) {
	policy, err := newEdgePolicy(config{hstsMaxAge: 3600, frameOptions: "off", referrerPolicy: "off"})
	if err != nil {
		t.Fatal(err)
	}
	h := policy.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=600")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
	}))

	httpResponse := httptest.NewRecorder()
	h.ServeHTTP(httpResponse, httptest.NewRequest(http.MethodGet, "http://public.example/", nil))
	if got := httpResponse.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS was sent over HTTP: %q", got)
	}
	if httpResponse.Header().Get("X-Frame-Options") != "" || httpResponse.Header().Get("Referrer-Policy") != "" {
		t.Fatalf("off policy retained upstream security headers: %v", httpResponse.Header())
	}

	httpsRequest := httptest.NewRequest(http.MethodGet, "https://public.example/", nil)
	httpsRequest.TLS = &tls.ConnectionState{}
	httpsResponse := httptest.NewRecorder()
	h.ServeHTTP(httpsResponse, httpsRequest)
	if got := httpsResponse.Header().Get("Strict-Transport-Security"); got != "max-age=3600" {
		t.Fatalf("HTTPS HSTS = %q", got)
	}
}

func TestEdgePolicyDisabledPreservesApplicationHeaders(t *testing.T) {
	policy, err := newEdgePolicy(config{})
	if err != nil {
		t.Fatal(err)
	}
	h := policy.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=120")
		w.Header().Set("Strict-Transport-Security", "max-age=90")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "origin")
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("ok"))
		}
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://public.example/", nil))
	for name, want := range map[string]string{
		"Cache-Control":             "public, max-age=120",
		"Strict-Transport-Security": "max-age=90",
		"X-Frame-Options":           "SAMEORIGIN",
		"Referrer-Policy":           "origin",
	} {
		if got := w.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	health := httptest.NewRecorder()
	h.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "http://public.example/healthz", nil))
	if got := health.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("health cache control = %q", got)
	}
}

func TestEdgePolicyFlushAppliesHeadersBeforeStreaming(t *testing.T) {
	policy, err := newEdgePolicy(config{frameOptions: "DENY"})
	if err != nil {
		t.Fatal(err)
	}
	h := policy.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
			return
		}
		_, _ = w.Write([]byte("stream"))
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://public.example/", nil))
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("streaming response policy = %q", got)
	}
	if !strings.Contains(w.Body.String(), "stream") {
		t.Fatalf("stream body = %q", w.Body.String())
	}
}
