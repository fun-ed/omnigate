package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const maxHSTSMaxAge int64 = 2 * 365 * 24 * 60 * 60

type edgePolicy struct {
	publicURL      string
	publicHost     string
	httpsRedirect  bool
	trustedProxies []*net.IPNet
	clientIPHeader string
	privateCache   bool
	hstsMaxAge     int64
	frameOptions   string
	referrerPolicy string
}

type edgeRequestMetadata struct {
	clientIP   string
	scheme     string
	publicHost string
}

type edgeMetadataKey struct{}

func newEdgePolicy(c config) (*edgePolicy, error) {
	p := &edgePolicy{
		httpsRedirect:  c.httpsRedirect,
		privateCache:   c.privateCache,
		hstsMaxAge:     c.hstsMaxAge,
		clientIPHeader: canonicalClientIPHeader(c.clientIPHeader),
	}

	if c.publicURL != "" {
		canonicalURL, err := canonicalHTTPSOriginURL(c.publicURL)
		if err != nil {
			return nil, fmt.Errorf("-public-url must be an HTTPS origin URL: %w", err)
		}
		p.publicURL = canonicalURL.String()
		p.publicHost = canonicalURL.Host
	}
	if p.httpsRedirect && p.publicURL == "" {
		return nil, errors.New("-https-redirect requires -public-url")
	}

	for _, token := range strings.Fields(strings.ReplaceAll(c.trustedProxies, ",", " ")) {
		_, network, err := net.ParseCIDR(token)
		if err != nil {
			return nil, fmt.Errorf("-trusted-proxies contains invalid CIDR %q", token)
		}
		p.trustedProxies = append(p.trustedProxies, network)
	}
	if c.clientIPHeader != "" && p.clientIPHeader == "" {
		return nil, errors.New("-client-ip-header must be CF-Connecting-IP or X-Real-IP")
	}
	if p.clientIPHeader != "" && len(p.trustedProxies) == 0 {
		return nil, errors.New("-client-ip-header requires -trusted-proxies")
	}

	if c.hstsMaxAge < 0 || c.hstsMaxAge > maxHSTSMaxAge {
		return nil, fmt.Errorf("-hsts-max-age must be between 0 and %d seconds", maxHSTSMaxAge)
	}
	frameOptions, referrerPolicy, err := canonicalResponsePolicies(c.frameOptions, c.referrerPolicy)
	if err != nil {
		return nil, err
	}
	p.frameOptions, p.referrerPolicy = frameOptions, referrerPolicy
	return p, nil
}

func canonicalHTTPSOriginURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "?#") {
		return nil, errors.New("must not contain whitespace, query or fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.User != nil || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("must be HTTPS and contain only an origin")
	}
	if (u.Path != "" && u.Path != "/") || (u.RawPath != "" && u.RawPath != "/") {
		return nil, errors.New("path must be empty or root")
	}

	host, port, bracketed, err := splitOriginHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, errors.New("host is empty")
	}
	var canonicalHost string
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, ":") && !bracketed {
			return nil, errors.New("IPv6 hosts must be bracketed")
		}
		canonicalHost = ip.String()
		if ip.To4() != nil {
			canonicalHost = ip.To4().String()
		}
		if strings.Contains(canonicalHost, ":") {
			canonicalHost = "[" + canonicalHost + "]"
		}
	} else {
		if bracketed || !validOriginDNSName(host) {
			return nil, errors.New("invalid host")
		}
		canonicalHost = strings.ToLower(host)
	}
	if port != "" {
		for _, r := range port {
			if r < '0' || r > '9' {
				return nil, errors.New("invalid port")
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid port")
		}
		canonicalHost += ":" + strconv.Itoa(n)
	}

	return &url.URL{Scheme: "https", Host: canonicalHost, Path: "/"}, nil
}

func splitOriginHostPort(raw string) (host, port string, bracketed bool, err error) {
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", "", false, errors.New("invalid bracketed host")
		}
		host = raw[1:end]
		bracketed = true
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				return "", "", false, errors.New("invalid host port")
			}
			port = rest[1:]
		}
		return host, port, bracketed, nil
	}
	if strings.ContainsAny(raw, "[]") {
		return "", "", false, errors.New("invalid host")
	}
	switch strings.Count(raw, ":") {
	case 0:
		return raw, "", false, nil
	case 1:
		parts := strings.SplitN(raw, ":", 2)
		if parts[1] == "" {
			return "", "", false, errors.New("invalid host port")
		}
		return parts[0], parts[1], false, nil
	default:
		return "", "", false, errors.New("IPv6 hosts must be bracketed")
	}
}

func validOriginDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	numeric := true
	for _, r := range host {
		if r < '0' || r > '9' {
			if r != '.' {
				numeric = false
			}
		}
	}
	if numeric {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func canonicalClientIPHeader(header string) string {
	switch strings.ToLower(strings.TrimSpace(header)) {
	case "cf-connecting-ip":
		return "CF-Connecting-IP"
	case "x-real-ip":
		return "X-Real-IP"
	default:
		return ""
	}
}

func canonicalResponsePolicies(frameOptions, referrerPolicy string) (string, string, error) {
	frame := ""
	switch strings.ToUpper(frameOptions) {
	case "":
	case "OFF":
		frame = "off"
	case "DENY":
		frame = "DENY"
	case "SAMEORIGIN":
		frame = "SAMEORIGIN"
	default:
		return "", "", errors.New("-frame-options must be DENY, SAMEORIGIN, off or empty")
	}

	referrer := ""
	switch strings.ToLower(referrerPolicy) {
	case "":
	case "off":
		referrer = "off"
	case "strict-origin-when-cross-origin":
		referrer = "strict-origin-when-cross-origin"
	case "no-referrer":
		referrer = "no-referrer"
	default:
		return "", "", errors.New("-referrer-policy must be strict-origin-when-cross-origin, no-referrer, off or empty")
	}
	return frame, referrer, nil
}

func (p *edgePolicy) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerIP, peerText := requestPeerIP(r)
		trusted := p.isTrustedProxy(peerIP)
		clientIP := peerText
		if trusted && p.clientIPHeader != "" {
			if forwardedIP, ok := singleValidIPHeader(r.Header, p.clientIPHeader); ok {
				clientIP = forwardedIP
			}
		}

		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		} else if trusted {
			if forwardedScheme, ok := singleForwardedScheme(r.Header); ok {
				scheme = forwardedScheme
			}
		}
		publicHost := r.Host
		if publicHost == "" && r.URL != nil {
			publicHost = r.URL.Host
		}
		if p.publicHost != "" {
			publicHost = p.publicHost
		}

		meta := edgeRequestMetadata{clientIP: clientIP, scheme: scheme, publicHost: publicHost}
		r = r.WithContext(context.WithValue(r.Context(), edgeMetadataKey{}, meta))
		health := r.URL != nil && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz")
		policyWriter := newEdgePolicyResponseWriter(w, p, scheme == "https", health)
		defer func() {
			if recovered := recover(); recovered != nil {
				if !policyWriter.committed && !policyWriter.hijacked {
					policyWriter.prepareHeaders()
				}
				panic(recovered)
			}
			policyWriter.finish()
		}()

		if p.httpsRedirect && !health && requestScheme(r) == "http" {
			policyWriter.Header().Set("Cache-Control", "no-store")
			policyWriter.Header().Set("Location", p.redirectLocation(r))
			policyWriter.WriteHeader(http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(policyWriter, r)
	})
}

func (p *edgePolicy) isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range p.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestPeerIP(r *http.Request) (net.IP, string) {
	if r == nil {
		return nil, ""
	}
	remote := r.RemoteAddr
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = strings.Trim(remote, "[]")
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return ip, v4.String()
		}
		return ip, ip.String()
	}
	return nil, remote
}

func singleHeaderValue(header http.Header, name string) (string, bool) {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	if value == "" || strings.Contains(value, ",") {
		return "", false
	}
	return value, true
}

func singleValidIPHeader(header http.Header, name string) (string, bool) {
	value, ok := singleHeaderValue(header, name)
	if !ok {
		return "", false
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return ip.String(), true
}

func singleForwardedScheme(header http.Header) (string, bool) {
	value, ok := singleHeaderValue(header, "X-Forwarded-Proto")
	if !ok {
		return "", false
	}
	switch strings.ToLower(value) {
	case "http":
		return "http", true
	case "https":
		return "https", true
	default:
		return "", false
	}
}

func requestClientIP(r *http.Request) string {
	if r != nil {
		if metadata, ok := r.Context().Value(edgeMetadataKey{}).(edgeRequestMetadata); ok && metadata.clientIP != "" {
			return metadata.clientIP
		}
	}
	_, peer := requestPeerIP(r)
	return peer
}

func requestScheme(r *http.Request) string {
	if r != nil && r.TLS != nil {
		return "https"
	}
	if r != nil {
		if metadata, ok := r.Context().Value(edgeMetadataKey{}).(edgeRequestMetadata); ok && (metadata.scheme == "http" || metadata.scheme == "https") {
			return metadata.scheme
		}
	}
	return "http"
}

func requestPublicHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if metadata, ok := r.Context().Value(edgeMetadataKey{}).(edgeRequestMetadata); ok {
		return metadata.publicHost
	}
	if r.Host != "" {
		return r.Host
	}
	if r.URL != nil {
		return r.URL.Host
	}
	return ""
}

func (p *edgePolicy) redirectLocation(r *http.Request) string {
	path := "/"
	if r.URL != nil && r.URL.EscapedPath() != "" {
		path = r.URL.EscapedPath()
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	location := strings.TrimSuffix(p.publicURL, "/") + path
	if r.URL != nil && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		location += "?" + r.URL.RawQuery
	}
	return location
}

func enforcePrivateCache(header http.Header) {
	for key := range header {
		switch {
		case strings.EqualFold(key, "Cache-Control"),
			strings.EqualFold(key, "CDN-Cache-Control"),
			strings.EqualFold(key, "Cloudflare-CDN-Cache-Control"),
			strings.EqualFold(key, "Surrogate-Control"),
			strings.EqualFold(key, "Expires"),
			strings.EqualFold(key, "Age"):
			delete(header, key)
		}
	}
	header.Set("Cache-Control", "private, no-store")
}

type edgePolicyResponseWriter struct {
	underlying http.ResponseWriter
	header     http.Header
	policy     *edgePolicy
	https      bool
	health     bool
	committed  bool
	hijacked   bool
}

func newEdgePolicyResponseWriter(w http.ResponseWriter, policy *edgePolicy, https, health bool) *edgePolicyResponseWriter {
	return &edgePolicyResponseWriter{
		underlying: w,
		header:     cloneHTTPHeader(w.Header()),
		policy:     policy,
		https:      https,
		health:     health,
	}
}

func cloneHTTPHeader(source http.Header) http.Header {
	cloned := make(http.Header, len(source))
	for key, values := range source {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func (w *edgePolicyResponseWriter) Header() http.Header {
	if w.committed || w.hijacked {
		return w.underlying.Header()
	}
	return w.header
}

func (w *edgePolicyResponseWriter) WriteHeader(statusCode int) {
	if w.committed {
		return
	}
	applyEdgeResponsePolicy(w.header, w.policy, w.https, w.health)
	copyHTTPHeader(w.underlying.Header(), w.header)
	w.underlying.WriteHeader(statusCode)
	if statusCode < 100 || statusCode >= 200 || statusCode == http.StatusSwitchingProtocols {
		w.committed = true
	}
}

func (w *edgePolicyResponseWriter) Write(body []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return w.underlying.Write(body)
}

func (w *edgePolicyResponseWriter) Flush() {
	_ = w.FlushError()
}

func (w *edgePolicyResponseWriter) FlushError() error {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.underlying).Flush()
}

func (w *edgePolicyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	// Preserve staged application headers before ReverseProxy copies upgrade
	// headers. Its ModifyResponse hook applies policy to the upgrade itself.
	copyHTTPHeader(w.underlying.Header(), w.header)
	conn, rw, err := http.NewResponseController(w.underlying).Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, rw, err
}

func (w *edgePolicyResponseWriter) Push(target string, options *http.PushOptions) error {
	writer := w.underlying
	for range 100 {
		if pusher, ok := writer.(http.Pusher); ok {
			return pusher.Push(target, options)
		}
		unwrapper, ok := writer.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return http.ErrNotSupported
		}
		writer = unwrapper.Unwrap()
		if writer == nil {
			return http.ErrNotSupported
		}
	}
	return http.ErrNotSupported
}

func (w *edgePolicyResponseWriter) Unwrap() http.ResponseWriter { return w.underlying }

func (w *edgePolicyResponseWriter) prepareHeaders() {
	applyEdgeResponsePolicy(w.header, w.policy, w.https, w.health)
	copyHTTPHeader(w.underlying.Header(), w.header)
}

func (w *edgePolicyResponseWriter) finish() {
	if w.committed || w.hijacked {
		return
	}
	w.prepareHeaders()
	w.underlying.WriteHeader(http.StatusOK)
	w.committed = true
}

func applyEdgeResponsePolicy(header http.Header, policy *edgePolicy, https, health bool) {
	if health || policy.privateCache {
		enforcePrivateCache(header)
	}
	if policy.hstsMaxAge > 0 {
		if https {
			setHeaderValue(header, "Strict-Transport-Security", fmt.Sprintf("max-age=%d", policy.hstsMaxAge))
		} else {
			deleteHeaderCaseInsensitive(header, "Strict-Transport-Security")
		}
	}
	if policy.frameOptions != "" {
		if policy.frameOptions == "off" {
			deleteHeaderCaseInsensitive(header, "X-Frame-Options")
		} else {
			setHeaderValue(header, "X-Frame-Options", policy.frameOptions)
		}
	}
	if policy.referrerPolicy != "" {
		if policy.referrerPolicy == "off" {
			deleteHeaderCaseInsensitive(header, "Referrer-Policy")
		} else {
			setHeaderValue(header, "Referrer-Policy", policy.referrerPolicy)
		}
	}
}

func copyHTTPHeader(destination, source http.Header) {
	for key := range destination {
		delete(destination, key)
	}
	for key, values := range source {
		destination[key] = append([]string(nil), values...)
	}
}

func deleteHeaderCaseInsensitive(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(key, name) {
			delete(header, key)
		}
	}
}

func setHeaderValue(header http.Header, name, value string) {
	deleteHeaderCaseInsensitive(header, name)
	header.Set(name, value)
}
