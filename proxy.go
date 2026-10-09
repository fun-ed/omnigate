package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type backend struct {
	target    *url.URL
	healthURL string
	healthy   atomic.Bool
	proxy     *httputil.ReverseProxy
}
type upstreamPool struct {
	mu        sync.Mutex
	next      int
	backends  []*backend
	transport *http.Transport
	client    *http.Client
}

func newPool(raw, healthPath string) (*upstreamPool, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	p := &upstreamPool{transport: transport, client: &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if raw == "" {
		return p, nil
	}
	for _, item := range strings.Split(raw, ",") {
		u, err := url.Parse(strings.TrimSpace(item))
		if err != nil {
			return nil, errors.New("invalid upstream URL")
		}
		switch u.Scheme {
		case "ws":
			u.Scheme = "http"
		case "wss":
			u.Scheme = "https"
		}
		if u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
			return nil, errors.New("upstreams must be HTTP(S) or WS(S) URLs without credentials, query or fragment")
		}
		checkURL := *u
		hp, err := url.Parse(healthPath)
		if err != nil {
			return nil, fmt.Errorf("health path: %w", err)
		}
		checkURL.Path = strings.TrimSuffix(u.Path, "/") + hp.Path
		checkURL.RawPath = ""
		checkURL.RawQuery = hp.RawQuery
		b := &backend{target: u, healthURL: checkURL.String()}
		b.proxy = &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
				pr.SetXForwarded()
				pr.Out.Header.Set("X-Forwarded-For", requestClientIP(pr.In))
				pr.Out.Header.Set("X-Forwarded-Proto", requestScheme(pr.In))
				pr.Out.Header.Set("X-Forwarded-Host", requestPublicHost(pr.In))
				pr.Out.Header.Del("CF-Connecting-IP")
				pr.Out.Header.Del("X-Real-IP")
				pr.Out.Header.Del("X-Request-ID")
				if id := requestID(pr.In); id != "" {
					pr.Out.Header.Set("X-Request-ID", id)
				}
				pr.Out.Header.Del("Forwarded")
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				status := proxyErrorStatus(err)
				if r.Context().Err() == nil && status != http.StatusRequestEntityTooLarge {
					b.healthy.Store(false)
				}
				message := "upstream unavailable"
				if status == http.StatusRequestEntityTooLarge {
					message = "request body too large"
				}
				http.Error(w, message, status)
			},
		}
		p.backends = append(p.backends, b)
	}
	return p, nil
}
func (p *upstreamPool) close() { p.transport.CloseIdleConnections() }
func (p *upstreamPool) ready() bool {
	for _, b := range p.backends {
		if b.healthy.Load() {
			return true
		}
	}
	return false
}
func (p *upstreamPool) pick() *backend {
	p.mu.Lock()
	defer p.mu.Unlock()
	for range p.backends {
		b := p.backends[p.next]
		p.next = (p.next + 1) % len(p.backends)
		if b.healthy.Load() {
			return b
		}
	}
	return nil
}
func (p *upstreamPool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b := p.pick()
	if b == nil {
		http.Error(w, "no healthy upstream", http.StatusServiceUnavailable)
		return
	}
	// Do not retry failed application requests: POSTs may already have reached the backend.
	b.proxy.ServeHTTP(w, r)
}
func (p *upstreamPool) check(ctx context.Context) {
	var wg sync.WaitGroup
	for _, b := range p.backends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.healthURL, nil)
			if err != nil {
				b.healthy.Store(false)
				return
			}
			res, err := p.client.Do(req)
			if err != nil {
				b.healthy.Store(false)
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
			_ = res.Body.Close()
			b.healthy.Store(res.StatusCode >= 200 && res.StatusCode < 300)
		}()
	}
	wg.Wait()
}
func (p *upstreamPool) monitor(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.check(ctx)
		}
	}
}
