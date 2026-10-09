package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const defaultHTML = `<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>OmniGate</title></head>
<body><h1>OmniGate</h1><p>Web server is running.</p></body></html>`

func newApp(ctx context.Context, c config) (http.Handler, func(), error) {
	policy, err := newEdgePolicy(c)
	if err != nil {
		return nil, nil, err
	}
	pool, err := newPool(c.upstreams, c.healthPath)
	if err != nil {
		return nil, nil, err
	}
	for _, backend := range pool.backends {
		backend.proxy.ModifyResponse = func(response *http.Response) error {
			// Upgrade responses are serialized after hijacking, bypassing WriteHeader.
			applyEdgeResponsePolicy(response.Header, policy, requestScheme(response.Request) == "https", false)
			if c.accessLog && response.StatusCode == http.StatusSwitchingProtocols {
				deleteHeaderCaseInsensitive(response.Header, requestIDHeader)
			}
			return nil
		}
	}
	if c.publicURL != "" {
		for _, backend := range pool.backends {
			rewrite := backend.proxy.Rewrite
			backend.proxy.Rewrite = func(request *httputil.ProxyRequest) {
				rewrite(request)
				request.Out.Host = requestPublicHost(request.In)
			}
		}
	}
	var root *os.Root
	var files http.Handler
	if c.root != "" {
		root, err = os.OpenRoot(c.root)
		if err != nil {
			pool.close()
			return nil, nil, err
		}
		files = http.FileServerFS(publicFS{root.FS()})
	}
	closeApp := func() {
		pool.close()
		if root != nil {
			_ = root.Close()
		}
	}
	if len(pool.backends) > 0 {
		pool.check(ctx)
		go pool.monitor(ctx, c.healthInterval)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if files != nil && strings.HasPrefix(r.URL.Path, "/static/") {
			http.StripPrefix("/static", files).ServeHTTP(w, r)
			return
		}
		if len(pool.backends) > 0 {
			pool.ServeHTTP(w, r)
			return
		}
		if files != nil {
			if r.URL.Path != "/" {
				files.ServeHTTP(w, r)
				return
			}
			if _, err := fs.Stat(publicFS{root.FS()}, "index.html"); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(defaultHTML))
		}
	})
	var protected http.Handler = limitRequestBody(c.maxBodyBytes, application)
	if c.authUser != "" {
		protected = basicAuth(protected, c.authUser, c.authPassword)
	}
	if c.rps > 0 {
		protected = newIPLimiter(c.rps, c.burst).wrap(protected)
	}
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", 405)
				return
			}
			if r.URL.Path == "/readyz" && len(pool.backends) > 0 && !pool.ready() {
				http.Error(w, "no healthy upstream", 503)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte("ok\n"))
			}
			return
		}
		protected.ServeHTTP(w, r)
	})
	return observeRequests(c.accessLog, policy.wrap(final)), closeApp, nil
}

func basicAuth(next http.Handler, user, password string) http.Handler {
	expectedUser, expectedPass := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		actualUser, actualPass := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
		match := subtle.ConstantTimeCompare(actualUser[:], expectedUser[:]) & subtle.ConstantTimeCompare(actualPass[:], expectedPass[:])
		if !ok || match != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="OmniGate", charset="UTF-8"`)
			http.Error(w, "unauthorized", 401)
			return
		}
		// Edge credentials must not be forwarded to an upstream application.
		r = r.Clone(r.Context())
		r.Header.Del("Authorization")
		next.ServeHTTP(w, r)
	})
}

type ipEntry struct {
	limiter *rate.Limiter
	last    time.Time
}
type ipLimiter struct {
	mu        sync.Mutex
	entries   map[string]*ipEntry
	rps       rate.Limit
	burst     int
	lastSweep time.Time
}

func newIPLimiter(rps float64, burst int) *ipLimiter {
	return &ipLimiter{entries: make(map[string]*ipEntry), rps: rate.Limit(rps), burst: burst}
}
func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= time.Minute {
		for key, entry := range l.entries {
			if now.Sub(entry.last) >= 10*time.Minute {
				delete(l.entries, key)
			}
		}
		l.lastSweep = now
	}
	entry := l.entries[ip]
	if entry == nil {
		if len(l.entries) >= 10000 {
			return false
		}
		entry = &ipEntry{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.entries[ip] = entry
	}
	entry.last = now
	return entry.limiter.AllowN(now, 1)
}
func (l *ipLimiter) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := requestClientIP(r)
		// Never trust client-supplied X-Forwarded-For without an explicit trusted proxy configuration.
		if !l.allow(ip, time.Now()) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", 429)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// os.Root confines all file access, including symlinks, to the configured root.
// Dotfiles and directory listing are disabled; directories must contain index.html.
type publicFS struct{ fs.FS }

func (p publicFS) Open(name string) (fs.File, error) {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") && part != "." {
			return nil, fs.ErrNotExist
		}
	}
	f, err := p.FS.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.IsDir() {
		index := strings.TrimSuffix(name, "/") + "/index.html"
		if name == "." {
			index = "index.html"
		}
		stat, err := fs.Stat(p.FS, index)
		if err != nil || stat.IsDir() {
			_ = f.Close()
			return nil, fs.ErrNotExist
		}
	}
	return f, nil
}
