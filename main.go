package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const googleACME = "https://dv.acme-v02.api.pki.goog/directory"

type config struct {
	httpAddr, httpsAddr, domain, email, acmeDirectory, certDir string
	root, upstreams, healthPath, authUser, authPassword        string
	rps                                                        float64
	burst                                                      int
	healthInterval                                             time.Duration
	http3Addr, googleProject, gcloudPath                       string
	googleSetup                                                bool
	acceptTOS                                                  bool
	publicURL, trustedProxies, clientIPHeader                  string
	frameOptions, referrerPolicy                               string
	httpsRedirect, privateCache, accessLog                     bool
	hstsMaxAge, maxBodyBytes                                   int64
}

func (c config) validate() error {
	if c.httpAddr == "" {
		return errors.New("-http must not be empty")
	}
	if c.rps < 0 || c.rps != c.rps || c.rps > 1e6 || c.burst < 1 || c.healthInterval <= 0 {
		return errors.New("invalid rate, burst or health interval")
	}
	if (c.authUser == "") != (c.authPassword == "") {
		return errors.New("set both -auth-user and WEB_HTTP_AUTH_PASSWORD to enable Basic Auth")
	}
	if strings.Contains(c.authUser, ":") {
		return errors.New("Basic Auth username must not contain ':'")
	}
	if c.maxBodyBytes < 0 {
		return errors.New("-max-body-bytes must not be negative")
	}
	if _, err := newEdgePolicy(c); err != nil {
		return err
	}
	p, err := url.Parse(c.healthPath)
	if err != nil || !strings.HasPrefix(c.healthPath, "/") || strings.HasPrefix(c.healthPath, "//") || p.IsAbs() || p.Host != "" || p.Fragment != "" {
		return errors.New("-health-path must be an absolute URL path")
	}
	if c.domain != "" {
		if net.ParseIP(c.domain) != nil || !strings.Contains(c.domain, ".") || len(c.domain) > 253 {
			return errors.New("-domain must be a lowercase DNS hostname, without port or wildcard")
		}
		for _, label := range strings.Split(c.domain, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errors.New("-domain contains an invalid DNS label")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return errors.New("-domain must use lowercase ASCII DNS labels (use punycode for IDNs)")
				}
			}
		}
		if c.email == "" || !c.acceptTOS || c.httpsAddr == "" {
			return errors.New("HTTPS requires -email, -accept-tos and -https")
		}
		u, err := url.Parse(c.acmeDirectory)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("-acme-directory must be an HTTPS URL")
		}
	}
	if c.http3Addr != "" {
		_, port, err := net.SplitHostPort(c.http3Addr)
		n, parseErr := strconv.Atoi(port)
		if c.domain == "" || err != nil || parseErr != nil || n < 0 || n > 65535 {
			return errors.New("-http3 requires HTTPS and a valid UDP host:port address")
		}
	}
	return nil
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
}

func run(ctx context.Context, c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	app, closeApp, err := newApp(ctx, c)
	if err != nil {
		return err
	}
	defer closeApp()
	var cm *certManager
	handler := app
	if c.domain != "" {
		cm, err = newCertManager(c)
		if err != nil {
			return err
		}
		cm.ctx = ctx
		handler = cm.httpHandler(c, app)
	}
	httpListener, err := net.Listen("tcp", c.httpAddr)
	if err != nil {
		return err
	}
	defer httpListener.Close()
	servers := []*http.Server{newHTTPServer(c.httpAddr, handler)}
	errorsCh := make(chan error, 3)
	go func(s *http.Server) { errorsCh <- s.Serve(httpListener) }(servers[0])
	var h3Server *http3.Server
	var udpConn net.PacketConn
	defer func() {
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if h3Server != nil {
			if err := h3Server.Shutdown(shutdownCtx); err != nil {
				_ = h3Server.Close()
			}
			_ = udpConn.Close()
		}
		for _, s := range servers {
			if err := s.Shutdown(shutdownCtx); err != nil {
				_ = s.Close()
			}
		}
	}()
	if cm != nil {
		// The HTTP challenge listener must be running before requesting a certificate.
		if err := cm.ensureCertificate(); err != nil {
			if _, cachedErr := cm.getCertificate(&tls.ClientHelloInfo{ServerName: c.domain}); cachedErr != nil {
				return fmt.Errorf("ACME setup: %w", err)
			}
			slog.Warn("initial renewal failed; serving the valid cached certificate and retrying in background", "error", err)
		}
		tlsServer := newHTTPServer(c.httpsAddr, app)
		tlsServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cm.getCertificate}
		tlsListener, err := net.Listen("tcp", c.httpsAddr)
		if err != nil {
			return err
		}
		defer tlsListener.Close()
		if c.http3Addr != "" {
			var advertised http.Handler
			h3Server, udpConn, advertised, err = newHTTP3Server(c.http3Addr, tlsServer.TLSConfig, app)
			if err != nil {
				return err
			}
			tlsServer.Handler = advertised
		}
		servers = append(servers, tlsServer)
		go func() { errorsCh <- tlsServer.ServeTLS(tlsListener, "", "") }()
		if h3Server != nil {
			go func() { errorsCh <- h3Server.Serve(udpConn) }()
		}
		go cm.renewLoop(ctx)
	}
	slog.Info("server started", "http", httpListener.Addr(), "https_enabled", cm != nil, "http3", c.http3Addr)
	select {
	case <-ctx.Done():
		return nil
	case err := <-errorsCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := parseConfig(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err == nil && c.googleSetup {
		c, err = prepareGoogle(ctx, c, os.Stdin, os.Stdout)
	}
	if err == nil {
		err = run(ctx, c)
	}
	if err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
