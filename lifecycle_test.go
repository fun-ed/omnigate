package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}
func TestRunHTTPSAndHTTP3FromCache(t *testing.T) {
	t.Run("fresh", func(t *testing.T) { testRunCachedProtocols(t, false) })
	t.Run("renewal_failure", func(t *testing.T) { testRunCachedProtocols(t, true) })
}

func testRunCachedProtocols(t *testing.T, renewalFailure bool) {
	t.Helper()
	c := testConfig()
	c.httpAddr = unusedTCPAddress(t)
	c.httpsAddr = unusedTCPAddress(t)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.http3Addr = udp.LocalAddr().String()
	_ = udp.Close()
	c.domain = "example.com"
	c.email = "admin@example.com"
	c.acceptTOS = true
	c.certDir = t.TempDir()
	c.rps = 0
	if renewalFailure {
		c.acmeDirectory = "https://127.0.0.1:1/directory"
	}
	manager, err := newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	before, after := time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour)
	if renewalFailure {
		before = time.Now().Add(-89 * 24 * time.Hour)
		after = time.Now().Add(24 * time.Hour)
	}
	certPEM, keyPEM := makeTestCert(t, c.domain, before, after)
	manager.state.CertPEM, manager.state.KeyPEM = certPEM, keyPEM
	if err := manager.save(manager.state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, c) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(12 * time.Second):
			t.Error("server did not shut down")
		}
	})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	tcpTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.domain}, ForceAttemptHTTP2: true}
	defer tcpTransport.CloseIdleConnections()
	client := &http.Client{Transport: tcpTransport, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	var response *http.Response
	for {
		response, err = client.Get("https://" + c.httpsAddr + "/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cached HTTPS startup:", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || !strings.Contains(string(body), "<!doctype html>") || response.Header.Get("Alt-Svc") == "" {
		t.Fatal("HTTPS app or HTTP3 discovery failed")
	}
	h3Transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.domain}}
	defer h3Transport.Close()
	h3Client := &http.Client{Transport: h3Transport, Timeout: 3 * time.Second}
	response, err = h3Client.Get("https://" + c.http3Addr + "/")
	if err != nil {
		t.Fatal("full server HTTP3:", err)
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 3 || response.StatusCode != 200 || !strings.Contains(string(body), "<!doctype html>") {
		t.Fatal("full server HTTP3 app failed")
	}
}
