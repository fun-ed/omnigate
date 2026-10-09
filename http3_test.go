package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3TLSAuthAndAltSvc(t *testing.T) {
	c := testConfig()
	c.domain = "example.com"
	c.email = "admin@example.com"
	c.acceptTOS = true
	c.http3Addr = "127.0.0.1:0"
	c.rps = 0
	c.authUser = "admin"
	c.authPassword = "local-password"
	certPEM, keyPEM := makeTestCert(t, c.domain, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	cert, err := parseCertificate(certPEM, keyPEM, c.domain)
	if err != nil {
		t.Fatal(err)
	}
	manager := &certManager{cfg: c}
	manager.cert.Store(cert)
	server, conn, advertised, err := newHTTP3Server(c.http3Addr, &tls.Config{GetCertificate: manager.getCertificate, MinVersion: tls.VersionTLS12}, testApp(t, c))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(conn) }()
	defer func() {
		_ = server.Close()
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("QUIC listener did not stop")
		}
	}()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid test CA")
	}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.domain}}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	base := "https://" + conn.LocalAddr().String()
	res, err := client.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.ProtoMajor != 3 || res.StatusCode != 401 {
		t.Fatalf("HTTP3 should enforce auth, got %s %d", res.Proto, res.StatusCode)
	}
	req, err := http.NewRequest(http.MethodGet, base+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", "local-password")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if res.ProtoMajor != 3 || res.StatusCode != 200 || !strings.Contains(string(body), "<!doctype html>") {
		t.Fatalf("QUIC request failed: %s %d", res.Proto, res.StatusCode)
	}
	// HTTPS and QUIC share the same certificate and application handler.
	https := httptest.NewUnstartedServer(advertised)
	https.TLS = &tls.Config{GetCertificate: manager.getCertificate, MinVersion: tls.VersionTLS12}
	https.EnableHTTP2 = true
	https.StartTLS()
	defer https.Close()
	tcpTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.domain}, ForceAttemptHTTP2: true}
	defer tcpTransport.CloseIdleConnections()
	tcpClient := &http.Client{Transport: tcpTransport, Timeout: 5 * time.Second}
	req, err = http.NewRequest(http.MethodGet, https.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", "local-password")
	res, err = tcpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	want := fmt.Sprintf(`h3=":%d"`, server.Port)
	if res.ProtoMajor != 2 || res.StatusCode != 200 || !strings.Contains(res.Header.Get("Alt-Svc"), want) {
		t.Fatalf("HTTPS discovery: %s %d Alt-Svc=%q", res.Proto, res.StatusCode, res.Header.Get("Alt-Svc"))
	}
	if server.QUICConfig.Allow0RTT {
		t.Fatal("replayable 0-RTT requests enabled")
	}
	// Certificate replacement is seen by new QUIC handshakes without restarting.
	nextPEM, nextKey := makeTestCert(t, c.domain, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	nextCert, err := parseCertificate(nextPEM, nextKey, c.domain)
	if err != nil {
		t.Fatal(err)
	}
	manager.cert.Store(nextCert)
	nextRoots := x509.NewCertPool()
	nextRoots.AppendCertsFromPEM(nextPEM)
	nextTransport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: nextRoots, ServerName: c.domain}}
	defer nextTransport.Close()
	nextClient := &http.Client{Transport: nextTransport, Timeout: 5 * time.Second}
	res, err = nextClient.Get(base + "/healthz")
	if err != nil {
		t.Fatal("rotated QUIC certificate:", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	_ = nextTransport.Close()
	_ = transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal("QUIC graceful shutdown:", err)
	}
}
