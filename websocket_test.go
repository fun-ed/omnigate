package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebSocketAndWSS(t *testing.T) {
	for _, frontTLS := range []bool{false, true} {
		for _, upstreamTLS := range []bool{false, true} {
			t.Run(fmt.Sprintf("frontTLS=%t/upstreamTLS=%t", frontTLS, upstreamTLS), func(t *testing.T) {
				var credentialsLeaked atomic.Bool
				echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/healthz" {
						w.WriteHeader(200)
						return
					}
					if r.Header.Get("Authorization") != "" {
						credentialsLeaked.Store(true)
					}
					if r.Header.Get("Upgrade") != "websocket" {
						http.Error(w, "upgrade required", 400)
						return
					}
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
					_, _ = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
					_ = rw.Flush()
					for range 2 {
						header := make([]byte, 2)
						if _, err := io.ReadFull(rw, header); err != nil {
							t.Error(err)
							return
						}
						if header[0] != 0x81 || header[1]&0x80 == 0 || header[1]&0x7f > 125 {
							t.Error("invalid masked test frame")
							return
						}
						mask := make([]byte, 4)
						if _, err := io.ReadFull(rw, mask); err != nil {
							t.Error(err)
							return
						}
						payload := make([]byte, int(header[1]&0x7f))
						if _, err := io.ReadFull(rw, payload); err != nil {
							t.Error(err)
							return
						}
						for i := range payload {
							payload[i] ^= mask[i%4]
						}
						_, _ = rw.Write([]byte{0x81, byte(len(payload))})
						_, _ = rw.Write(payload)
						if err := rw.Flush(); err != nil {
							t.Error(err)
							return
						}
					}
				})
				var upstream *httptest.Server
				if upstreamTLS {
					upstream = httptest.NewTLSServer(echo)
				} else {
					upstream = httptest.NewServer(echo)
				}
				defer upstream.Close()
				raw := "ws" + strings.TrimPrefix(upstream.URL, "http")
				pool, err := newPool(raw, "/healthz")
				if err != nil {
					t.Fatal(err)
				}
				defer pool.close()
				if upstreamTLS {
					roots := x509.NewCertPool()
					roots.AddCert(upstream.Certificate())
					pool.transport.TLSClientConfig = &tls.Config{RootCAs: roots}
				}
				pool.check(context.Background())
				if !pool.ready() {
					t.Fatal("WebSocket upstream unhealthy")
				}
				h := newIPLimiter(10, 20).wrap(basicAuth(pool, "admin", "local-password"))
				var front *httptest.Server
				var clientTLS *tls.Config
				if frontTLS {
					certPEM, keyPEM := makeTestCert(t, "example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
					cert, err := parseCertificate(certPEM, keyPEM, "example.com")
					if err != nil {
						t.Fatal(err)
					}
					manager := &certManager{cfg: config{domain: "example.com"}}
					manager.cert.Store(cert)
					front = httptest.NewUnstartedServer(h)
					front.TLS = &tls.Config{GetCertificate: manager.getCertificate}
					front.StartTLS()
					roots := x509.NewCertPool()
					roots.AppendCertsFromPEM(certPEM)
					clientTLS = &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"http/1.1"}}
				} else {
					front = httptest.NewServer(h)
				}
				defer front.Close()
				u, err := url.Parse(front.URL)
				if err != nil {
					t.Fatal(err)
				}
				dial := func() net.Conn {
					t.Helper()
					var conn net.Conn
					var err error
					if frontTLS {
						conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", u.Host, clientTLS)
					} else {
						conn, err = net.DialTimeout("tcp", u.Host, 3*time.Second)
					}
					if err != nil {
						t.Fatal(err)
					}
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					return conn
				}
				handshake := func(conn net.Conn, auth string) (*http.Response, *bufio.Reader) {
					t.Helper()
					_, err := fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n%s\r\n", u.Host, auth)
					if err != nil {
						t.Fatal(err)
					}
					reader := bufio.NewReader(conn)
					res, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
					if err != nil {
						t.Fatal(err)
					}
					return res, reader
				}
				denied := dial()
				res, _ := handshake(denied, "")
				if res.StatusCode != 401 {
					t.Fatal("WebSocket bypassed Basic Auth")
				}
				_ = res.Body.Close()
				_ = denied.Close()
				conn := dial()
				defer conn.Close()
				auth := base64.StdEncoding.EncodeToString([]byte("admin:local-password"))
				res, reader := handshake(conn, "Authorization: Basic "+auth+"\r\n")
				if res.StatusCode != 101 || res.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
					t.Fatalf("upgrade failed: %d", res.StatusCode)
				}
				for _, message := range []string{"hello", "second message"} {
					frame := []byte{0x81, 0x80 | byte(len(message)), 1, 2, 3, 4}
					for i, ch := range []byte(message) {
						frame = append(frame, ch^byte(i%4+1))
					}
					if _, err := conn.Write(frame); err != nil {
						t.Fatal(err)
					}
					header := make([]byte, 2)
					if _, err := io.ReadFull(reader, header); err != nil {
						t.Fatal(err)
					}
					if header[0] != 0x81 || int(header[1]) != len(message) {
						t.Fatal("invalid echoed frame")
					}
					payload := make([]byte, len(message))
					if _, err := io.ReadFull(reader, payload); err != nil {
						t.Fatal(err)
					}
					if string(payload) != message {
						t.Fatal("bidirectional WebSocket message corrupted")
					}
				}
				if credentialsLeaked.Load() {
					t.Fatal("edge auth credentials forwarded to WebSocket upstream")
				}
			})
		}
	}
}
