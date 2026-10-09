package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func newHTTP3Server(addr string, tlsConfig *tls.Config, app http.Handler) (*http3.Server, net.PacketConn, http.Handler, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, nil, err
	}
	server := &http3.Server{
		Addr:      addr,
		Port:      conn.LocalAddr().(*net.UDPAddr).Port,
		TLSConfig: http3.ConfigureTLSConfig(tlsConfig.Clone()),
		// Disable 0-RTT so application requests, especially POSTs, cannot be replayed.
		QUICConfig:     &quic.Config{Allow0RTT: false, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 90 * time.Second},
		Handler:        app,
		MaxHeaderBytes: 1 << 20,
		IdleTimeout:    90 * time.Second,
	}
	advertised := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = server.SetQUICHeaders(w.Header())
		app.ServeHTTP(w, r)
	})
	return server, conn, advertised, nil
}
