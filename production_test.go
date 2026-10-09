package main

import (
	"os"
	"strings"
	"testing"
)

func TestProductionWebfile(t *testing.T) {
	data, err := os.ReadFile("config/production-example.Webfile")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEB_HTTP_AUTH_PASSWORD", "production-fixture-password")
	c, err := parseWebfile(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if c.domain != "example.com" || c.httpAddr != ":80" || c.httpsAddr != ":443" || c.http3Addr != ":443" {
		t.Fatal("unexpected production listener settings")
	}
	if !c.googleSetup || c.acceptTOS || c.authUser != "admin" || c.certDir != ".certs-example.com" || c.rps != 10 || c.burst != 20 {
		t.Fatal("unexpected production safety defaults")
	}
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "accept-tos") {
		t.Fatal("production template must require explicit CA terms acceptance")
	}
	c.acceptTOS = true
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEB_HTTP_AUTH_PASSWORD", "")
	if _, err := parseWebfile(strings.NewReader(string(data))); err == nil {
		t.Fatal("production template accepted an empty Basic Auth password")
	}
}
