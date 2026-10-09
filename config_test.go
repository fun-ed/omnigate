package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebfile(t *testing.T) {
	t.Setenv("TEST_WEB_PASSWORD", "local-test-password")
	data := `# configuration
example.com:8443 {
 http :8081
 http3 :8444
 tls google admin@example.com
 accept_tos on
 google_setup on
 google_project sample-project
 cert_dir ".private certs"
 root "./public files" # comments
 basic_auth admin env:TEST_WEB_PASSWORD
 reverse_proxy http://127.0.0.1:9001 https://127.0.0.1:9002/base
 rate_limit 25 50
 health_check /status?ready=1 3s
}`
	c, err := parseWebfile(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if c.domain != "example.com" || c.httpsAddr != ":8443" || c.httpAddr != ":8081" || c.http3Addr != ":8444" {
		t.Fatalf("bad listener configuration: %+v", config{domain: c.domain, httpAddr: c.httpAddr, httpsAddr: c.httpsAddr, http3Addr: c.http3Addr})
	}
	if c.email != "admin@example.com" || !c.acceptTOS || !c.googleSetup || c.googleProject != "sample-project" {
		t.Fatal("bad Google TLS settings")
	}
	if c.certDir != ".private certs" || c.root != "./public files" || c.authPassword != "local-test-password" || c.authUser != "admin" {
		t.Fatal("bad paths or environment password")
	}
	if c.upstreams != "http://127.0.0.1:9001,https://127.0.0.1:9002/base" || c.rps != 25 || c.burst != 50 || c.healthInterval != 3*time.Second || c.healthPath != "/status?ready=1" {
		t.Fatal("bad application directives")
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
}
func TestWebfileErrors(t *testing.T) {
	for _, input := range []string{
		"", "example.com", "example.com {\nhttp :80", "example.com {\nunknown value\n}",
		"example.com {\nhttp :80\nhttp :81\n}", "example.com {\nrate_limit ten 20\n}",
		"example.com {\nhealth_check /healthz bad\n}", "example.com {\nbasic_auth admin plaintext-secret\n}",
		"example.com {\nbasic_auth admin env:UNSET_TEST_PASSWORD\n}", "example.com {\naccept_tos yes\n}",
		"example.com {\ntls other admin@example.com\n}", "example.com {\nroot {\n}\n}",
		"example.com {\n}\nanother.example {\n}", "example.com {\nroot \"unterminated\n}",
	} {
		t.Run(strings.ReplaceAll(input, "\n", "_"), func(t *testing.T) {
			_, err := parseWebfile(strings.NewReader(input))
			if err == nil {
				t.Fatal("accepted invalid Webfile")
			}
			if strings.Contains(err.Error(), "plaintext-secret") {
				t.Fatal("password disclosed in parser error")
			}
		})
	}
}
func TestConfigCLIOverridesFile(t *testing.T) {
	t.Setenv("WEB_HTTP_AUTH_PASSWORD", "")
	file := filepath.Join(t.TempDir(), "Webfile")
	if err := os.WriteFile(file, []byte(`:8082 {
 rate_limit 5 10
 root "public files"
 google_setup on
}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig([]string{"-config", file, "-http", ":8090", "-rate", "0", "-setup-google=false"})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpAddr != ":8090" || c.rps != 0 || c.burst != 10 || c.root != "public files" || c.googleSetup {
		t.Fatal("CLI override precedence broken")
	}
	if c.domain != "" || c.httpsAddr != ":443" {
		t.Fatal("plain HTTP site defaults broken")
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c, err = parseConfig([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpAddr != ":8080" || c.rps != 10 || c.burst != 20 || c.http3Addr != "" {
		t.Fatal("legacy defaults changed")
	}
	if _, err := parseConfig([]string{"unexpected"}); err == nil {
		t.Fatal("positional argument ignored")
	}
	if _, err := parseConfig([]string{"-config", "/nonexistent/Webfile"}); err == nil {
		t.Fatal("missing file ignored")
	}
}
func TestHTTP3ConfigValidation(t *testing.T) {
	for _, addr := range []string{":443", "127.0.0.1:8443", "[::1]:9443", ":0"} {
		c := testConfig()
		c.domain = "example.com"
		c.email = "admin@example.com"
		c.acceptTOS = true
		c.http3Addr = addr
		if err := c.validate(); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"443", ":65536", ":-1", ":bad"} {
		c := testConfig()
		c.domain = "example.com"
		c.email = "admin@example.com"
		c.acceptTOS = true
		c.http3Addr = addr
		if c.validate() == nil {
			t.Fatalf("accepted invalid UDP address %s", addr)
		}
	}
	c := testConfig()
	c.http3Addr = ":8443"
	if c.validate() == nil {
		t.Fatal("HTTP3 requires TLS")
	}
}
func TestExampleWebfile(t *testing.T) {
	for _, path := range []string{
		"Webfile.example",
		"Webfile.websocket.example",
		"config/http-example.Webfile",
		"config/google-https-example.Webfile",
		"config/proxy-example.Webfile",
		"config/websocket-example.Webfile",
	} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			c, err := parseWebfile(strings.NewReader(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := c.validate(); err != nil {
				t.Fatal(err)
			}
			pool, err := newPool(c.upstreams, c.healthPath)
			if err != nil {
				t.Fatal(err)
			}
			pool.close()
		})
	}
}
