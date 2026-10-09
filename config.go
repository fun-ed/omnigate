package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"text/scanner"
	"time"
	"unicode"
)

func defaultConfig() config {
	return config{httpAddr: ":8080", httpsAddr: ":443", acmeDirectory: googleACME, certDir: ".certs", healthPath: "/healthz", healthInterval: 10 * time.Second, rps: 10, burst: 20}
}

func parseConfig(args []string) (config, error) {
	c := defaultConfig()
	var configPath string
	f := flag.NewFlagSet("omnigate", flag.ContinueOnError)
	f.StringVar(&configPath, "config", "", "Single-site Caddy-like Webfile; explicit CLI flags override it")
	f.StringVar(&c.httpAddr, "http", c.httpAddr, "HTTP listen address (public port 80 required for ACME HTTP-01)")
	f.StringVar(&c.httpsAddr, "https", c.httpsAddr, "HTTPS TCP listen address; enabled by -domain")
	f.StringVar(&c.http3Addr, "http3", "", "Enable HTTP/3 on this UDP address, e.g. :8443 (requires HTTPS)")
	f.StringVar(&c.domain, "domain", "", "Single DNS hostname for automatic HTTPS (no wildcard)")
	f.StringVar(&c.email, "email", "", "ACME account email")
	f.StringVar(&c.acmeDirectory, "acme-directory", c.acmeDirectory, "ACME directory URL")
	f.StringVar(&c.certDir, "cert-dir", c.certDir, "Private persistent ACME state; one process per directory")
	f.BoolVar(&c.acceptTOS, "accept-tos", false, "Accept the ACME CA terms of service")
	f.BoolVar(&c.googleSetup, "setup-google", false, "Interactively install/init gcloud, select project and configure Google SSL")
	f.StringVar(&c.googleProject, "google-project", "", "Google project to select during setup (otherwise choose interactively)")
	f.StringVar(&c.root, "root", "", "Static file root; /static/ and / when no upstream")
	f.StringVar(&c.upstreams, "upstreams", "", "Comma-separated HTTP(S) or WS(S) upstream URLs; WebSocket Upgrade is proxied")
	f.StringVar(&c.healthPath, "health-path", c.healthPath, "Upstream health path, relative to upstream base path")
	f.DurationVar(&c.healthInterval, "health-interval", c.healthInterval, "Upstream health check interval")
	f.StringVar(&c.authUser, "auth-user", "", "Basic Auth username; password from WEB_HTTP_AUTH_PASSWORD")
	f.Float64Var(&c.rps, "rate", c.rps, "Requests per second per peer IP (0 disables)")
	f.IntVar(&c.burst, "burst", c.burst, "Per-IP rate limit burst")
	f.StringVar(&c.publicURL, "public-url", "", "Canonical external HTTPS origin for redirects and forwarding")
	f.BoolVar(&c.httpsRedirect, "https-redirect", false, "Redirect application HTTP requests to public-url with 301")
	f.StringVar(&c.trustedProxies, "trusted-proxies", "", "Comma-separated trusted proxy CIDRs; empty trusts no forwarded metadata")
	f.StringVar(&c.clientIPHeader, "client-ip-header", "", "Trusted single-IP header: CF-Connecting-IP or X-Real-IP")
	f.BoolVar(&c.privateCache, "private-cache", false, "Override application cache policy with private, no-store")
	f.Int64Var(&c.hstsMaxAge, "hsts-max-age", 0, "HTTPS-only HSTS max-age seconds; 0 disables")
	f.StringVar(&c.frameOptions, "frame-options", "", "Frame protection: SAMEORIGIN, DENY, or off")
	f.StringVar(&c.referrerPolicy, "referrer-policy", "", "Referrer policy: strict-origin-when-cross-origin, no-referrer, or off")
	f.Int64Var(&c.maxBodyBytes, "max-body-bytes", 0, "Maximum authenticated application request body bytes; 0 disables")
	f.BoolVar(&c.accessLog, "access-log", false, "Safe request completion logs and generated request IDs")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 {
		return c, errors.New("unexpected positional arguments")
	}
	c.authPassword = os.Getenv("WEB_HTTP_AUTH_PASSWORD")
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return c, err
		}
		c, err = parseWebfile(strings.NewReader(string(data)))
		if err != nil {
			return c, fmt.Errorf("Webfile: %w", err)
		}
		// Flag pointers still reference c's fields; a second parse applies only flags
		// actually supplied, leaving file values and defaults untouched.
		if err := f.Parse(args); err != nil {
			return c, err
		}
		f.Visit(func(v *flag.Flag) {
			if v.Name == "auth-user" {
				c.authPassword = os.Getenv("WEB_HTTP_AUTH_PASSWORD")
			}
		})
	}
	return c, nil
}

func configTokens(line string) ([]string, error) {
	var s scanner.Scanner
	s.Init(strings.NewReader(line))
	s.Mode = scanner.ScanIdents | scanner.ScanStrings
	s.IsIdentRune = func(ch rune, _ int) bool { return !unicode.IsSpace(ch) && !strings.ContainsRune("{}#\"", ch) }
	var scanErr error
	s.Error = func(*scanner.Scanner, string) { scanErr = errors.New("invalid quoted string") }
	var tokens []string
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		if tok == '#' {
			break
		}
		text := s.TokenText()
		if tok == scanner.String {
			var err error
			text, err = strconv.Unquote(text)
			if err != nil {
				return nil, errors.New("invalid quoted string")
			}
		}
		tokens = append(tokens, text)
	}
	return tokens, scanErr
}

// This is a deliberately small single-site format, not a full Caddyfile parser.
// Directives are one per line; strings may use double quotes, comments start with #.
func parseWebfile(r io.Reader) (config, error) {
	c := defaultConfig()
	lines := bufio.NewScanner(r)
	opened, closed := false, false
	seen := make(map[string]bool)
	lineNumber := 0
	for lines.Scan() {
		lineNumber++
		tokens, err := configTokens(lines.Text())
		fail := func(message string) (config, error) { return c, fmt.Errorf("line %d: %s", lineNumber, message) }
		if err != nil {
			return fail(err.Error())
		}
		if len(tokens) == 0 {
			continue
		}
		if closed {
			return fail("only one site block is supported")
		}
		if !opened {
			if len(tokens) != 2 || tokens[1] != "{" {
				return fail("expected hostname { or :port {")
			}
			site := tokens[0]
			if strings.HasPrefix(site, ":") {
				c.httpAddr = site
			} else {
				c.domain = site
				if strings.Contains(site, ":") {
					host, port, err := net.SplitHostPort(site)
					if err != nil {
						return fail("invalid site address")
					}
					c.domain = host
					c.httpsAddr = ":" + port
				}
			}
			opened = true
			continue
		}
		if len(tokens) == 1 && tokens[0] == "}" {
			closed = true
			continue
		}
		for _, token := range tokens {
			if token == "{" || token == "}" {
				return fail("nested blocks are not supported")
			}
		}
		directive, args := tokens[0], tokens[1:]
		if seen[directive] {
			return fail("duplicate directive")
		}
		seen[directive] = true
		arity := func(n int) bool { return len(args) == n }
		switch directive {
		case "http", "https", "http3", "root", "cert_dir", "google_project", "acme_directory", "public_url", "client_ip_header", "frame_options", "referrer_policy":
			if !arity(1) {
				return fail("directive requires one argument")
			}
			switch directive {
			case "http":
				c.httpAddr = args[0]
			case "https":
				c.httpsAddr = args[0]
			case "http3":
				c.http3Addr = args[0]
			case "root":
				c.root = args[0]
			case "cert_dir":
				c.certDir = args[0]
			case "google_project":
				c.googleProject = args[0]
			case "acme_directory":
				c.acmeDirectory = args[0]
			case "public_url":
				c.publicURL = args[0]
			case "client_ip_header":
				c.clientIPHeader = args[0]
			case "frame_options":
				c.frameOptions = args[0]
			case "referrer_policy":
				c.referrerPolicy = args[0]
			}
		case "tls":
			if !arity(2) || args[0] != "google" {
				return fail("use tls google <email>")
			}
			c.email = args[1]
		case "accept_tos", "google_setup", "https_redirect", "private_cache", "access_log":
			if !arity(1) || (args[0] != "on" && args[0] != "off") {
				return fail("use on or off")
			}
			switch directive {
			case "accept_tos":
				c.acceptTOS = args[0] == "on"
			case "google_setup":
				c.googleSetup = args[0] == "on"
			case "https_redirect":
				c.httpsRedirect = args[0] == "on"
			case "private_cache":
				c.privateCache = args[0] == "on"
			case "access_log":
				c.accessLog = args[0] == "on"
			}
		case "reverse_proxy":
			if len(args) == 0 {
				return fail("reverse_proxy requires at least one upstream")
			}
			c.upstreams = strings.Join(args, ",")
		case "basic_auth":
			if !arity(2) || !strings.HasPrefix(args[1], "env:") || len(args[1]) == 4 {
				return fail("use basic_auth <username> env:<VARIABLE>; plaintext passwords are not allowed")
			}
			c.authUser = args[0]
			c.authPassword = os.Getenv(strings.TrimPrefix(args[1], "env:"))
			if c.authPassword == "" {
				return fail("Basic Auth password environment variable is empty")
			}
		case "rate_limit":
			if !arity(2) {
				return fail("use rate_limit <requests-per-second> <burst>")
			}
			c.rps, err = strconv.ParseFloat(args[0], 64)
			if err != nil {
				return fail("invalid rate")
			}
			c.burst, err = strconv.Atoi(args[1])
			if err != nil {
				return fail("invalid burst")
			}
		case "health_check":
			if !arity(2) {
				return fail("use health_check <path> <interval>")
			}
			c.healthPath = args[0]
			c.healthInterval, err = time.ParseDuration(args[1])
			if err != nil {
				return fail("invalid health interval")
			}
		case "trusted_proxies":
			if len(args) == 0 {
				return fail("trusted_proxies requires at least one CIDR")
			}
			c.trustedProxies = strings.Join(args, ",")
		case "hsts_max_age", "max_body_bytes":
			if !arity(1) {
				return fail("directive requires one integer argument")
			}
			value, parseErr := strconv.ParseInt(args[0], 10, 64)
			if parseErr != nil || value < 0 {
				return fail("directive requires a non-negative integer")
			}
			if directive == "hsts_max_age" {
				c.hstsMaxAge = value
			} else {
				c.maxBodyBytes = value
			}
		default:
			return fail("unknown directive")
		}
	}
	if err := lines.Err(); err != nil {
		return c, err
	}
	if !opened || !closed {
		return c, errors.New("missing site block or closing brace")
	}
	return c, nil
}
