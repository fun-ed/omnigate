package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type acmeState struct {
	Directory    string                 `json:"directory"`
	Domain       string                 `json:"domain"`
	Email        string                 `json:"email"`
	AccountKey   []byte                 `json:"account_key"`
	Registration *registration.Resource `json:"registration"`
	EABKid       string                 `json:"eab_kid,omitempty"`
	EABHMAC      string                 `json:"eab_hmac,omitempty"`
	Resource     *certificate.Resource  `json:"resource,omitempty"`
	CertPEM      []byte                 `json:"cert_pem,omitempty"`
	KeyPEM       []byte                 `json:"key_pem,omitempty"`
}
type acmeUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }

type certManager struct {
	cfg         config
	ctx         context.Context
	state       acmeState
	user        *acmeUser
	cert        atomic.Pointer[tls.Certificate]
	challengeMu sync.RWMutex
	challenges  map[string]string
}

func newCertManager(c config) (*certManager, error) {
	m := &certManager{cfg: c, ctx: context.Background(), challenges: make(map[string]string)}
	data, err := os.ReadFile(filepath.Join(c.certDir, "state.json"))
	if err == nil {
		if err := json.Unmarshal(data, &m.state); err != nil {
			return nil, errors.New("invalid ACME cache")
		}
		if m.state.Directory != c.acmeDirectory || m.state.Domain != c.domain || m.state.Email != c.email {
			return nil, errors.New("ACME cache identity differs; use a separate -cert-dir")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		m.state = acmeState{Directory: c.acmeDirectory, Domain: c.domain, Email: c.email, AccountKey: der}
	}
	key, err := x509.ParsePKCS8PrivateKey(m.state.AccountKey)
	if err != nil {
		return nil, errors.New("invalid ACME account key")
	}
	m.user = &acmeUser{email: c.email, key: key, registration: m.state.Registration}
	if len(m.state.CertPEM) > 0 {
		cert, err := parseCertificate(m.state.CertPEM, m.state.KeyPEM, c.domain)
		if err != nil {
			return nil, err
		}
		m.cert.Store(cert)
	}
	return m, nil
}

func parseCertificate(certPEM, keyPEM []byte, domain string) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("invalid cached certificate or key")
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := cert.Leaf.VerifyHostname(domain); err != nil {
		return nil, err
	}
	return &cert, nil
}

func renewalDue(cert *tls.Certificate, now time.Time) bool {
	if cert == nil {
		return true
	}
	// Renew in the final third of the lifetime (also supports short-lived certificates).
	lifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore)
	return !now.Before(cert.Leaf.NotAfter.Add(-lifetime / 3))
}

func (m *certManager) ensureCertificate() error {
	if !renewalDue(m.cert.Load(), time.Now()) {
		return nil
	}
	cfg := lego.NewConfig(m.user)
	defer cfg.HTTPClient.CloseIdleConnections()
	cfg.CADirURL = m.cfg.acmeDirectory
	cfg.HTTPClient.Timeout = 30 * time.Second
	client, err := lego.NewClient(cfg)
	if err != nil {
		return err
	}
	if err := client.Challenge.SetHTTP01Provider(m); err != nil {
		return err
	}
	if m.user.registration == nil {
		// Persist the account key before lookup so an interrupted registration
		// can be recovered without reusing EAB.
		if err := m.save(m.state); err != nil {
			return err
		}
		reg, err := client.Registration.ResolveAccountByKey()
		if err != nil {
			var problem *acme.ProblemDetails
			if !errors.As(err, &problem) || problem.Type != "urn:ietf:params:acme:error:accountDoesNotExist" {
				return errors.New("ACME account lookup failed; check CA connectivity before registering")
			}
			kid, hmac := os.Getenv("GOOGLE_ACME_EAB_KID"), os.Getenv("GOOGLE_ACME_EAB_HMAC")
			switch {
			case kid != "" || hmac != "":
				if kid == "" || hmac == "" {
					return errors.New("incomplete EAB environment credentials")
				}
				if !validEABCredentials(kid, hmac) {
					return errors.New("invalid EAB environment credentials")
				}
			case m.state.EABKid != "" || m.state.EABHMAC != "":
				kid, hmac = m.state.EABKid, m.state.EABHMAC
				if !validEABCredentials(kid, hmac) {
					return errors.New("invalid saved ACME EAB credentials")
				}
			case m.cfg.googleSetup:
				kid, hmac, err = requestGoogleEAB(m.ctx, m.cfg)
				if err != nil {
					return err
				}
				if !validEABCredentials(kid, hmac) {
					return errors.New("invalid Google EAB credentials")
				}
			default:
				return errors.New("first ACME registration requires GOOGLE_ACME_EAB_KID and GOOGLE_ACME_EAB_HMAC")
			}
			mac, ok := decodeEABMAC(hmac)
			if !ok {
				return errors.New("invalid EAB credentials")
			}
			hmac = base64.RawURLEncoding.EncodeToString(mac)
			withEAB := m.state
			withEAB.EABKid, withEAB.EABHMAC = kid, hmac
			if err := m.save(withEAB); err != nil {
				return err
			}
			m.state = withEAB
			reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{TermsOfServiceAgreed: m.cfg.acceptTOS, Kid: kid, HmacEncoded: hmac})
			if err != nil {
				return errors.New("ACME EAB registration failed; verify the EAB credentials and CA environment")
			}
		}
		m.user.registration, m.state.Registration = reg, reg
		if err := m.save(m.state); err != nil {
			return err
		}
	}
	var resource *certificate.Resource
	if m.state.Resource != nil && len(m.state.CertPEM) > 0 {
		previous := *m.state.Resource
		previous.Certificate, previous.PrivateKey = m.state.CertPEM, m.state.KeyPEM
		resource, err = client.Certificate.RenewWithOptions(previous, &certificate.RenewOptions{Bundle: true})
	} else {
		resource, err = client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{m.cfg.domain}, Bundle: true})
	}
	if err != nil {
		return err
	}
	cert, err := parseCertificate(resource.Certificate, resource.PrivateKey, m.cfg.domain)
	if err != nil {
		return err
	}
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) || !now.Before(cert.Leaf.NotAfter) {
		return errors.New("CA returned a certificate that is not currently valid")
	}
	next := m.state
	next.Resource, next.CertPEM, next.KeyPEM = resource, resource.Certificate, resource.PrivateKey
	if err := m.save(next); err != nil {
		return err
	}
	m.state = next
	m.cert.Store(cert)
	slog.Info("TLS certificate installed", "domain", m.cfg.domain, "expires", cert.Leaf.NotAfter)
	return nil
}

func (m *certManager) save(state acmeState) error {
	if err := os.MkdirAll(m.cfg.certDir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.cfg.certDir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(m.cfg.certDir, "state.json"))
}

func (m *certManager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, m.cfg.domain) {
		return nil, errors.New("unconfigured TLS hostname")
	}
	cert := m.cert.Load()
	if cert == nil || !time.Now().Before(cert.Leaf.NotAfter) {
		return nil, errors.New("no valid TLS certificate")
	}
	return cert, nil
}
func (m *certManager) renewLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.ensureCertificate(); err != nil {
				slog.Error("certificate renewal failed; retry in one hour", "error", err)
			}
		}
	}
}

func challengeKey(domain, token string) string {
	return strings.ToLower(domain) + "\x00" + http01.ChallengePath(token)
}
func (m *certManager) Present(domain, token, keyAuth string) error {
	m.challengeMu.Lock()
	defer m.challengeMu.Unlock()
	m.challenges[challengeKey(domain, token)] = keyAuth
	return nil
}
func (m *certManager) CleanUp(domain, token, _ string) error {
	m.challengeMu.Lock()
	defer m.challengeMu.Unlock()
	delete(m.challenges, challengeKey(domain, token))
	return nil
}
func requestHostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}
func (m *certManager) httpHandler(c config, app http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, http01.PathPrefix) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", 405)
				return
			}
			m.challengeMu.RLock()
			value, ok := m.challenges[requestHostname(r.Host)+"\x00"+r.URL.Path]
			m.challengeMu.RUnlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(value))
			return
		}
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			app.ServeHTTP(w, r)
			return
		}
		if requestHostname(r.Host) != c.domain {
			http.Error(w, "unconfigured hostname", http.StatusMisdirectedRequest)
			return
		}
		host := c.domain
		if _, port, err := net.SplitHostPort(c.httpsAddr); err == nil && port != "443" {
			host = net.JoinHostPort(c.domain, port)
		}
		target := &url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
	})
}
