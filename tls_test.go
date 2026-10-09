package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func makeTestCert(t *testing.T, domain string, before, after time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{domain}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
func TestChallengeAndRedirect(t *testing.T) {
	c := testConfig()
	c.domain = "example.com"
	c.httpsAddr = ":443"
	m := &certManager{cfg: c, challenges: make(map[string]string)}
	if err := m.Present(c.domain, "token", "token.key"); err != nil {
		t.Fatal(err)
	}
	h := m.httpHandler(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	if w := request(h, "/.well-known/acme-challenge/token", ""); w.Code != 200 || w.Body.String() != "token.key" {
		t.Fatal("challenge missing")
	}
	r := httptest.NewRequest(http.MethodGet, "http://evil.example/.well-known/acme-challenge/token", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("challenge exposed for wrong host")
	}
	if err := m.CleanUp(c.domain, "token", ""); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "/.well-known/acme-challenge/token", ""); w.Code != 404 {
		t.Fatal("challenge was not cleaned up")
	}
	if w := request(h, "/path?q=1", ""); w.Code != 308 || w.Header().Get("Location") != "https://example.com/path?q=1" {
		t.Fatalf("redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	r = httptest.NewRequest(http.MethodGet, "http://evil.example/path", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 421 || w.Header().Get("Location") != "" {
		t.Fatal("host injection redirect")
	}
	if w := request(h, "/healthz", ""); w.Code != 200 {
		t.Fatal("HTTP health unavailable")
	}
}
func TestCertificateCacheAndRenewalWindow(t *testing.T) {
	c := testConfig()
	c.domain = "example.com"
	c.email = "test@example.com"
	c.certDir = t.TempDir()
	m, err := newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certPEM, keyPEM := makeTestCert(t, c.domain, now.Add(-time.Hour), now.Add(48*time.Hour))
	cert, err := parseCertificate(certPEM, keyPEM, c.domain)
	if err != nil {
		t.Fatal(err)
	}
	if renewalDue(cert, now) {
		t.Fatal("fresh certificate renewed too soon")
	}
	if !renewalDue(cert, now.Add(40*time.Hour)) {
		t.Fatal("short-lived certificate not renewed")
	}
	if !renewalDue(nil, now) {
		t.Fatal("missing certificate not due")
	}
	m.state.CertPEM, m.state.KeyPEM = certPEM, keyPEM
	if err := m.save(m.state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(c.certDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("private cache permissions")
	}
	restored, err := newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.ensureCertificate(); err != nil {
		t.Fatal("valid cache must not require a network call", err)
	}
	if _, err := restored.getCertificate(&tls.ClientHelloInfo{ServerName: c.domain}); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.getCertificate(&tls.ClientHelloInfo{ServerName: "evil.example"}); err == nil {
		t.Fatal("accepted wrong TLS SNI")
	}
	c.domain = "another.example"
	if _, err := newCertManager(c); err == nil {
		t.Fatal("cache identity mismatch accepted")
	}
	if _, err := parseCertificate(certPEM, keyPEM, "another.example"); err == nil {
		t.Fatal("certificate hostname mismatch accepted")
	}
}

// A local ACME fixture exercises the real lego client, EAB registration,
// HTTP-01 presentation, CSR signing, renewal and cache restart without a public CA.
func TestACMEIssueRenewRestartAndTLS(t *testing.T) {
	var mu sync.Mutex
	var base string
	var manager *certManager
	var registered, authorized bool
	var issued int64
	var certBundle []byte
	var sawEAB bool
	var accountLookups, registrationAttempts int
	var statePath string
	var stateDir string
	var failEABSave, stateSaveBlocked bool
	var stateBackup []byte
	const eabKid = "test-kid"
	const failedRegistrationDetail = "fixture-registration-failure-detail"
	eabHMAC := base64.RawURLEncoding.EncodeToString([]byte("test-hmac-key-for-local-fixture-32-bytes"))
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Local Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	order := func(status string) map[string]any {
		return map[string]any{"status": status, "identifiers": []map[string]string{{"type": "dns", "value": "example.com"}}, "authorizations": []string{base + "/auth"}, "finalize": base + "/finalize", "certificate": base + "/cert"}
	}
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		nonce := make([]byte, 24)
		_, _ = rand.Read(nonce)
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString(nonce))
		w.Header().Set("Content-Type", "application/json")
		var payload map[string]json.RawMessage
		if r.Method == http.MethodPost {
			var jws struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
				t.Errorf("bad JWS: %v", err)
				w.WriteHeader(400)
				return
			}
			body, err := base64.RawURLEncoding.DecodeString(jws.Payload)
			if err != nil {
				t.Errorf("bad payload: %v", err)
				w.WriteHeader(400)
				return
			}
			if len(body) > 0 {
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Errorf("payload JSON: %v", err)
					w.WriteHeader(400)
					return
				}
			}
		}
		respond := func(v any) {
			if err := json.NewEncoder(w).Encode(v); err != nil {
				t.Error(err)
			}
		}
		switch r.URL.Path {
		case "/directory":
			respond(map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order", "revokeCert": base + "/revoke", "keyChange": base + "/key-change", "meta": map[string]any{"externalAccountRequired": true}})
		case "/nonce":
			w.WriteHeader(200)
		case "/account":
			accountLookups++
			var existing bool
			_ = json.Unmarshal(payload["onlyReturnExisting"], &existing)
			if existing && failEABSave {
				failEABSave = false
				var err error
				stateBackup, err = os.ReadFile(statePath)
				if err != nil {
					t.Errorf("could not preserve state fixture before save-failure simulation: %v", err)
				} else if err := os.Remove(statePath); err != nil {
					t.Errorf("could not prepare state save-failure simulation: %v", err)
				} else if err := os.Remove(stateDir); err != nil {
					t.Errorf("could not prepare state directory save-failure simulation: %v", err)
				} else if err := os.WriteFile(stateDir, []byte("blocked"), 0600); err != nil {
					t.Errorf("could not block state directory for save-failure simulation: %v", err)
				} else {
					stateSaveBlocked = true
				}
			}
			if existing && !registered {
				w.WriteHeader(400)
				respond(map[string]any{"type": "urn:ietf:params:acme:error:accountDoesNotExist", "detail": "no account", "status": 400})
				return
			}
			if !existing {
				binding := payload["externalAccountBinding"]
				if len(binding) == 0 {
					t.Error("missing EAB")
					w.WriteHeader(400)
					return
				}
				var eab struct {
					Protected string `json:"protected"`
				}
				_ = json.Unmarshal(binding, &eab)
				data, _ := base64.RawURLEncoding.DecodeString(eab.Protected)
				var protected struct {
					Kid string `json:"kid"`
				}
				_ = json.Unmarshal(data, &protected)
				if protected.Kid != eabKid {
					t.Error("wrong EAB key ID")
				}
				sawEAB = true
				registrationAttempts++
				if registrationAttempts == 1 {
					data, err := os.ReadFile(statePath)
					if err != nil {
						t.Errorf("EAB state was not persisted before registration: %v", err)
					} else {
						var saved acmeState
						if json.Unmarshal(data, &saved) != nil ||
							len(saved.AccountKey) == 0 || saved.EABKid != eabKid || saved.EABHMAC != eabHMAC {
							t.Error("registration began before account key and complete EAB were persisted")
						}
					}
					w.WriteHeader(400)
					respond(map[string]any{"type": "urn:ietf:params:acme:error:serverInternal", "detail": failedRegistrationDetail, "status": 400})
					return
				}
				registered = true
			}
			w.Header().Set("Location", base+"/account/1")
			w.WriteHeader(201)
			respond(map[string]any{"status": "valid", "contact": []string{"mailto:test@example.com"}, "orders": base + "/orders"})
		case "/order":
			authorized = false
			w.Header().Set("Location", base+"/order/1")
			w.WriteHeader(201)
			respond(order("pending"))
		case "/order/1":
			status := "ready"
			if len(certBundle) > 0 {
				status = "valid"
			}
			respond(order(status))
		case "/auth":
			status := "pending"
			if authorized {
				status = "valid"
			}
			respond(map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": "example.com"}, "challenges": []map[string]string{{"type": "http-01", "url": base + "/challenge", "token": "test-token", "status": status}}})
		case "/challenge":
			challenge := request(manager.httpHandler(manager.cfg, http.NotFoundHandler()), "/.well-known/acme-challenge/test-token", "")
			if challenge.Code != 200 || !strings.HasPrefix(challenge.Body.String(), "test-token.") {
				t.Error("HTTP-01 not available to CA")
				w.WriteHeader(400)
				return
			}
			authorized = true
			respond(map[string]string{"type": "http-01", "url": base + "/challenge", "token": "test-token", "status": "valid"})
		case "/finalize":
			var csrEncoded string
			_ = json.Unmarshal(payload["csr"], &csrEncoded)
			der, err := base64.RawURLEncoding.DecodeString(csrEncoded)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if err := csr.CheckSignature(); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			issued++
			leaf := &x509.Certificate{SerialNumber: big.NewInt(issued), DNSNames: csr.DNSNames, Subject: csr.Subject, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			certDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, csr.PublicKey, caKey)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			certBundle = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), caPEM...)
			respond(order("valid"))
		case "/cert":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(certBundle)
		default:
			t.Errorf("unexpected ACME request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer fixture.Close()
	base = fixture.URL
	trustFile := filepath.Join(t.TempDir(), "acme-ca.pem")
	if err := os.WriteFile(trustFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", trustFile)
	t.Setenv("GOOGLE_ACME_EAB_KID", "")
	t.Setenv("GOOGLE_ACME_EAB_HMAC", "")
	c := testConfig()
	c.domain = "example.com"
	c.email = "test@example.com"
	c.acceptTOS = true
	c.certDir = t.TempDir()
	c.acmeDirectory = base + "/directory"
	statePath = filepath.Join(c.certDir, "state.json")
	stateDir = c.certDir
	manager, err = newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}

	blockedDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedDir, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	manager.cfg.certDir = blockedDir
	if err := manager.ensureCertificate(); err == nil {
		t.Fatal("ACME setup succeeded after the account-key state save failed")
	}
	manager.cfg.certDir = c.certDir
	if accountLookups != 0 || registrationAttempts != 0 {
		t.Fatal("ACME account lookup or registration ran before account-key persistence")
	}

	if err := manager.ensureCertificate(); err == nil ||
		!strings.Contains(err.Error(), "first ACME registration requires") {
		t.Fatal("first registration without EAB did not fail with the missing-credentials error")
	}
	const partialEAB = "partial-eab-secret"
	t.Setenv("GOOGLE_ACME_EAB_KID", partialEAB)
	if err := manager.ensureCertificate(); err == nil ||
		!strings.Contains(err.Error(), "incomplete EAB environment credentials") ||
		strings.Contains(err.Error(), partialEAB) {
		t.Fatal("partial environment EAB was not rejected without exposing its value")
	}
	const malformedHMAC = "malformed-hmac-secret"
	t.Setenv("GOOGLE_ACME_EAB_KID", eabKid)
	t.Setenv("GOOGLE_ACME_EAB_HMAC", malformedHMAC)
	if err := manager.ensureCertificate(); err == nil ||
		!strings.Contains(err.Error(), "invalid EAB environment credentials") ||
		strings.Contains(err.Error(), malformedHMAC) {
		t.Fatal("malformed environment EAB was not rejected without exposing its value")
	}
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var malformedState acmeState
	if err := json.Unmarshal(stateData, &malformedState); err != nil {
		t.Fatal(err)
	}
	if malformedState.EABKid != "" || malformedState.EABHMAC != "" {
		t.Fatal("malformed EAB credentials were saved")
	}
	t.Setenv("GOOGLE_ACME_EAB_KID", eabKid)
	t.Setenv("GOOGLE_ACME_EAB_HMAC", eabHMAC)
	mu.Lock()
	failEABSave = true
	mu.Unlock()
	err = manager.ensureCertificate()
	if err == nil {
		t.Fatal("ACME registration proceeded after EAB state persistence failed")
	}
	mu.Lock()
	backup := append([]byte(nil), stateBackup...)
	blocked := stateSaveBlocked
	mu.Unlock()
	if !blocked || len(backup) == 0 || registrationAttempts != 0 {
		t.Fatal("registration ran without a successful EAB state save")
	}
	if err := os.Remove(stateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, backup, 0600); err != nil {
		t.Fatal(err)
	}
	var stateBeforeEAB acmeState
	if err := json.Unmarshal(backup, &stateBeforeEAB); err != nil {
		t.Fatal(err)
	}
	if stateBeforeEAB.EABKid != "" || stateBeforeEAB.EABHMAC != "" {
		t.Fatal("failed EAB state save left partial credentials in state")
	}
	err = manager.ensureCertificate()
	if err == nil || !strings.Contains(err.Error(), "ACME EAB registration failed") ||
		strings.Contains(err.Error(), eabKid) || strings.Contains(err.Error(), eabHMAC) ||
		strings.Contains(err.Error(), failedRegistrationDetail) {
		t.Fatal("failed ACME registration did not return a sanitized error")
	}
	if registrationAttempts != 1 {
		t.Fatal("expected one failed EAB registration attempt")
	}
	stateData, err = os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted acmeState
	if err := json.Unmarshal(stateData, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.AccountKey) == 0 || persisted.EABKid != eabKid || persisted.EABHMAC != eabHMAC {
		t.Fatal("complete account key and EAB pair were not saved for retry")
	}
	stateInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if stateInfo.Mode().Perm() != 0600 {
		t.Fatalf("ACME state permissions = %04o, want 0600", stateInfo.Mode().Perm())
	}

	c.googleSetup = true
	c.googleProject = "fake-project"
	c.gcloudPath = "fake-gcloud"
	manager.cfg = c
	googleEABRequests := 0
	replaceGoogleDeps(t, func(_ context.Context, _ string, args []string, _ []string, _ io.Reader, _, _ io.Writer) error {
		if strings.HasPrefix(strings.Join(args, " "), "publicca external-account-keys create ") {
			googleEABRequests++
		}
		return io.ErrUnexpectedEOF
	})
	t.Setenv("GOOGLE_ACME_EAB_KID", partialEAB)
	t.Setenv("GOOGLE_ACME_EAB_HMAC", "")
	if err := manager.ensureCertificate(); err == nil ||
		!strings.Contains(err.Error(), "incomplete EAB environment credentials") ||
		strings.Contains(err.Error(), partialEAB) {
		t.Fatal("partial environment EAB did not take precedence over saved credentials")
	}
	if registrationAttempts != 1 || googleEABRequests != 0 {
		t.Fatal("partial environment EAB fell back to another credential source")
	}

	t.Setenv("GOOGLE_ACME_EAB_KID", "")
	manager, err = newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ensureCertificate(); err != nil {
		t.Fatal("registration retry from saved EAB failed")
	}
	if !sawEAB || issued != 1 || registrationAttempts != 2 || googleEABRequests != 0 {
		t.Fatal("saved EAB was not reused for registration retry and certificate issuance")
	}
	if manager.state.EABKid != eabKid || manager.state.EABHMAC != eabHMAC {
		t.Fatal("certificate issuance did not preserve the EAB pair")
	}
	if w := request(manager.httpHandler(c, http.NotFoundHandler()), "/.well-known/acme-challenge/test-token", ""); w.Code != 404 {
		t.Fatal("challenge not cleaned after issue")
	}
	// Force a renewal window while retaining the issued cert/key as the renewal resource.
	old := *manager.cert.Load()
	leaf := *old.Leaf
	leaf.NotBefore = time.Now().Add(-90 * 24 * time.Hour)
	leaf.NotAfter = time.Now().Add(time.Hour)
	old.Leaf = &leaf
	manager.cert.Store(&old)
	if err := manager.ensureCertificate(); err != nil {
		t.Fatal("renew:", err)
	}
	if issued != 2 {
		t.Fatal("renewal did not issue another certificate")
	}
	if manager.state.EABKid != eabKid || manager.state.EABHMAC != eabHMAC {
		t.Fatal("renewal did not preserve the EAB pair")
	}
	t.Setenv("GOOGLE_ACME_EAB_KID", "")
	t.Setenv("GOOGLE_ACME_EAB_HMAC", "")
	restored, err := newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.ensureCertificate(); err != nil {
		t.Fatal("restart should not need EAB", err)
	}
	if restored.state.EABKid != eabKid || restored.state.EABHMAC != eabHMAC {
		t.Fatal("registered restart lost the saved EAB pair")
	}
	// Renew a registered account after restart without EAB or a usable gcloud.
	manager = restored
	restored.cfg.googleSetup = true
	restored.cfg.gcloudPath = "/nonexistent/gcloud"
	old = *restored.cert.Load()
	leaf = *old.Leaf
	leaf.NotBefore = time.Now().Add(-90 * 24 * time.Hour)
	leaf.NotAfter = time.Now().Add(time.Hour)
	old.Leaf = &leaf
	restored.cert.Store(&old)
	if err := restored.ensureCertificate(); err != nil {
		t.Fatal("registered account renewal should not need EAB or gcloud", err)
	}
	if issued != 3 {
		t.Fatal("registered account did not renew after restart")
	}
	// Validate the certificate in a real TLS handshake using the local CA, not InsecureSkipVerify.
	https := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "secure") }))
	https.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: restored.getCertificate}
	https.StartTLS()
	defer https.Close()
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.domain, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	res, err := client.Get(https.URL)
	if err != nil {
		t.Fatal("TLS:", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || string(body) != "secure" {
		t.Fatal("HTTPS failed")
	}
	// Recover a registered account after a crash before the registration resource was saved.
	restored.state.Registration = nil
	restored.user.registration = nil
	restored.state.Resource = nil
	restored.state.CertPEM = nil
	restored.state.KeyPEM = nil
	restored.cert.Store(nil)
	if err := restored.save(restored.state); err != nil {
		t.Fatal(err)
	}
	manager, err = newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ensureCertificate(); err != nil {
		t.Fatal("account recovery without EAB:", err)
	}
	if issued != 4 {
		t.Fatal("account recovery did not obtain a certificate")
	}
	if registrationAttempts != 2 || googleEABRequests != 0 {
		t.Fatal("registered-account recovery made an unnecessary EAB request")
	}
}
