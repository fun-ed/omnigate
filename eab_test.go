package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestEnsureCertificateNormalizesEABBeforeRegistration(t *testing.T) {
	const savedKid = "saved-kid-A"
	const environmentKid = "environment-kid-B"
	const registrationDetail = "fixture-private-registration-detail"
	savedMAC := bytes.Repeat([]byte{0x11}, 32)
	savedHMAC := base64.RawURLEncoding.EncodeToString(savedMAC)
	environmentMAC := bytes.Repeat([]byte{0xff}, 32)
	environmentHMAC := base64.StdEncoding.EncodeToString(environmentMAC)
	if !strings.ContainsAny(environmentHMAC, "+/") {
		t.Fatal("fixture HMAC does not exercise standard-base64 characters")
	}
	canonicalHMAC := base64.RawURLEncoding.EncodeToString(environmentMAC)

	c := testConfig()
	c.domain = "example.com"
	c.email = "test@example.com"
	c.acceptTOS = true
	c.certDir = t.TempDir()
	statePath := filepath.Join(c.certDir, "state.json")
	var mu sync.Mutex
	var fixtureErr string
	var accountLookups, registrationAttempts int
	var sawEAB bool
	recordFixtureError := func(message string) {
		mu.Lock()
		defer mu.Unlock()
		if fixtureErr == "" {
			fixtureErr = message
		}
	}
	var base string
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := make([]byte, 24)
		if _, err := rand.Read(nonce); err != nil {
			recordFixtureError("could not generate replay nonce: " + err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString(nonce))
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"newNonce": base + "/nonce", "newAccount": base + "/account",
				"newOrder": base + "/order", "revokeCert": base + "/revoke",
				"keyChange": base + "/key-change",
				"meta":      map[string]any{"externalAccountRequired": true},
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			var envelope struct {
				Payload string `json:"payload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				recordFixtureError("could not decode account JWS: " + err.Error())
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			payloadBytes, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
			if err != nil {
				recordFixtureError("could not decode account payload: " + err.Error())
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var payload struct {
				OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
				ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
			}
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				recordFixtureError("could not decode account payload JSON: " + err.Error())
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if payload.OnlyReturnExisting {
				mu.Lock()
				accountLookups++
				mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"type":   "urn:ietf:params:acme:error:accountDoesNotExist",
					"detail": "account does not exist", "status": http.StatusBadRequest,
				})
				return
			}

			mu.Lock()
			registrationAttempts++
			mu.Unlock()
			if len(payload.ExternalAccountBinding) == 0 {
				recordFixtureError("registration request did not contain EAB")
			} else {
				var binding struct {
					Protected string `json:"protected"`
					Payload   string `json:"payload"`
					Signature string `json:"signature"`
				}
				if err := json.Unmarshal(payload.ExternalAccountBinding, &binding); err != nil {
					recordFixtureError("could not decode EAB JWS: " + err.Error())
				} else {
					protectedBytes, err := base64.RawURLEncoding.DecodeString(binding.Protected)
					if err != nil {
						recordFixtureError("could not decode EAB protected header: " + err.Error())
					} else {
						var protected struct {
							Algorithm string `json:"alg"`
							Kid       string `json:"kid"`
						}
						if err := json.Unmarshal(protectedBytes, &protected); err != nil {
							recordFixtureError("could not decode EAB protected header JSON: " + err.Error())
						} else if protected.Algorithm != "HS256" || protected.Kid != environmentKid {
							recordFixtureError("registration used the wrong EAB key ID or algorithm")
						} else {
							mac := hmac.New(sha256.New, environmentMAC)
							_, _ = mac.Write([]byte(binding.Protected + "." + binding.Payload))
							signature, err := base64.RawURLEncoding.DecodeString(binding.Signature)
							if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
								recordFixtureError("registration EAB signature did not use the selected HMAC")
							} else {
								mu.Lock()
								sawEAB = true
								mu.Unlock()
							}
						}
					}
				}
			}
			stateData, err := os.ReadFile(statePath)
			if err != nil {
				recordFixtureError("EAB was not saved before registration: " + err.Error())
			} else {
				var saved acmeState
				if err := json.Unmarshal(stateData, &saved); err != nil ||
					len(saved.AccountKey) == 0 || saved.EABKid != environmentKid || saved.EABHMAC != canonicalHMAC {
					recordFixtureError("registration began before canonical environment EAB was persisted")
				}
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":   "urn:ietf:params:acme:error:serverInternal",
				"detail": registrationDetail + " " + savedKid + " " + savedHMAC + " " + environmentKid + " " + environmentHMAC,
				"status": http.StatusBadRequest,
			})
		default:
			recordFixtureError("unexpected ACME request: " + r.Method + " " + r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer fixture.Close()
	base = fixture.URL
	c.acmeDirectory = base + "/directory"
	caPath := filepath.Join(t.TempDir(), "acme-ca.pem")
	if err := os.WriteFile(caPath, pemEncodeCertificate(fixture.Certificate().Raw), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caPath)
	t.Setenv("GOOGLE_ACME_EAB_KID", environmentKid)
	t.Setenv("GOOGLE_ACME_EAB_HMAC", environmentHMAC)

	manager, err := newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	manager.state.EABKid, manager.state.EABHMAC = savedKid, savedHMAC
	if err := manager.save(manager.state); err != nil {
		t.Fatal(err)
	}
	manager, err = newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	err = manager.ensureCertificate()
	if err == nil || !strings.Contains(err.Error(), "ACME EAB registration failed") ||
		strings.Contains(err.Error(), registrationDetail) || strings.Contains(err.Error(), savedKid) ||
		strings.Contains(err.Error(), savedHMAC) || strings.Contains(err.Error(), environmentKid) ||
		strings.Contains(err.Error(), environmentHMAC) {
		t.Fatalf("registration error was not sanitized: %v", err)
	}
	mu.Lock()
	gotLookups, gotRegistrations, gotEAB, gotFixtureErr := accountLookups, registrationAttempts, sawEAB, fixtureErr
	mu.Unlock()
	if gotFixtureErr != "" {
		t.Fatal(gotFixtureErr)
	}
	if gotLookups != 1 || gotRegistrations != 1 || !gotEAB {
		t.Fatalf("ACME fixture observed lookups=%d registrations=%d EAB=%t", gotLookups, gotRegistrations, gotEAB)
	}
	if manager.state.EABKid != environmentKid || manager.state.EABHMAC != canonicalHMAC {
		t.Fatal("environment EAB did not override the saved pair with canonical HMAC")
	}

	t.Setenv("GOOGLE_ACME_EAB_KID", "")
	t.Setenv("GOOGLE_ACME_EAB_HMAC", "")
	manager.state.EABKid, manager.state.EABHMAC = "malformed-saved-kid", "malformed-saved-hmac"
	if err := manager.save(manager.state); err != nil {
		t.Fatal(err)
	}
	manager, err = newCertManager(c)
	if err != nil {
		t.Fatal(err)
	}
	err = manager.ensureCertificate()
	if err == nil || !strings.Contains(err.Error(), "invalid saved ACME EAB credentials") ||
		strings.Contains(err.Error(), "malformed-saved-kid") || strings.Contains(err.Error(), "malformed-saved-hmac") {
		t.Fatalf("malformed saved EAB was not rejected safely: %v", err)
	}
	mu.Lock()
	gotLookups, gotRegistrations, gotFixtureErr = accountLookups, registrationAttempts, fixtureErr
	mu.Unlock()
	if gotFixtureErr != "" {
		t.Fatal(gotFixtureErr)
	}
	if gotLookups != 2 || gotRegistrations != 1 {
		t.Fatalf("malformed saved EAB reached registration: lookups=%d registrations=%d", gotLookups, gotRegistrations)
	}
}

func pemEncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
