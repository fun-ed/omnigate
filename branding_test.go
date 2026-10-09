package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestOmniGateBranding(t *testing.T) {
	c := testConfig()
	h := testApp(t, c)
	response := request(h, "/", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "<title>OmniGate</title>") || !strings.Contains(response.Body.String(), "<h1>OmniGate</h1>") {
		t.Fatal("default page must use the OmniGate product name")
	}

	c.authUser, c.authPassword = "fixture-user", "fixture-password"
	h = testApp(t, c)
	response = request(h, "/", "")
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") != `Basic realm="OmniGate", charset="UTF-8"` {
		t.Fatal("Basic Auth challenge must use the OmniGate realm")
	}
}
