// SPDX-FileCopyrightText: Ella Networks Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	testerURL  string
	ellaAPIURL string
	// ellaAdminToken authenticates the admin-API calls that provision resources
	// mid-run, such as the subscribers claimSubscriber draws on demand.
	ellaAdminToken string
)

func TestMain(m *testing.M) {
	testerURL = envOrDefault("TESTER_URL", "http://localhost:8080")
	ellaAPIURL = envOrDefault("ELLA_API_URL", "http://10.3.0.2:5002")

	if err := waitForEllaCore(30 * time.Second); err != nil {
		log.Fatalf("Ella Core not ready: %v", err)
	}

	token, err := provisionEllaCore()
	if err != nil {
		log.Fatalf("Ella Core provisioning failed: %v", err)
	}

	ellaAdminToken = token

	// The reserved subscriber pool (imsi-00101 + 10-digit MSIN), for tests that
	// name a subscriber index explicitly via testSUPI. Tests that need only "a
	// subscriber nobody else holds" call claimSubscriber, which allocates above
	// this block and provisions on demand.
	for i := 1; i <= numTestSubscribers; i++ {
		imsi := testSUPI(i)[len("imsi-"):]
		if err := createSubscriber(token, imsi); err != nil {
			log.Fatalf("subscriber %s creation failed: %v", imsi, err)
		}
	}

	// Extra data networks on the default profile/slice so the same subscribers
	// can drive PDU-session-type negotiation (IPv6-only and dual-stack alongside
	// the IPv4-only "internet", TS 24.501 §6.4.1.3) and IP-pool exhaustion (a
	// tiny /30 pool, §6.4.1.x #26).
	if err := provisionExtraDataNetworks(token); err != nil {
		log.Fatalf("data-network provisioning failed: %v", err)
	}

	// Home network key pairs so subscribers can register with a SUCI concealed
	// under ECIES Profile A (X25519) or Profile B (P-256) — TS 33.501 §6.12.2,
	// Annex C. The core must de-conceal these to recover the SUPI.
	if err := provisionHomeNetworkKeys(token); err != nil {
		log.Fatalf("home network key provisioning failed: %v", err)
	}

	// An alternate slice/profile and a dedicated subscriber for the
	// subscription-change reconciliation tests (e.g. moving a UE off the slice
	// its PDU session runs on — TS 23.501 §5.15.5.2.2).
	if err := provisionAlternateSlice(token); err != nil {
		log.Fatalf("alternate slice provisioning failed: %v", err)
	}

	if err := createSubscriber(token, subscriptionChangeIMSI); err != nil {
		log.Fatalf("subscription-change subscriber creation failed: %v", err)
	}

	if err := waitForTester(30 * time.Second); err != nil {
		log.Fatalf("3gpp-server not ready: %v", err)
	}

	os.Exit(m.Run())
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func waitForEllaCore(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(ellaAPIURL + "/api/v1/status")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("timeout after %v", timeout)
}

func waitForTester(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Post(testerURL+"/gnb", "application/json", strings.NewReader(`{}`))
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %v", timeout)
}

func provisionEllaCore() (string, error) {
	creds := `{"email":"admin@test.com","password":"admin1234"}`

	token, err := postForToken(ellaAPIURL+"/api/v1/init", creds)
	if err == nil {
		return token, nil
	}

	token, err = postForToken(ellaAPIURL+"/api/v1/auth/login", creds)
	if err != nil {
		return "", fmt.Errorf("both init and login failed: %v", err)
	}
	return token, nil
}

func postForToken(url, body string) (string, error) {
	resp, err := doHTTP("POST", url, body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)

	var tokenResp struct {
		Result struct {
			Token string `json:"token"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &tokenResp); err != nil {
		return "", fmt.Errorf("decode: %v (body: %s)", err, b)
	}
	if tokenResp.Result.Token == "" {
		return "", fmt.Errorf("no token: %s", b)
	}
	return tokenResp.Result.Token, nil
}

func createSubscriber(token, imsi string) error {
	body := fmt.Sprintf(`{
		"imsi": "%s",
		"key": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"sequenceNumber": "000000000020",
		"profile_name": "default"
	}`, imsi)
	req, _ := http.NewRequest("POST", ellaAPIURL+"/api/v1/subscribers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("create subscriber: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(b), "already") || resp.StatusCode == 409 {
			return nil
		}
		return fmt.Errorf("create subscriber: HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// provisionExtraDataNetworks creates the data networks (and their default-profile
// policies) used by the PDU-session-type and IP-exhaustion tests, alongside the
// IPv4-only "internet" seeded by init:
//   - internet6:  IPv6-only
//   - internet46: dual-stack
//   - exhaust:    IPv4 /30 (exactly 2 allocatable addresses)
//
// Idempotent: each resource is created only when not already present (the env
// persists across runs).
func provisionExtraDataNetworks(token string) error {
	dataNetworks := []struct{ name, body string }{
		{"internet6", `{"name":"internet6","ipv6_pool":"2001:db8:6::/48","dns":"2001:4860:4860::8888","mtu":1400}`},
		{"internet46", `{"name":"internet46","ipv4_pool":"10.46.0.0/22","ipv6_pool":"2001:db8:46::/48","dns":"8.8.8.8","mtu":1400}`},
		{"exhaust", `{"name":"exhaust","ipv4_pool":"10.99.0.0/30","dns":"8.8.8.8","mtu":1400}`},
	}
	for _, dn := range dataNetworks {
		if err := ensureProvisioned(token, "/api/v1/networking/data-networks", dn.name, dn.body); err != nil {
			return err
		}
	}

	policies := []struct{ name, body string }{
		{"internet6-policy", `{"name":"internet6-policy","profile_name":"default","slice_name":"default","data_network_name":"internet6","session_ambr_uplink":"200 Mbps","session_ambr_downlink":"200 Mbps","var5qi":9,"arp":1}`},
		{"internet46-policy", `{"name":"internet46-policy","profile_name":"default","slice_name":"default","data_network_name":"internet46","session_ambr_uplink":"200 Mbps","session_ambr_downlink":"200 Mbps","var5qi":9,"arp":1}`},
		{"exhaust-policy", `{"name":"exhaust-policy","profile_name":"default","slice_name":"default","data_network_name":"exhaust","session_ambr_uplink":"200 Mbps","session_ambr_downlink":"200 Mbps","var5qi":9,"arp":1}`},
	}
	for _, p := range policies {
		if err := ensureProvisioned(token, "/api/v1/policies", p.name, p.body); err != nil {
			return err
		}
	}

	return nil
}

// Home network key pairs used by the SUCI Profile A/B registration tests. The
// private keys are provisioned in the core; the matching public keys are derived
// from them in the tests and handed to the emulated UE. The key identifiers are
// dedicated (10/11) so they do not collide with the absent-key id used by
// TestRegistrationReject_InvalidHomeNetworkKey.
const (
	profileAKeyID   = 10
	profileBKeyID   = 11
	profileAPrivKey = "8e4f3c2a1b0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f"
	profileBPrivKey = "a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"
)

// subscriptionChangeIMSI is a dedicated subscriber (outside the shared pool) for
// the subscription-change reconciliation tests, which mutate its profile. Tests
// restore it on cleanup so the persistent env stays consistent. The 5G SUPI form
// is subscriptionChangeSUPI.
const (
	subscriptionChangeIMSI = "001010000000100"
	subscriptionChangeSUPI = "imsi-" + subscriptionChangeIMSI
)

// provisionAlternateSlice installs a second slice (SST 2) with its own profile
// and policy, so a subscriber can be moved onto a slice that does not match an
// existing PDU session. Idempotent across the persistent env.
func provisionAlternateSlice(token string) error {
	if err := ensureProvisioned(token, "/api/v1/slices", "alternate",
		`{"name":"alternate","sst":2,"sd":"abcdef"}`); err != nil {
		return err
	}

	if err := ensureProvisioned(token, "/api/v1/profiles", "alternate",
		`{"name":"alternate","ue_ambr_uplink":"100 Mbps","ue_ambr_downlink":"100 Mbps"}`); err != nil {
		return err
	}

	return ensureProvisioned(token, "/api/v1/policies", "alternate",
		`{"name":"alternate","profile_name":"alternate","slice_name":"alternate","data_network_name":"internet","session_ambr_uplink":"200 Mbps","session_ambr_downlink":"200 Mbps","var5qi":9,"arp":1}`)
}

// provisionHomeNetworkKeys installs the Profile A (X25519) and Profile B (P-256)
// home network private keys in the core. Idempotent across the persistent env.
func provisionHomeNetworkKeys(token string) error {
	keys := []struct {
		id     int
		scheme string
		priv   string
	}{
		{profileAKeyID, "A", profileAPrivKey},
		{profileBKeyID, "B", profileBPrivKey},
	}

	for _, k := range keys {
		body := fmt.Sprintf(`{"keyIdentifier":%d,"scheme":%q,"privateKey":%q}`, k.id, k.scheme, k.priv)

		req, _ := http.NewRequest("POST", ellaAPIURL+"/api/v1/operator/home-network-keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("create home network key %d: %v", k.id, err)
		}

		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// On a fresh DB the create returns 201. On a persistent env the key
		// already exists, which the core reports without a stable status code, so
		// non-success is treated as best-effort and surfaced as a log line — the
		// SUCI tests fail loudly if the key is in fact missing.
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			log.Printf("home network key %d not created (HTTP %d: %s) — assuming already provisioned", k.id, resp.StatusCode, b)
		}
	}

	return nil
}

// ensureProvisioned creates a named resource under collectionPath only if a GET
// on collectionPath/name does not already find it, keeping TestMain idempotent
// across the persistent test environment.
func ensureProvisioned(token, collectionPath, name, body string) error {
	getReq, _ := http.NewRequest("GET", ellaAPIURL+collectionPath+"/"+name, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)

	if resp, err := http.DefaultClient.Do(getReq); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			return nil
		}
	}

	postReq, _ := http.NewRequest("POST", ellaAPIURL+collectionPath, strings.NewReader(body))
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		return fmt.Errorf("POST %s: %v", collectionPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 201 || resp.StatusCode == 200 {
		return nil
	}

	b, _ := io.ReadAll(resp.Body)

	return fmt.Errorf("POST %s: HTTP %d: %s", collectionPath, resp.StatusCode, b)
}

func doHTTP(method, url, body string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

// doRequest performs an HTTP request and returns status code + body.
func doRequest(t *testing.T, method, path, body string) (int, []byte) {
	t.Helper()
	resp, err := doHTTP(method, testerURL+path, body)
	if err != nil {
		t.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, b
}

// jsonGet extracts a value from JSON using dot-separated keys (e.g. "nas.message_type").
func jsonGet(data []byte, path string) string {
	keys := strings.Split(path, ".")
	var current any
	if err := json.Unmarshal(data, &current); err != nil {
		return ""
	}
	for _, k := range keys {
		switch c := current.(type) {
		case map[string]any:
			current = c[k]
		case []any:
			idx, err := strconv.Atoi(k)
			if err != nil || idx < 0 || idx >= len(c) {
				return ""
			}
			current = c[idx]
		default:
			return ""
		}
	}
	if current == nil {
		return ""
	}
	switch v := current.(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return fmt.Sprintf("%d", int64(v))
		}
		return fmt.Sprintf("%v", v)
	case bool:
		return fmt.Sprintf("%v", v)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// mustCreateGnB creates a standard gNB on an allocated gNB ID and returns its
// store ID. Registers cleanup. Tests that need a specific NGAP gNB ID call
// createGnBWithID.
func mustCreateGnB(t *testing.T) string {
	t.Helper()
	body := fmt.Sprintf(`{
		"amf_address": "10.3.0.2:38412",
		"gnb_n2_address": "10.3.0.3",
		"mcc": "001", "mnc": "01",
		"tac": "000001", "gnb_id": %q,
		"name": "test-gnb", "sst": 1
	}`, claimGnBID())
	status, resp := doRequest(t, "POST", "/gnb", body)
	if status != 201 {
		t.Fatalf("create gnb: HTTP %d: %s", status, resp)
	}
	gnbID := jsonGet(resp, "gnb_id")
	if gnbID == "" {
		t.Fatal("create gnb: no gnb_id in response")
	}
	t.Cleanup(func() {
		doRequest(t, "DELETE", "/gnb/"+gnbID, "")
		time.Sleep(200 * time.Millisecond)
	})
	return gnbID
}

// mustCreateUE creates a UE on the given gNB, drawing a subscriber no other test
// holds, and returns its store ID. Tests that need a specific subscriber call
// createUEForSUPI or establishRegisteredUEWithSUPI.
func mustCreateUE(t *testing.T, gnbID string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"supi": %q,
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet",
		"routing_indicator": "0",
		"protection_scheme": "0",
		"public_key_id": "0",
		"imeisv": "1122334455667788"
	}`, claimSubscriber(t))
	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue", body)
	if status != 201 {
		t.Fatalf("create ue: HTTP %d: %s", status, resp)
	}
	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		t.Fatal("create ue: no ue_id in response")
	}

	return ueID
}

// doRegistrationFlow completes a full registration (all 4 steps) for the given gNB/UE.
func doRegistrationFlow(t *testing.T, gnbID, ueID string) {
	t.Helper()

	steps := []string{
		`{"message_type":"registration_request"}`,
		`{"message_type":"authentication_response"}`,
		`{"message_type":"security_mode_complete"}`,
		`{"message_type":"registration_complete"}`,
	}
	for _, body := range steps {
		status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap", body)
		if status != 200 {
			t.Fatalf("registration flow step failed: HTTP %d\n  body: %s", status, resp)
		}
	}
}

// doFullFlow completes registration + PDU session + deregistration.
func doFullFlow(t *testing.T, gnbID, ueID string) {
	t.Helper()

	doRegistrationFlow(t, gnbID, ueID)

	status, resp := doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"pdu_session_establishment_request"}`)
	if status != 200 {
		t.Fatalf("pdu_session: HTTP %d: %s", status, resp)
	}

	status, resp = doRequest(t, "POST", "/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"deregistration_request"}`)
	if status != 200 {
		t.Fatalf("deregistration: HTTP %d: %s", status, resp)
	}
}

// fieldCheck is used in table-driven tests to assert a JSON field value.
type fieldCheck struct {
	wantNonEmpty bool
	wantExact    string
}

var nonEmpty = fieldCheck{wantNonEmpty: true}

func exact(v string) fieldCheck { return fieldCheck{wantExact: v} }

func (fc fieldCheck) assert(t *testing.T, field, got string) {
	t.Helper()
	if fc.wantNonEmpty && got == "" {
		t.Errorf("%s is empty, want non-empty", field)
	}
	if fc.wantExact != "" && got != fc.wantExact {
		t.Errorf("%s = %q, want %q", field, got, fc.wantExact)
	}
}
