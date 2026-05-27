//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var (
	testerURL  string
	ellaAPIURL string
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

	if err := createSubscriber(token, "001010000000001"); err != nil {
		log.Fatalf("Subscriber 001 creation failed: %v", err)
	}

	if err := createSubscriber(token, "001010000000002"); err != nil {
		log.Fatalf("Subscriber 002 creation failed: %v", err)
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
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[k]
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

// mustCreateGnB creates a standard gNB and returns its ID. Registers cleanup.
func mustCreateGnB(t *testing.T) string {
	t.Helper()
	body := `{
		"amf_address": "10.3.0.2:38412",
		"gnb_n2_address": "10.3.0.3",
		"mcc": "001", "mnc": "01",
		"tac": "000001", "gnb_id": "000001",
		"name": "test-gnb", "sst": 1
	}`
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

// mustCreateUE creates a UE on the given gNB with subscriber 001 and returns its ID.
func mustCreateUE(t *testing.T, gnbID string) string {
	t.Helper()

	return mustCreateUEWithSUPI(t, gnbID, "imsi-001010000000001")
}

// mustCreateUE2 creates a UE on the given gNB with subscriber 002 and returns its ID.
func mustCreateUE2(t *testing.T, gnbID string) string {
	t.Helper()

	return mustCreateUEWithSUPI(t, gnbID, "imsi-001010000000002")
}

func mustCreateUEWithSUPI(t *testing.T, gnbID, supi string) string {
	t.Helper()

	body := fmt.Sprintf(`{
		"supi": "%s",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet",
		"routing_indicator": "0",
		"protection_scheme": "0",
		"public_key_id": "0"
	}`, supi)
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
