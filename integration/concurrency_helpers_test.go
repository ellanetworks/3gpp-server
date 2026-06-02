//go:build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"testing"
)

// numTestSubscribers is the size of the subscriber pool TestMain provisions.
// Low indices (1..6) are hard-coded by older single-UE tests; concurrency and
// fast-sequence tests claim higher, non-overlapping blocks.
const numTestSubscribers = 40

// testSUPI returns the SUPI of the i-th pooled subscriber (1-based): MCC 001,
// MNC 01, and a 10-digit MSIN, matching the keys createSubscriber provisions.
func testSUPI(i int) string {
	return fmt.Sprintf("imsi-00101%010d", i)
}

// post issues a POST without a *testing.T, so it is safe to call from a
// goroutine (t.Fatalf must only run on the test's own goroutine).
func post(path, body string) (int, []byte, error) {
	resp, err := doHTTP("POST", testerURL+path, body)
	if err != nil {
		return 0, nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, b, nil
}

// createUEForSUPI creates a UE context for supi on gnbID and returns its store
// id. Goroutine-safe (returns errors instead of calling *testing.T).
func createUEForSUPI(gnbID, supi string) (string, error) {
	body := fmt.Sprintf(`{
		"supi": "%s",
		"k": "00112233445566778899aabbccddeeff",
		"opc": "63bfa50ee6523365ff14c1f45f88737d",
		"amf": "8000", "sqn": "000000000020",
		"sst": 1, "dnn": "internet",
		"routing_indicator": "0", "protection_scheme": "0", "public_key_id": "0",
		"imeisv": "1122334455667788"
	}`, supi)

	status, resp, err := post("/gnb/"+gnbID+"/ue", body)
	if err != nil {
		return "", err
	}

	if status != 201 {
		return "", fmt.Errorf("create ue %s: HTTP %d: %s", supi, status, resp)
	}

	ueID := jsonGet(resp, "ue_id")
	if ueID == "" {
		return "", fmt.Errorf("create ue %s: no ue_id in response: %s", supi, resp)
	}

	return ueID, nil
}

// regResult is the outcome of a goroutine-safe registration.
type regResult struct {
	ueID string
	guti string
}

// registerSUPI creates a UE for supi and runs a full initial registration,
// returning its store id and the 5G-GUTI the AMF assigned. Goroutine-safe.
func registerSUPI(gnbID, supi string) (regResult, error) {
	ueID, err := createUEForSUPI(gnbID, supi)
	if err != nil {
		return regResult{}, err
	}

	steps := []struct{ body, wantNAS string }{
		{`{"message_type":"registration_request","capability_5gmm":"07"}`, nasAuthenticationRequest},
		{`{"message_type":"authentication_response"}`, nasSecurityModeCommand},
		{`{"message_type":"security_mode_complete"}`, nasRegistrationAccept},
		{`{"message_type":"registration_complete"}`, ""},
	}

	var guti string

	for i, s := range steps {
		status, body, err := post("/gnb/"+gnbID+"/ue/"+ueID+"/ngap", s.body)
		if err != nil {
			return regResult{}, err
		}

		if status != 200 {
			return regResult{}, fmt.Errorf("reg step %d (%s): HTTP %d: %s", i, supi, status, body)
		}

		if s.wantNAS != "" {
			if got := jsonGet(body, "nas.message_type"); got != s.wantNAS {
				return regResult{}, fmt.Errorf("reg step %d (%s): nas.message_type = %q, want %q: %s", i, supi, got, s.wantNAS, body)
			}
		}

		if s.wantNAS == nasRegistrationAccept {
			guti = jsonGet(body, "nas.guti")
		}
	}

	return regResult{ueID: ueID, guti: guti}, nil
}

// establishSession sends a PDU Session Establishment Request and returns the UE
// IP address the SMF allocated (from the PDU Session Establishment Accept).
// Goroutine-safe.
func establishSession(gnbID, ueID string, sessionID int) (string, error) {
	status, body, err := post("/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		fmt.Sprintf(`{"message_type":"pdu_session_establishment_request","pdu_session_id":%d}`, sessionID))
	if err != nil {
		return "", err
	}

	if status != 200 {
		return "", fmt.Errorf("establish PDU session %d on ue %s: HTTP %d: %s", sessionID, ueID, status, body)
	}

	return jsonGet(body, "nas.pdu_address"), nil
}

// deregister sends a (switch-off) Deregistration Request. Goroutine-safe.
func deregister(gnbID, ueID string) error {
	status, body, err := post("/gnb/"+gnbID+"/ue/"+ueID+"/ngap",
		`{"message_type":"deregistration_request"}`)
	if err != nil {
		return err
	}

	if status != 200 {
		return fmt.Errorf("deregister ue %s: HTTP %d: %s", ueID, status, body)
	}

	return nil
}

// runParallel runs fn(i) for i in [0,n) concurrently and reports the first error
// from each worker. fn must be goroutine-safe — it must not touch *testing.T.
func runParallel(t *testing.T, n int, fn func(i int) error) {
	t.Helper()

	var wg sync.WaitGroup

	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			errs[i] = fn(i)
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("parallel worker %d: %v", i, err)
		}
	}
}

// ueAmfNgapID returns the AMF UE NGAP ID the AMF assigned to a UE.
func ueAmfNgapID(t *testing.T, gnbID, ueID string) int64 {
	t.Helper()

	status, body := doRequest(t, "GET", "/gnb/"+gnbID+"/ue/"+ueID, "")
	if status != 200 {
		t.Fatalf("get ue %s state: HTTP %d\n  body: %s", ueID, status, body)
	}

	var st struct {
		AmfUeNgapID int64 `json:"amf_ue_ngap_id"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("decode ue state: %v\n  body: %s", err, body)
	}

	return st.AmfUeNgapID
}
