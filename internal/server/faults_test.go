package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// clientCreds is a normal, valid client-credentials call used to observe
// whether a fault is active.
func clientCreds(t *testing.T, base string) (int, map[string]any) {
	t.Helper()
	resp, body := postForm(t, http.DefaultClient, base+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {daemonID},
		"client_secret": {store.SeedDaemonSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	})
	return resp.StatusCode, body
}

func getJSON(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func deleteFaults(t *testing.T, origin string) {
	t.Helper()
	req, _ := http.NewRequest("DELETE", origin+"/admin/api/faults", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestFaultInjectionForcedError(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Baseline: works.
	if code, _ := clientCreds(t, hts.URL); code != 200 {
		t.Fatalf("baseline should succeed, got %d", code)
	}

	// Arm a forced error.
	status, _ := postJSON(t, hts.URL+"/admin/api/faults", map[string]any{
		"tokenError":            "temporarily_unavailable",
		"tokenErrorDescription": "chaos test",
	})
	if status != 200 {
		t.Fatalf("set faults: %d", status)
	}

	// Now the token endpoint fails with the injected error + correct status.
	code, body := clientCreds(t, hts.URL)
	if code != 503 { // temporarily_unavailable → 503
		t.Fatalf("injected error: want 503, got %d %v", code, body)
	}
	if body["error"] != "temporarily_unavailable" || body["error_description"] != "chaos test" {
		t.Fatalf("injected error body: %v", body)
	}

	// Clearing restores normal behavior.
	deleteFaults(t, hts.URL)
	if code, _ := clientCreds(t, hts.URL); code != 200 {
		t.Fatalf("after clear should succeed, got %d", code)
	}
}

func TestFaultInjectionLatency(t *testing.T) {
	hts, _, _ := newTestServer(t)

	if status, _ := postJSON(t, hts.URL+"/admin/api/faults", map[string]any{
		"tokenLatencyMs": 200,
	}); status != 200 {
		t.Fatal("set latency fault failed")
	}

	start := time.Now()
	code, _ := clientCreds(t, hts.URL)
	elapsed := time.Since(start)
	// Latency applies but no error — the call still succeeds.
	if code != 200 {
		t.Fatalf("latency-only fault should still succeed, got %d", code)
	}
	if elapsed < 180*time.Millisecond {
		t.Fatalf("expected >=~200ms latency, took %v", elapsed)
	}
}

func TestFaultInjectionValidation(t *testing.T) {
	hts, _, _ := newTestServer(t)

	if status, _ := postJSON(t, hts.URL+"/admin/api/faults", map[string]any{
		"probability": 2.0,
	}); status != 400 {
		t.Fatalf("probability > 1 should be 400, got %d", status)
	}
	if status, _ := postJSON(t, hts.URL+"/admin/api/faults", map[string]any{
		"tokenLatencyMs": -5,
	}); status != 400 {
		t.Fatalf("negative latency should be 400, got %d", status)
	}
}

func TestFaultInjectionGetReflectsState(t *testing.T) {
	hts, _, _ := newTestServer(t)

	postJSON(t, hts.URL+"/admin/api/faults", map[string]any{
		"tokenError": "invalid_grant", "probability": 1,
	})
	code, body := getJSON(t, hts.URL+"/admin/api/faults")
	if code != 200 || body["tokenError"] != "invalid_grant" {
		t.Fatalf("GET faults should reflect state: %d %v", code, body)
	}
}
