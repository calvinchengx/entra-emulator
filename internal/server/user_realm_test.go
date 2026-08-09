package server

import (
	"net/http"
	"testing"
)

// TestUserRealmProbe covers /common/UserRealm/{user}, the endpoint MSAL Go
// calls BEFORE it will attempt a username/password request. It gives up on a
// non-200, so a missing route makes ROPC unreachable from that SDK — the token
// endpoint is never even contacted.
//
// MSAL Go also validates the body and rejects a response missing any of
// account_type, domain_name, cloud_instance_name or cloud_audience_urn, so a
// 200 with a thin payload is as fatal as a 404.
func TestUserRealmProbe(t *testing.T) {
	hts, _, _ := newTestServer(t)

	t.Run("answers with every field MSAL Go requires", func(t *testing.T) {
		code, doc := getJSON(t, hts.URL+"/common/UserRealm/alice@entraemulator.dev?api-version=1.0")
		if code != http.StatusOK {
			t.Fatalf("user realm probe: %d", code)
		}
		for _, field := range []string{
			"account_type", "domain_name", "cloud_instance_name", "cloud_audience_urn",
		} {
			if v, _ := doc[field].(string); v == "" {
				t.Errorf("%s is empty — MSAL Go rejects the response", field)
			}
		}
		// Managed, always: the emulator holds every credential it can verify.
		// Federated would send the client to an IdP that does not exist.
		if doc["account_type"] != "Managed" {
			t.Errorf("account_type = %v, want Managed", doc["account_type"])
		}
		if doc["domain_name"] != "entraemulator.dev" {
			t.Errorf("domain_name = %v, want the address's own domain", doc["domain_name"])
		}
	})

	// The probe must not become a user-enumeration oracle: real Entra answers
	// the same shape whether or not the address exists, and so does this.
	t.Run("does not reveal whether the user exists", func(t *testing.T) {
		code, doc := getJSON(t, hts.URL+"/common/UserRealm/nobody@entraemulator.dev?api-version=1.0")
		if code != http.StatusOK {
			t.Fatalf("unknown user: %d — a 404 here tells an attacker the address is free", code)
		}
		if doc["account_type"] != "Managed" {
			t.Errorf("unknown user answered differently: %v", doc["account_type"])
		}
	})
}
