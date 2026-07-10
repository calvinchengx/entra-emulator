package emulator_test

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/emulator"
)

func decodeClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestStartAndHealth(t *testing.T) {
	emu := emulator.StartT(t)

	if emu.Origin == "" || emu.TenantID != emulator.TenantID {
		t.Fatalf("unexpected instance fields: %+v", emu)
	}
	resp, err := emu.HTTPClient().Get(emu.Origin + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health: want 200, got %d", resp.StatusCode)
	}
	var health map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&health)
	if health["tenantId"] != emulator.TenantID {
		t.Fatalf("health tenantId mismatch: %v", health["tenantId"])
	}
}

func TestDiscoveryAndIssuerAgree(t *testing.T) {
	emu := emulator.StartT(t)

	resp, err := emu.HTTPClient().Get(emu.DiscoveryURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)

	if doc["issuer"] != emu.Issuer {
		t.Fatalf("discovery issuer %v != emu.Issuer %v", doc["issuer"], emu.Issuer)
	}
	if doc["jwks_uri"] != emu.JWKSURL() {
		t.Fatalf("jwks_uri %v != emu.JWKSURL() %v", doc["jwks_uri"], emu.JWKSURL())
	}
}

// TestClientCredentialsViaLibrary proves the headline use case: acquire and
// verify a token entirely in-process, no external server, using only the
// exported seed constants.
func TestClientCredentialsViaLibrary(t *testing.T) {
	emu := emulator.StartT(t)

	resp, err := emu.HTTPClient().PostForm(emu.Authority()+"/oauth2/v2.0/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {emulator.DaemonClientID},
		"client_secret": {emulator.DaemonSecret},
		"scope":         {"api://" + emulator.DaemonClientID + "/.default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("token: want 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)

	claims := decodeClaims(t, body["access_token"].(string))
	if claims["iss"] != emu.Issuer {
		t.Fatalf("token iss %v != issuer %v", claims["iss"], emu.Issuer)
	}
	if claims["aud"] != "api://"+emulator.DaemonClientID {
		t.Fatalf("unexpected aud: %v", claims["aud"])
	}
}

func TestStoreAccessForFixtures(t *testing.T) {
	emu := emulator.StartT(t)

	// The exposed Store lets tests build fixtures directly.
	u, err := emu.Store().GetUser(emulator.AliceOID)
	if err != nil {
		t.Fatal(err)
	}
	if u.UserPrincipalName != emulator.AliceUPN {
		t.Fatalf("seed UPN mismatch: %q", u.UserPrincipalName)
	}
}

func TestWithoutSeedIsEmpty(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithoutSeed())

	seeded, err := emu.Store().IsSeeded()
	if err != nil {
		t.Fatal(err)
	}
	if seeded {
		t.Fatal("WithoutSeed should leave the directory empty")
	}
}

func TestTLSModeTrustsOwnCert(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())

	if !strings.HasPrefix(emu.Origin, "https://") {
		t.Fatalf("TLS mode origin should be https: %q", emu.Origin)
	}
	// The provided client trusts the self-signed cert.
	resp, err := emu.HTTPClient().Get(emu.Origin + "/health")
	if err != nil {
		t.Fatalf("HTTPClient should trust the emulator cert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("TLS health: want 200, got %d", resp.StatusCode)
	}
}

func TestIsolationBetweenInstances(t *testing.T) {
	a := emulator.StartT(t)
	b := emulator.StartT(t)

	if a.Origin == b.Origin {
		t.Fatal("two instances must have distinct listeners")
	}
	// A write to one must not appear in the other.
	if err := a.Store().DeleteUser(emulator.BobOID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Store().GetUser(emulator.BobOID); err != nil {
		t.Fatalf("instance b should be unaffected by writes to a: %v", err)
	}
}
