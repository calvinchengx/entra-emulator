// private_key_jwt / certificate client authentication, witnessed by Microsoft's
// own MSAL Go rather than by a hand-rolled assertion.
//
// This matters because the client assertion is a JWT the CLIENT builds: its
// header (`alg`, `x5t`), its claims (`iss`, `sub`, `aud`, `jti`, `exp`) and its
// signature are all MSAL's work, not ours. A hand-written test proves the
// emulator accepts the assertion WE know how to build; this proves it accepts
// the one a real Microsoft client actually sends.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"

	"github.com/calvinchengx/entra-emulator/emulator"
)

// selfSigned mints an RSA key and a self-signed certificate for it — the shape
// an app registration's keyCredential carries.
func selfSigned(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// registerKey adds a keyCredential to an app through the admin API.
func registerKey(t *testing.T, emu *emulator.Emulator, appID, certPEM string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"publicKey": certPEM, "displayName": "e2e cert"})
	resp, err := emu.HTTPClient().Post(
		emu.Origin+"/admin/api/apps/"+appID+"/keyCredentials",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register keyCredential: %d", resp.StatusCode)
	}
}

func certClient(t *testing.T, emu *emulator.Emulator, cert *x509.Certificate, key *rsa.PrivateKey) confidential.Client {
	t.Helper()
	// NewCredFromCert is MSAL Go's certificate credential: it signs a
	// client_assertion with this key and sends it as private_key_jwt.
	cred, err := confidential.NewCredFromCert([]*x509.Certificate{cert}, key)
	if err != nil {
		t.Fatal(err)
	}
	client, err := confidential.New(emu.Authority(), emulator.DaemonClientID, cred,
		confidential.WithHTTPClient(emu.HTTPClient()),
		confidential.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestMSALGoCertificateClientAuthentication(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())

	cert, key, certPEM := selfSigned(t, "registered.e2e")
	registerKey(t, emu, emulator.DaemonClientID, certPEM)

	scopes := []string{"api://" + emulator.DaemonClientID + "/.default"}

	t.Run("a registered certificate authenticates the client", func(t *testing.T) {
		result, err := certClient(t, emu, cert, key).
			AcquireTokenByCredential(context.Background(), scopes)
		if err != nil {
			t.Fatalf("MSAL Go could not authenticate with the registered cert: %v", err)
		}
		if result.AccessToken == "" {
			t.Fatal("no access token")
		}
	})

	// The negative control. Without it this test would pass against an emulator
	// that accepted any assertion at all — which is not authentication, it is a
	// formality. The key here is never registered, so the signature cannot
	// verify against anything the app holds.
	t.Run("an unregistered certificate is rejected", func(t *testing.T) {
		otherCert, otherKey, _ := selfSigned(t, "unregistered.e2e")
		_, err := certClient(t, emu, otherCert, otherKey).
			AcquireTokenByCredential(context.Background(), scopes)
		if err == nil {
			t.Fatal("an assertion signed by an unregistered key was accepted")
		}
	})
}
