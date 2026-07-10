// Demonstrates the embeddable library (roadmap #1): a real MSAL Go client
// completes client credentials against an in-process emulator — no external
// server, no e2e/run.sh, no fixed ports. This is the headline use case for
// Go teams testing MSAL/azidentity integration.
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"

	"github.com/calvinchengx/entra-emulator/emulator"
)

func TestEmbeddedLibraryWithMSALGo(t *testing.T) {
	// TLS is required: MSAL Go rejects non-https authorities. HTTPClient()
	// trusts the instance's self-signed cert.
	emu := emulator.StartT(t, emulator.WithTLS()) // in-process; auto-closed at test end

	cred, err := confidential.NewCredFromSecret(emulator.DaemonSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := confidential.New(emu.Authority(), emulator.DaemonClientID, cred,
		confidential.WithHTTPClient(emu.HTTPClient()),
		confidential.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.AcquireTokenByCredential(context.Background(),
		[]string{"api://" + emulator.DaemonClientID + "/.default"})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(result.AccessToken, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != emu.Issuer {
		t.Fatalf("token iss %v != emu.Issuer %v", claims["iss"], emu.Issuer)
	}
	if claims["aud"] != "api://"+emulator.DaemonClientID {
		t.Fatalf("unexpected aud: %v", claims["aud"])
	}
	roles, _ := json.Marshal(claims["roles"])
	if !strings.Contains(string(roles), "Tasks.Read.All") {
		t.Fatalf("missing auto-granted role: %s", roles)
	}
}
