// Roadmap #3 e2e: a real azidentity.ManagedIdentityCredential acquires a
// token from the emulator's App Service managed-identity endpoint — the
// exact code path a Go service running in App Service / Container Apps uses,
// with no secret in the app. Uses the embeddable library (in-process).
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/calvinchengx/entra-emulator/emulator"
)

func TestManagedIdentityViaAzidentity(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())

	// The App Service protocol is discovered via these env vars; azidentity
	// reads them when constructing ManagedIdentityCredential.
	t.Setenv("IDENTITY_ENDPOINT", emu.Origin+"/msi/token")
	t.Setenv("IDENTITY_HEADER", "managed-identity-secret")

	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ClientOptions: azcore.ClientOptions{Transport: emu.HTTPClient()},
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		t.Fatalf("ManagedIdentityCredential.GetToken: %v", err)
	}

	parts := strings.Split(tok.Token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != emu.Issuer {
		t.Fatalf("token iss %v != emu.Issuer %v", claims["iss"], emu.Issuer)
	}
	// azidentity requests <resource>/.default; Azure/our endpoint issues a
	// token whose audience is the resource.
	if aud, _ := claims["aud"].(string); !strings.HasPrefix(aud, "https://management.azure.com") {
		t.Fatalf("unexpected managed-identity token aud: %v", claims["aud"])
	}
	if _, hasOID := claims["oid"]; hasOID {
		t.Fatal("managed-identity token must be app-only (no oid)")
	}
}
