// Delegated consent, witnessed through the token a real MSAL receives.
//
// An oauth2PermissionGrant that is merely STORED is bookkeeping. The claim is
// that it is load-bearing: the scopes a user token actually carries in `scp`
// are the requested scopes intersected with what was consented. That is only
// observable in an issued token, and only meaningful if some requested scope is
// demonstrably withheld — so every assertion here is paired with a scope that
// must NOT appear.
package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/calvinchengx/entra-emulator/emulator"
)

// scpOf signs the user in with MSAL Go for both resource scopes and returns the
// access token's scp claim.
func scpOf(t *testing.T, emu *emulator.Emulator, upn string) string {
	t.Helper()
	pca, err := public.New(emulator.SPAClientID,
		public.WithAuthority(emu.Authority()),
		public.WithHTTPClient(emu.HTTPClient()),
		public.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	res, err := pca.AcquireTokenByUsernamePassword(context.Background(),
		[]string{
			"api://" + emulator.DaemonClientID + "/read_tasks",
			"api://" + emulator.DaemonClientID + "/write_tasks",
		}, upn, emulator.Password)
	if err != nil {
		t.Fatalf("MSAL Go sign-in for %s: %v", upn, err)
	}
	scp, _ := oboClaims(t, res.AccessToken)["scp"].(string)
	return scp
}

func hasScopeIn(scp, want string) bool {
	for _, s := range strings.Fields(scp) {
		if s == want {
			return true
		}
	}
	return false
}

func TestMSALGoDelegatedConsentGatesScp(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())
	tok := graphToken(t, emu)
	exposeScope(t, emu, emulator.DaemonClientID, "read_tasks")
	exposeScope(t, emu, emulator.DaemonClientID, "write_tasks")

	// Positive control first. With no grant recorded the emulator auto-consents,
	// so BOTH scopes land in scp. Without this, the restriction asserted below
	// would pass against a server that never granted write_tasks to anyone.
	t.Run("with no grant, both requested scopes are granted", func(t *testing.T) {
		scp := scpOf(t, emu, emulator.AliceUPN)
		if !hasScopeIn(scp, "read_tasks") || !hasScopeIn(scp, "write_tasks") {
			t.Fatalf("scp = %q, want both scopes before any grant exists", scp)
		}
	})

	// Now record consent for read_tasks ONLY.
	graphPost(t, emu, tok, "/oauth2PermissionGrants", map[string]any{
		"clientId": emulator.SPAClientID, "consentType": "AllPrincipals",
		"resourceId": emulator.DaemonClientID, "scope": "read_tasks",
	})

	t.Run("consent narrows scp to what was consented", func(t *testing.T) {
		scp := scpOf(t, emu, emulator.AliceUPN)
		if !hasScopeIn(scp, "read_tasks") {
			t.Errorf("scp = %q, want the consented read_tasks", scp)
		}
		// The assertion that makes the grant load-bearing rather than stored.
		if hasScopeIn(scp, "write_tasks") {
			t.Errorf("scp = %q still carries write_tasks — consent did not gate it", scp)
		}
	})
}

func TestMSALGoPerPrincipalConsent(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())
	tok := graphToken(t, emu)
	exposeScope(t, emu, emulator.DaemonClientID, "read_tasks")
	exposeScope(t, emu, emulator.DaemonClientID, "write_tasks")

	// A grant for BOB only. Entra scopes a `Principal` grant to that user, so
	// alice must not inherit it — this is the difference between per-user
	// consent and tenant-wide consent, and getting it wrong silently widens
	// every user's token.
	graphPost(t, emu, tok, "/oauth2PermissionGrants", map[string]any{
		"clientId": emulator.SPAClientID, "consentType": "Principal",
		"principalId": emulator.BobOID,
		"resourceId":  emulator.DaemonClientID, "scope": "read_tasks",
	})

	t.Run("the named principal gets the consented scope", func(t *testing.T) {
		scp := scpOf(t, emu, emulator.BobUPN)
		if !hasScopeIn(scp, "read_tasks") {
			t.Errorf("bob's scp = %q, want read_tasks", scp)
		}
	})

	t.Run("another user does not inherit it", func(t *testing.T) {
		scp := scpOf(t, emu, emulator.AliceUPN)
		if hasScopeIn(scp, "read_tasks") {
			t.Errorf("alice's scp = %q, but the grant named bob", scp)
		}
	})
}
