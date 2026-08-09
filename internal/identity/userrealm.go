package identity

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// GET /common/UserRealm/{user}?api-version=1.0
//
// Entra's user-realm probe: given a username, is this account MANAGED (the
// tenant holds the credential) or FEDERATED (sign-in belongs to an external
// IdP, so the client must go there instead)?
//
// It is not optional decoration. MSAL Go calls this BEFORE it will attempt a
// username/password token request, and aborts on a non-200 — so without this
// route `AcquireTokenByUsernamePassword` fails against the emulator with a
// bare 404 and never reaches the token endpoint at all. msal-node does not
// probe, which is why the ROPC gap stayed invisible until MSAL Go drove it.
//
// The emulator has no federation: every account it holds is one it can verify
// a password for, so the answer is always "Managed". Answering Federated would
// be a lie that sends the client off to an IdP that does not exist.
//
// MSAL Go requires account_type, domain_name, cloud_instance_name and
// cloud_audience_urn to all be present, and rejects the response otherwise.
func (i *Identity) handleUserRealm(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if user == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: a username is required.")
		return
	}

	// The domain is taken from the username itself, as Entra does — the probe
	// answers for an address, and it deliberately does NOT reveal whether that
	// address exists. Returning 404 for an unknown user would turn this into a
	// user-enumeration oracle; real Entra answers uniformly.
	domain := i.tenantInitialDomain()
	if at := strings.LastIndex(user, "@"); at >= 0 && at+1 < len(user) {
		domain = user[at+1:]
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"ver":                 "1.0",
		"account_type":        "Managed",
		"domain_name":         domain,
		"cloud_instance_name": i.cloudInstanceName(),
		"cloud_audience_urn":  "urn:federation:MicrosoftOnline",
	})
}

// tenantInitialDomain is the fallback domain for a username with no domain
// part — the emulator's own host, which is what its issuer already uses.
func (i *Identity) tenantInitialDomain() string {
	return hostOf(i.Cfg.Origins.Login)
}
