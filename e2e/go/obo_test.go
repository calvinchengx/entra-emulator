// On-Behalf-Of, witnessed by MSAL Go's own AcquireTokenOnBehalfOf rather than a
// hand-built form POST.
//
// OBO is where a middle-tier API trades the user token it received for a token
// to call something downstream AS THAT USER. The value of a real-SDK witness
// here is the request shape: MSAL Go decides the grant type, the
// `requested_token_use` parameter and how the assertion is carried. A test that
// posts those fields itself is asserting our reading of the spec back to us.
package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/calvinchengx/entra-emulator/emulator"
)

const middleTierScope = "api://" + emulator.DaemonClientID + "/access_as_user"

// oboClaims reads a JWT payload without verifying it. Signature verification is
// a separate claim with its own witness; what is under test here is which user
// and audience the token carries.
func oboClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
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

// exposeScope registers a delegated scope on an app, so a user token can be
// addressed to it. The seeded daemon exposes an app ROLE (app-only) but no
// delegated scope, and OBO needs a delegated assertion.
func exposeScope(t *testing.T, emu *emulator.Emulator, appID, value string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"value": value, "adminConsentDisplayName": "Access as the signed-in user",
	})
	resp, err := emu.HTTPClient().Post(
		emu.Origin+"/admin/api/apps/"+appID+"/scopes", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		t.Fatalf("expose scope: %d", resp.StatusCode)
	}
}

func TestMSALGoOnBehalfOf(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())
	exposeScope(t, emu, emulator.DaemonClientID, "access_as_user")

	// 1. A user signs in to the middle tier. The public SPA acquires a token
	//    whose audience is the middle-tier API — this is what a real client
	//    sends to that API, and what the API then redeems.
	pca, err := public.New(emulator.SPAClientID,
		public.WithAuthority(emu.Authority()),
		public.WithHTTPClient(emu.HTTPClient()),
		public.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	userTok, err := pca.AcquireTokenByUsernamePassword(context.Background(),
		[]string{middleTierScope}, emulator.AliceUPN, emulator.Password)
	if err != nil {
		t.Fatalf("acquire the middle-tier user token: %v", err)
	}
	userClaims := oboClaims(t, userTok.AccessToken)
	if got := userClaims["aud"]; got != "api://"+emulator.DaemonClientID {
		t.Fatalf("assertion aud = %v, want the middle tier", got)
	}
	if userClaims["oid"] != emulator.AliceOID {
		t.Fatalf("assertion oid = %v, want alice", userClaims["oid"])
	}

	// 2. The middle tier redeems it for a downstream token.
	cred, err := confidential.NewCredFromSecret(emulator.DaemonSecret)
	if err != nil {
		t.Fatal(err)
	}
	cca, err := confidential.New(emu.Authority(), emulator.DaemonClientID, cred,
		confidential.WithHTTPClient(emu.HTTPClient()),
		confidential.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the middle tier exchanges the user token for a downstream one", func(t *testing.T) {
		down, err := cca.AcquireTokenOnBehalfOf(context.Background(), userTok.AccessToken,
			[]string{"https://graph.microsoft.com/User.Read"})
		if err != nil {
			t.Fatalf("MSAL Go OBO failed: %v", err)
		}
		claims := oboClaims(t, down.AccessToken)

		// The user is carried through: this is the whole point of OBO. A flow
		// that minted an app-only token here would look successful and be
		// completely wrong.
		if claims["oid"] != emulator.AliceOID {
			t.Errorf("downstream oid = %v, want alice — the user was not carried through", claims["oid"])
		}
		// The audience moved to the downstream resource...
		if aud, _ := claims["aud"].(string); aud == "api://"+emulator.DaemonClientID {
			t.Errorf("downstream aud is still the middle tier: %v", aud)
		}
		// ...and the middle tier is now the calling application.
		if appid, _ := claims["appid"].(string); appid != emulator.DaemonClientID {
			t.Errorf("downstream appid = %v, want the middle tier", appid)
		}
		// Delegated, not app-only.
		if _, hasScp := claims["scp"]; !hasScp {
			t.Errorf("downstream token has no scp — it is not a delegated token")
		}
	})

	// The rule that makes OBO safe: a token minted for a DIFFERENT resource
	// cannot be redeemed by this app. Without this, any API holding any user
	// token could impersonate that user anywhere.
	t.Run("an assertion addressed elsewhere is refused", func(t *testing.T) {
		graphTok, err := pca.AcquireTokenByUsernamePassword(context.Background(),
			[]string{"https://graph.microsoft.com/User.Read"}, emulator.AliceUPN, emulator.Password)
		if err != nil {
			t.Fatalf("acquire a Graph-audience token: %v", err)
		}
		_, err = cca.AcquireTokenOnBehalfOf(context.Background(), graphTok.AccessToken,
			[]string{"https://graph.microsoft.com/User.Read"})
		if err == nil {
			t.Fatal("a token addressed to Graph was redeemed by the middle tier")
		}
		// Assert WHY. A bare `err != nil` would pass if OBO were broken outright,
		// or if the assertion failed to parse — neither of which proves the
		// audience rule is enforced.
		if !strings.Contains(err.Error(), "invalid_grant") ||
			!strings.Contains(err.Error(), "not addressed to this application") {
			t.Fatalf("refused, but not by the audience rule: %v", err)
		}
	})
}
