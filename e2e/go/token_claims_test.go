// Directory-derived token claims, read off a token a real MSAL acquired.
//
// `wids` and the group-overage payload are the emulator's answer to "what does
// the directory say about this user", and they only matter as they appear in an
// issued token. Asserting them on a token MSAL Go fetched — rather than on one
// our own code minted — is what makes the claim about interoperability rather
// than about our own reading of the shape.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/calvinchengx/entra-emulator/emulator"
)

// globalAdminTemplateID is the well-known built-in Global Administrator role
// template GUID — the same value real Entra emits in `wids`.
const globalAdminTemplateID = "62e90394-69f5-4237-9190-012177145e10"

// graphToken acquires an app-only Graph token with MSAL Go, used to drive the
// directory setup through Graph rather than a side door.
func graphToken(t *testing.T, emu *emulator.Emulator) string {
	t.Helper()
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
	res, err := cca.AcquireTokenByCredential(context.Background(),
		[]string{"https://graph.microsoft.com/.default"})
	if err != nil {
		t.Fatal(err)
	}
	return res.AccessToken
}

func graphPost(t *testing.T, emu *emulator.Emulator, token, path string, body any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, emu.Origin+"/graph/v1.0"+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := emu.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 {
		t.Fatalf("POST %s: %d %v", path, resp.StatusCode, out)
	}
	return out
}

// patchApp sets app registration fields through the admin control surface.
func patchApp(t *testing.T, emu *emulator.Emulator, appID string, body any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch,
		emu.Origin+"/admin/api/apps/"+appID, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := emu.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("patch app: %d", resp.StatusCode)
	}
}

// aliceToken signs alice in with MSAL Go and returns the ID token's claims —
// `wids` and the overage payload are ID-token claims.
func aliceToken(t *testing.T, emu *emulator.Emulator) map[string]any {
	t.Helper()
	pca, err := public.New(emulator.SPAClientID,
		public.WithAuthority(emu.Authority()),
		public.WithHTTPClient(emu.HTTPClient()),
		public.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	res, err := pca.AcquireTokenByUsernamePassword(context.Background(),
		[]string{"openid", "profile"}, emulator.AliceUPN, emulator.Password)
	if err != nil {
		t.Fatalf("MSAL Go sign-in: %v", err)
	}
	if res.IDToken.Oid == "" {
		t.Fatal("no id token")
	}
	return oboClaims(t, res.IDToken.RawToken)
}

func TestMSALGoWidsClaim(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())
	tok := graphToken(t, emu)

	// wids is emitted only when the app opts into directory-role claims.
	patchApp(t, emu, emulator.SPAClientID, map[string]any{"groupMembershipClaims": "All"})

	// A custom (tenant-authored) role, assigned to alice. Real Entra emits
	// built-in role TEMPLATE GUIDs in wids and excludes custom roles, so this
	// is the negative control that makes the positive assertion mean something.
	custom := graphPost(t, emu, tok, "/roleManagement/directory/roleDefinitions", map[string]any{
		"displayName": "E2E Custom Role", "rolePermissions": []string{"microsoft.directory/users/basic/read"},
	})
	customID, _ := custom["id"].(string)
	graphPost(t, emu, tok, "/roleManagement/directory/roleAssignments", map[string]any{
		"roleDefinitionId": customID, "principalId": emulator.AliceOID, "directoryScopeId": "/",
	})

	t.Run("a custom role alone emits no wids", func(t *testing.T) {
		claims := aliceToken(t, emu)
		if w, present := claims["wids"]; present {
			t.Fatalf("custom roles must not appear in wids, got %v", w)
		}
	})

	graphPost(t, emu, tok, "/roleManagement/directory/roleAssignments", map[string]any{
		"roleDefinitionId": globalAdminTemplateID, "principalId": emulator.AliceOID,
		"directoryScopeId": "/",
	})

	t.Run("a built-in role emits exactly its template GUID", func(t *testing.T) {
		claims := aliceToken(t, emu)
		wids, _ := claims["wids"].([]any)
		if len(wids) != 1 {
			t.Fatalf("wids = %v, want exactly the built-in template GUID", claims["wids"])
		}
		if wids[0] != globalAdminTemplateID {
			t.Errorf("wids[0] = %v, want %s", wids[0], globalAdminTemplateID)
		}
	})
}

func TestMSALGoGroupOverage(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())
	tok := graphToken(t, emu)

	// Opt into group claims with a limit low enough to overflow deliberately.
	patchApp(t, emu, emulator.SPAClientID, map[string]any{
		"groupMembershipClaims": "All", "groupOverageLimit": 2,
	})

	// Below the limit: the groups list itself. Without this the overage
	// assertion would pass against a server that never emitted groups at all.
	t.Run("under the limit the groups list is emitted", func(t *testing.T) {
		claims := aliceToken(t, emu)
		groups, _ := claims["groups"].([]any)
		if len(groups) == 0 {
			t.Fatal("no groups claim below the overage limit")
		}
		if _, over := claims["_claim_names"]; over {
			t.Error("overage payload emitted below the limit")
		}
	})

	// Push alice over the limit, keeping the ids so the recovery below can be
	// asserted by identity rather than by count.
	var pushed []string
	for i := 0; i < 3; i++ {
		g := graphPost(t, emu, tok, "/groups", map[string]any{
			"displayName": fmt.Sprintf("Overage %d", i), "mailEnabled": false,
			"mailNickname": fmt.Sprintf("overage%d", i), "securityEnabled": true,
		})
		gid, _ := g["id"].(string)
		graphPost(t, emu, tok, "/groups/"+gid+"/members/$ref", map[string]any{
			"@odata.id": emu.Origin + "/graph/v1.0/directoryObjects/" + emulator.AliceOID,
		})
		pushed = append(pushed, gid)
	}

	t.Run("over the limit the overage payload replaces the list", func(t *testing.T) {
		claims := aliceToken(t, emu)
		if _, present := claims["groups"]; present {
			t.Error("groups list still emitted above the overage limit")
		}
		names, _ := claims["_claim_names"].(map[string]any)
		if names["groups"] != "src1" {
			t.Fatalf("_claim_names = %v, want groups -> src1", claims["_claim_names"])
		}
		sources, _ := claims["_claim_sources"].(map[string]any)
		src1, _ := sources["src1"].(map[string]any)
		endpoint, _ := src1["endpoint"].(string)
		// The endpoint has to be resolvable, not decorative: it is how a client
		// recovers the group list it did not get.
		if endpoint == "" {
			t.Fatal("_claim_sources carries no endpoint")
		}
		req, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := emu.HTTPClient().Do(req)
		if err != nil {
			t.Fatalf("overage endpoint %s: %v", endpoint, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("overage endpoint %s returned %d — a client following it "+
				"cannot recover the groups", endpoint, resp.StatusCode)
		}
		// A 200 is not the point; recovering the list is. The token dropped the
		// groups claim, so these ids are the only way back to it.
		var recovered struct {
			Value []string `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&recovered); err != nil {
			t.Fatal(err)
		}
		// By identity, not by count. A cardinality check ("more than 2 ids came
		// back") passes on a response full of ids that have nothing to do with
		// alice — it asserts the shape of the result rather than the result.
		got := make(map[string]bool, len(recovered.Value))
		for _, id := range recovered.Value {
			got[id] = true
		}
		for _, want := range pushed {
			if !got[want] {
				t.Errorf("group %s is missing from the recovered list %v — the "+
					"pointer resolved but did not return alice's groups", want, recovered.Value)
			}
		}
	})
}
