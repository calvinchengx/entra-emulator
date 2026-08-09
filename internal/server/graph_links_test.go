package server

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// TestGraphEmittedURLsResolve follows every URL the Graph surface hands a
// client, instead of asserting that those URLs look right.
//
// The distinction is the whole point. The group-overage payload advertised
// `getMemberObjects` for as long as it existed, and the route did not exist —
// the tests checked the payload's SHAPE and never fetched it, so a dead pointer
// read as a passing feature. Any assertion made against the shape of a URL is
// not testing the URL.
//
// Structure borrowed from the SCIM side's TestSCIMEmittedURLsResolve: collect
// from EVERY endpoint rather than the ones expected to emit links, and fail if
// the collector gathered nothing — a collector with a typo'd key silently
// collects zero and reports success, which would be this same defect one level
// up, inside the test written to detect it.
// identifierClaims are URL-shaped values that name something rather than
// pointing at it. Following them is a category error.
var identifierClaims = map[string]bool{"iss": true, "aud": true}

// probe issues one request and returns the status, closing the body.
func probe(t *testing.T, method, url, bearer string) (int, error) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	// Do NOT follow redirects. A 302 means the route resolved, which is what is
	// under test; chasing it would leave the emulator and fail on whatever the
	// caller nominated as its own landing page.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func TestGraphEmittedURLsResolve(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// Set up the two payloads that only emit a URL under specific conditions,
	// so the sweep covers them rather than silently skipping them.
	// (a) group overage: a low limit pushes alice's groups out of the token and
	//     replaces them with a `_claim_sources` endpoint.
	// A limit of 1 with alice already in the seeded Engineering group is enough
	// to overflow. (0 means "unset" and falls back to Entra's default of 200.)
	if code, _ := patchJSONAuth(t, hts.URL+"/admin/api/apps/"+spaID, app,
		map[string]any{"groupMembershipClaims": "All", "groupOverageLimit": 1}); code >= 300 {
		t.Fatalf("configure overage: %d", code)
	}
	if code, g := postJSONAuth(t, hts.URL+"/graph/v1.0/groups", app, map[string]any{
		"displayName": "Link Sweep", "mailEnabled": false,
		"mailNickname": "linksweep", "securityEnabled": true,
	}); code != http.StatusCreated {
		t.Fatalf("create group: %d %v", code, g)
	} else if code, _ := postJSONAuth(t,
		hts.URL+"/graph/v1.0/groups/"+g["id"].(string)+"/members/$ref", app,
		map[string]any{"@odata.id": hts.URL + "/graph/v1.0/directoryObjects/" + aliceID}); code >= 300 {
		t.Fatalf("add member: %d", code)
	}
	// (b) a B2B invitation, whose RESPONSE carries the redeem URL. Its body is
	// walked below — creating it and discarding the response would have left
	// the one link a guest is actually sent out of the sweep entirely.
	codeInv, invite := postJSONAuth(t, hts.URL+"/graph/v1.0/invitations", app, map[string]any{
		"invitedUserEmailAddress": "linkcheck@partner.example",
		"inviteRedirectUrl":       "https://app.example/welcome",
	})
	if codeInv != http.StatusCreated {
		t.Fatalf("create invitation: %d %v", codeInv, invite)
	}

	paths := []string{
		"/graph/v1.0/users", "/graph/v1.0/users/" + aliceID,
		"/graph/v1.0/users/" + aliceID + "/memberOf",
		"/graph/v1.0/users/" + aliceID + "/authentication/methods",
		"/graph/v1.0/groups", "/graph/v1.0/groups/" + store.SeedGroupEngID,
		"/graph/v1.0/groups/" + store.SeedGroupEngID + "/members",
		"/graph/v1.0/applications", "/graph/v1.0/applications/" + daemonID,
		"/graph/v1.0/servicePrincipals", "/graph/v1.0/servicePrincipals/" + daemonID,
		"/graph/v1.0/directory/administrativeUnits",
		"/graph/v1.0/directory/attributeSets",
		"/graph/v1.0/directory/customSecurityAttributeDefinitions",
		"/graph/v1.0/directory/deletedItems/microsoft.graph.user",
		"/graph/v1.0/roleManagement/directory/roleDefinitions",
		"/graph/v1.0/roleManagement/directory/roleAssignments",
		"/graph/v1.0/auditLogs/signIns", "/graph/v1.0/auditLogs/directoryAudits",
		"/graph/v1.0/policies/tokenLifetimePolicies",
		"/graph/v1.0/oauth2PermissionGrants",
		"/graph/v1.0/applications/" + daemonID + "/federatedIdentityCredentials",
		// $top forces a nextLink, the only paging URL a client is told to follow.
		"/graph/v1.0/users?$top=1",
	}

	// followable: URLs a client is told to dereference for DATA.
	// contextRefs: @odata.context annotations, which point at $metadata.
	followable := map[string]string{}
	contextRefs := map[string]bool{}

	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch t := v.(type) {
		case string:
			if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
				return
			}
			if key == "@odata.context" {
				contextRefs[t] = true
				return
			}
			// `iss` and `aud` are URL-SHAPED IDENTIFIERS, not links. An OIDC
			// issuer names a tenant; it is not required to resolve, and the
			// document that describes it lives at a well-known suffix. Treating
			// them as followable produces a false finding, which is its own way
			// of making a sweep untrustworthy.
			if identifierClaims[key] {
				return
			}
			// Only URLs on the emulator's OWN origin. Anything else is either an
			// external identifier or an echo of what the caller supplied — the
			// invitation's inviteRedirectUrl is the app's page, not ours, and a
			// sweep that fails on it is reporting the caller's infrastructure.
			if !strings.HasPrefix(t, hts.URL) {
				return
			}
			followable[t] = key
		case map[string]any:
			for k, vv := range t {
				walk(k, vv)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv)
			}
		}
	}

	for _, p := range paths {
		code, body := graphGet(t, hts.URL, p, app)
		if code != http.StatusOK {
			t.Errorf("%s returned %d — the sweep cannot cover an endpoint that does not answer", p, code)
			continue
		}
		walk("", body)
	}
	// Also sweep the token itself: the overage payload's endpoint is emitted in
	// a CLAIM, not in a Graph response, and it is the one that was dead.
	tokens := driveAuthCodeScope(t, hts, "verifier-for-link-sweep-0123456789abcdef", "openid profile")
	walk("", decodeJWTPayload(t, tokens["id_token"].(string)))
	// And the write responses, which carry links no GET ever returns.
	walk("", invite)

	// A collector that gathers nothing passes every assertion below.
	if len(followable) == 0 {
		t.Fatal("collected no followable URLs — the collector is broken, not the server")
	}

	urls := make([]string, 0, len(followable))
	for u := range followable {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	for _, u := range urls {
		// Probe GET, then POST. The question is whether a ROUTE exists, not
		// whether it answers one verb: the overage endpoint is POST-only, so a
		// GET-only sweep would report it dead exactly when it is healthy.
		status, err := probe(t, http.MethodGet, u, app)
		if err == nil && status == http.StatusNotFound {
			status, err = probe(t, http.MethodPost, u, app)
		}
		if err != nil {
			t.Errorf("%s (%s): %v", u, followable[u], err)
			continue
		}
		if status == http.StatusNotFound {
			t.Errorf("emitted URL 404s on GET and POST: %s (from %s)", u, followable[u])
		}
	}
	t.Logf("followed %d emitted URLs", len(urls))

	// @odata.context points at $metadata, which the emulator does not serve —
	// a documented boundary (docs/parity.md), not an accident. Asserting the
	// shape here is deliberate: these are type annotations, not data pointers.
	// The assertion that matters is that NOTHING ELSE ends up in this bucket,
	// which the followable sweep above enforces by exclusion.
	for u := range contextRefs {
		if !strings.Contains(u, "/$metadata#") {
			t.Errorf("@odata.context is not a $metadata reference: %s", u)
		}
	}
}
