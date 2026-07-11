// Package identity implements the STS surface: discovery, authorize +
// sign-in, the grant-multiplexed token endpoint, device code, and logout
// (docs/08-oidc-endpoints.md).
package identity

import (
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// OIDC scopes handled as protocol scopes, never resource scopes.
var oidcScopes = map[string]bool{
	"openid": true, "profile": true, "email": true, "offline_access": true,
}

// Known bare Microsoft Graph delegated scope names (auto-consented without
// registration — the Graph carve-out in docs/04).
var knownGraphScopes = map[string]bool{
	"User.Read": true, "User.ReadBasic.All": true, "User.Read.All": true, "Group.Read.All": true,
}

// setResource records the single resource audience for a delegated request,
// enforcing one resource per token. Returns false on a conflicting second
// resource.
func (r *ResolvedScopes) setResource(resource string) bool {
	if r.Resource != "" && r.Resource != resource {
		return false
	}
	r.Resource = resource
	return true
}

// SplitScopes parses a space-delimited scope parameter.
func SplitScopes(raw string) []string {
	return strings.Fields(raw)
}

// ResolvedScopes is the outcome of scope validation for delegated flows.
type ResolvedScopes struct {
	Granted  []string // scope values as granted (short names for resources)
	Resource string   // resolved audience; "" means the Graph default
}

// ResolveDelegatedScopes validates a delegated scope set against the
// directory. Rules (docs/04 audience rule):
//   - OIDC scopes pass through.
//   - Graph scopes (prefixed with the Graph resource id, or known bare
//     names) grant with aud=Graph and short names in scp.
//   - "<app_id_uri>/<scope>" or "<appId>/<scope>" grants a registered,
//     enabled exposed scope of that app and sets the resource audience.
//   - Bare unknown scope names are tolerated leniently
//     and granted with the default Graph audience.
//
// Returns nil when a resource-qualified scope refers to an unknown app or
// unregistered scope value.
func (i *Identity) ResolveDelegatedScopes(scopes []string) *ResolvedScopes {
	out := &ResolvedScopes{}
	graphPrefix := i.Cfg.GraphResourceID + "/"
	fabricPrefix := fabricResource + "/"
	for _, sc := range scopes {
		switch {
		case oidcScopes[sc]:
			out.Granted = append(out.Granted, sc)
		case strings.HasPrefix(sc, graphPrefix):
			out.Granted = append(out.Granted, strings.TrimPrefix(sc, graphPrefix))
		case knownGraphScopes[sc]:
			out.Granted = append(out.Granted, sc)
		// Fabric delegated carve-out: bare or resource-prefixed Fabric scopes
		// auto-consent with aud=Fabric (roadmap #16c).
		case strings.HasPrefix(sc, fabricPrefix):
			if !out.setResource(fabricResource) {
				return nil
			}
			out.Granted = append(out.Granted, strings.TrimPrefix(sc, fabricPrefix))
		case knownFabricScopes[sc]:
			if !out.setResource(fabricResource) {
				return nil
			}
			out.Granted = append(out.Granted, sc)
		case strings.Contains(sc, "/"):
			idx := strings.LastIndex(sc, "/")
			resource, name := sc[:idx], sc[idx+1:]
			app := i.findResourceApp(resource)
			if app == nil || !i.appExposesScope(app, name) {
				return nil
			}
			if !out.setResource(resource) {
				return nil // one resource per request
			}
			out.Granted = append(out.Granted, name)
		default:
			// Lenient: bare non-OIDC scope names pass through
			// (auto-consent posture; unknown names are harmless locally).
			out.Granted = append(out.Granted, sc)
		}
	}
	return out
}

// findResourceApp resolves a resource identifier: app_id_uri first, then
// bare app GUID.
func (i *Identity) findResourceApp(resource string) *store.App {
	if app, err := i.Store.GetAppByIDURI(resource); err == nil {
		return app
	}
	if app, err := i.Store.GetApp(resource); err == nil {
		return app
	}
	return nil
}

func (i *Identity) appExposesScope(app *store.App, name string) bool {
	scopes, err := i.Store.ListScopes(app.ID)
	if err != nil {
		return false
	}
	for _, sc := range scopes {
		if sc.Value == name && sc.IsEnabled {
			return true
		}
	}
	return false
}
