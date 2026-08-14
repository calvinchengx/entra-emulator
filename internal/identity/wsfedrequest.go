package identity

import (
	"fmt"
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// wsfedChallengeValue reads a WS-Fed parameter from the binding that carried
// it: query string on GET, form body on POST. wctx is optional; a missing
// field is empty and stays empty — the STS does not invent one.
func wsfedChallengeValue(r *http.Request, key string) string {
	if r.Method == http.MethodPost {
		return r.PostFormValue(key)
	}
	return r.URL.Query().Get(key)
}

// resolveWSFedRelyingParty maps wtrealm onto a registered app and decides
// where the RSTR may be delivered.
//
// THE WREPLY IS VALIDATED, NOT TRUSTED. wreply arrives from the caller, and
// an STS that posts a signed assertion to whatever URL it is handed is an
// open redirector that mints credentials. Real Entra checks the value against
// the app's registered reply URLs and refuses otherwise; so does this.
// Type-blind HasRedirectURI would accept a saml-acs or OIDC web URI, which
// is a different POST contract — so the check is type-aware.
func (i *Identity) resolveWSFedRelyingParty(wtrealm, wreply string) (*store.App, error) {
	if wtrealm == "" {
		return nil, fmt.Errorf("wsfed: no wtrealm")
	}
	app, err := i.Store.GetAppByIDURI(wtrealm)
	if err != nil {
		return nil, fmt.Errorf("wsfed: no application registered with identifier %q", wtrealm)
	}
	if wreply == "" {
		return nil, fmt.Errorf("wsfed: no wreply")
	}
	ok, err := i.Store.HasRedirectURIOfType(app.ID, wreply, redirectTypeWSFedReply)
	if err != nil {
		return nil, fmt.Errorf("wsfed: cannot read reply URLs for %s: %w", app.ID, err)
	}
	if !ok {
		return nil, fmt.Errorf("wsfed: %q is not a registered wsfed-reply for %s", wreply, app.ID)
	}
	return app, nil
}

// redirectTypeWSFedReply marks a WS-Fed passive reply URL. Reusing the
// existing table rather than adding a WS-Fed-specific one keeps one answer
// to "where may this app receive credentials".
const redirectTypeWSFedReply = "wsfed-reply"
