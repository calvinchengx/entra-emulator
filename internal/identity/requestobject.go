package identity

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// JAR — JWT-Secured Authorization Requests (RFC 9101). The client passes
// `request_uri` pointing at a signed JWT holding the authorization parameters,
// which the emulator fetches, verifies against the app's registered keys, and
// applies. Entra advertises request_uri_parameter_supported, so this is the
// half of JAR that is parity; inline `request` is deliberately NOT accepted,
// because Entra does not advertise request_parameter_supported either.
//
// SSRF, addressed head-on: an authorize endpoint that fetches a caller-supplied
// URL is a server-side request forgery primitive. This one will only fetch from
// an origin the tenant admin already trusted for this app — its registered
// redirect URIs. A request_uri anywhere else is refused before any connection
// is opened, redirects are not followed, and the body is size- and time-capped.

const (
	requestObjectMaxBytes = 64 << 10
	requestObjectTimeout  = 5 * time.Second
)

// requestObjectHTTP never follows redirects: a 302 to an internal address is
// exactly how an origin allowlist gets bypassed.
var requestObjectHTTP = &http.Client{
	Timeout: requestObjectTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// originOf reduces a URL to scheme://host[:port] for allowlist comparison.
func originOf(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

// allowedRequestURIOrigin reports whether this app has a registered redirect
// URI on the same origin as the request_uri.
func (i *Identity) allowedRequestURIOrigin(appID, requestURI string) bool {
	want, ok := originOf(requestURI)
	if !ok {
		return false
	}
	uris, err := i.Store.ListRedirectURIs(appID)
	if err != nil {
		return false
	}
	for _, r := range uris {
		if got, ok := originOf(r.URI); ok && got == want {
			return true
		}
	}
	return false
}

// fetchRequestObject retrieves and verifies the request object, returning its
// claims. Every failure is deliberate and specific so a developer can tell an
// allowlist rejection from a signature failure.
func (i *Identity) fetchRequestObject(appID, requestURI string) (map[string]any, error) {
	if !i.allowedRequestURIOrigin(appID, requestURI) {
		return nil, fmt.Errorf("request_uri origin is not a registered redirect-URI origin for this application")
	}
	resp, err := requestObjectHTTP.Get(requestURI)
	if err != nil {
		return nil, fmt.Errorf("could not fetch request_uri")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request_uri returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, requestObjectMaxBytes))
	if err != nil {
		return nil, fmt.Errorf("could not read request_uri body")
	}
	assertion := strings.TrimSpace(string(raw))

	// The object must be signed by a key this app registered — otherwise
	// anyone who can host a file could dictate authorization parameters.
	creds, err := i.Store.ListAppKeyCredentials(appID)
	if err != nil || len(creds) == 0 {
		return nil, fmt.Errorf("the application has no registered key to verify a request object")
	}
	keys := make([]string, 0, len(creds))
	for _, c := range creds {
		keys = append(keys, c.PublicKey)
	}
	claims, err := tokens.VerifyRequestObject(assertion, appID, keys, i.Store.Now())
	if err != nil {
		return nil, fmt.Errorf("request object validation failed: %w", err)
	}
	return claims, nil
}

// applyRequestObject overlays the request object's parameters onto the query.
// RFC 9101: values inside the signed object win over the plain query, which is
// the entire point — the signature is what makes them trustworthy.
func applyRequestObject(q url.Values, claims map[string]any) {
	for _, k := range []string{
		"response_type", "response_mode", "redirect_uri", "scope", "state",
		"nonce", "prompt", "login_hint", "code_challenge", "code_challenge_method",
	} {
		if v, ok := claims[k].(string); ok && v != "" {
			q.Set(k, v)
		}
	}
}
