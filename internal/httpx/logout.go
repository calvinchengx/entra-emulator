package httpx

import (
	"net/url"
	"strings"
)

// ValidFrontchannelLogoutURI accepts absolute HTTP(S) notification URLs only.
// A javascript: iframe could execute content on the provider origin; data:
// and other non-HTTP schemes are not valid logout notification endpoints.
// HTTP is supported for local development; fragments and userinfo are not.
func ValidFrontchannelLogoutURI(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") &&
		u.Hostname() != "" && u.User == nil && !strings.Contains(raw, "#") && u.Opaque == ""
}
