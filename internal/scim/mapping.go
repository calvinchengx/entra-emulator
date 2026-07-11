package scim

import (
	"regexp"
	"strings"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// SCIM 2.0 schema URNs (RFC 7643/7644).
const (
	userSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	groupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	listSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

func isoTime(epoch int64) string {
	if epoch == 0 {
		return ""
	}
	return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
}

// userResource maps a store user to a SCIM User (core schema).
func userResource(u *store.User, base string) map[string]any {
	res := map[string]any{
		"schemas":     []string{userSchema},
		"id":          u.ID,
		"userName":    u.UserPrincipalName,
		"displayName": u.DisplayName,
		"active":      u.AccountEnabled,
		"name": map[string]any{
			"givenName":  u.GivenName,
			"familyName": u.Surname,
		},
		"meta": map[string]any{
			"resourceType": "User",
			"created":      isoTime(u.CreatedAt),
			"location":     base + "/Users/" + u.ID,
		},
	}
	if u.Mail != "" {
		res["emails"] = []map[string]any{{"value": u.Mail, "type": "work", "primary": true}}
	}
	return res
}

// groupResource maps a store group + its members to a SCIM Group.
func groupResource(g *store.Group, members []*store.User, base string) map[string]any {
	ms := make([]map[string]any, 0, len(members))
	for _, m := range members {
		ms = append(ms, map[string]any{"value": m.ID, "display": m.DisplayName, "$ref": base + "/Users/" + m.ID})
	}
	return map[string]any{
		"schemas":     []string{groupSchema},
		"id":          g.ID,
		"displayName": g.DisplayName,
		"members":     ms,
		"meta": map[string]any{
			"resourceType": "Group",
			"created":      isoTime(g.CreatedAt),
			"location":     base + "/Groups/" + g.ID,
		},
	}
}

// userBody is the writable subset of a SCIM User (create / replace).
type userBody struct {
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Name        struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Active   *bool  `json:"active"`
	Password string `json:"password"`
}

// applyTo writes the body onto a store user (create or full replace).
func (b *userBody) applyTo(u *store.User) {
	if b.UserName != "" {
		u.UserPrincipalName = b.UserName
	}
	u.DisplayName = b.DisplayName
	u.GivenName = b.Name.GivenName
	u.Surname = b.Name.FamilyName
	u.Mail = primaryEmail(b.Emails)
	if b.Active != nil {
		u.AccountEnabled = *b.Active
	}
}

func primaryEmail(emails []struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}) string {
	for _, e := range emails {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

// filterEq parses the "attr eq \"value\"" filters Entra uses for correlation
// (the only filter form the emulator supports). Returns attr, value, ok.
var filterRe = regexp.MustCompile(`^\s*(\w+)\s+eq\s+"([^"]*)"\s*$`)

func filterEq(filter string) (attr, value string, ok bool) {
	m := filterRe.FindStringSubmatch(filter)
	if m == nil {
		return "", "", false
	}
	return strings.ToLower(m[1]), m[2], true
}
